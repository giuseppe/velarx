// SPDX-License-Identifier: Apache-2.0
//! The seccomp program of a confined thread, as classic BPF: the generator
//! (`deny_program`: a table of calls in, instructions out) and the
//! interpreter (`run`: what a program answers to one call), which is the
//! meaning of a program.  The shell that gives the tables, makes
//! `sock_filter`s of the instructions and installs them is `velarx-sys`.
//!
//! What a program answers (the order is the order of the rules):
//!
//! 1. a call of another architecture: `EPERM`;
//! 2. on x86_64, a call with a number at or above the x32 bit: `EPERM`;
//! 3. a denied call: the errno of the table;
//! 4. a call with a rule on an argument: allowed when the low word of the
//!    argument is one of the values of the first rule of that call, else
//!    `EPERM`;
//! 5. `clone3`: `ENOSYS` (the C library falls back to `clone`);
//! 6. `clone`: allowed when the low word of its flags has `CLONE_THREAD`
//!    and no flag that makes a namespace, else `EPERM`;
//! 7. everything else is allowed.
//!
//! The code is plain loops over slices with indices (the list of rules,
//! whose values are borrowed, is walked by recursion), and every jump
//! offset is checked to fit a byte, so that Aeneas can translate it
//! (tools/verify/bpf-core).  The types derive `Debug` for the tests only:
//! Aeneas has no model of the formatter.

/// The instructions of classic BPF that a filter needs (`BPF_LD | BPF_W |
/// BPF_ABS`, the conditional jumps with a constant, `BPF_RET | BPF_K`),
/// and the two more that the programs of seccompiler have (`BPF_ALU |
/// BPF_AND | BPF_K`, `BPF_JA`).
pub const LD_W_ABS: u16 = 0x20;
pub const ALU_AND_K: u16 = 0x54;
pub const JA: u16 = 0x05;
pub const JEQ_K: u16 = 0x15;
pub const JGT_K: u16 = 0x25;
pub const JGE_K: u16 = 0x35;
pub const JSET_K: u16 = 0x45;
pub const RET_K: u16 = 0x06;

/// `SECCOMP_RET_ALLOW`.
pub const RET_ALLOW: u32 = 0x7fff_0000;
/// `SECCOMP_RET_ERRNO`: the errno is in the low 16 bits.
pub const RET_ERRNO: u32 = 0x0005_0000;
pub const EPERM: u32 = 1;
pub const ENOSYS: u32 = 38;

/// `CLONE_THREAD`.
pub const CLONE_THREAD: u32 = 0x0001_0000;
/// The flags of `clone` that make a namespace: `CLONE_NEWNS`,
/// `CLONE_NEWCGROUP`, `CLONE_NEWUTS`, `CLONE_NEWIPC`, `CLONE_NEWUSER`,
/// `CLONE_NEWPID`, `CLONE_NEWNET` and `CLONE_NEWTIME`.
pub const CLONE_NEW_FLAGS: u32 = 0x7e02_0080;
/// The bit of the number of an x32 call.
pub const X32: u32 = 0x4000_0000;

/// One instruction of the program (`struct sock_filter`).
#[cfg_attr(any(test, feature = "check"), derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    /// The instructions to skip when the condition holds
    pub jt: u8,
    /// The instructions to skip when it does not
    pub jf: u8,
    pub k: u32,
}

/// A call that is allowed only with some values of one argument.
#[cfg_attr(any(test, feature = "check"), derive(Debug))]
#[derive(Clone, Copy)]
pub struct OnlyIf<'a> {
    /// The system call
    pub nr: i64,
    /// Which argument (0 to 5): its low word is compared
    pub arg: usize,
    /// The values it may have
    pub values: &'a [u32],
}

/// The calls of a program: `denied` answer `errno` (its low 16 bits), the
/// calls of `only` are allowed with some arguments, the rest as the module
/// says.
#[cfg_attr(any(test, feature = "check"), derive(Debug))]
#[derive(Clone, Copy)]
pub struct Table<'a> {
    pub denied: &'a [i64],
    pub only: &'a [OnlyIf<'a>],
    pub errno: u32,
}

/// What differs between the architectures: the numbers of the calls the
/// program treats on its own, and whether the x32 numbers are refused.  The
/// architecture is little endian (the low word of an argument is at the
/// offset of the argument) and `clone` takes its flags as argument 0.
#[cfg_attr(any(test, feature = "check"), derive(Debug))]
#[derive(Clone, Copy)]
pub struct Target {
    /// `AUDIT_ARCH_*`
    pub arch: u32,
    /// Refuse the numbers with the bit `X32` (x86_64)
    pub x32: bool,
    /// The number of `clone`: allowed for a thread without a namespace
    pub clone: u32,
    /// The number of `clone3`: answered `ENOSYS`
    pub clone3: u32,
}

/// A table that cannot be made a program (see `deny_program`).
#[cfg_attr(any(test, feature = "check"), derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A number of a call that is not a `u32`
    Number,
    /// An argument that is not 0 to 5
    Argument,
    /// A rule with so many values that a jump does not fit a byte
    Jump,
}

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}

fn errno(e: u32) -> Insn {
    insn(RET_K, 0, 0, RET_ERRNO | (e & 0xffff))
}

/// A call number is a `u32` to the program.
#[allow(
    clippy::manual_range_contains,
    reason = "Aeneas has no model of `RangeInclusive::contains`, nor of `i64::from(u32::MAX)`"
)]
fn is_word(nr: i64) -> bool {
    nr >= 0 && nr <= 0xffff_ffff
}

/// A jump of `n` instructions is a byte.
fn is_byte(n: usize) -> bool {
    n <= 255
}

/// The table makes a program: its numbers are `u32`, its arguments 0 to 5,
/// and every jump of a rule fits a byte (the longest is the one that skips
/// the block, over the `values` and three more instructions; the jumps to
/// the allow are shorter).  The emitting code below relies on exactly
/// this.
fn valid(table: &Table) -> Result<(), Error> {
    valid_denied(table.denied)?;
    valid_rules(table.only, 0)
}

fn valid_denied(denied: &[i64]) -> Result<(), Error> {
    let mut i = 0;
    while i < denied.len() {
        if !is_word(denied[i]) {
            return Err(Error::Number);
        }
        i += 1;
    }
    Ok(())
}

// The rules are walked by recursion, not by a loop: Aeneas does not
// translate a loop that holds a slice of rules, which have borrowed
// values.  The depth is the number of rules.
fn valid_rules(only: &[OnlyIf], r: usize) -> Result<(), Error> {
    if r < only.len() {
        valid_rule(only[r].nr, only[r].arg, only[r].values.len())?;
        valid_rules(only, r + 1)
    } else {
        Ok(())
    }
}

fn valid_rule(nr: i64, arg: usize, values: usize) -> Result<(), Error> {
    if !is_word(nr) {
        Err(Error::Number)
    } else if arg > 5 {
        Err(Error::Argument)
    } else if !is_byte(values + 3) {
        Err(Error::Jump)
    } else {
        Ok(())
    }
}

/// The program of `table` for `target`.
pub fn deny_program(table: &Table, target: &Target) -> Result<Vec<Insn>, Error> {
    valid(table)?;
    let mut p = Vec::new();
    push_prelude(&mut p, target);
    push_denied(&mut p, table.denied, table.errno);
    push_rules(&mut p, table.only, 0);
    push_clone(&mut p, target);
    Ok(p)
}

/// The architecture, the x32 numbers.
fn push_prelude(p: &mut Vec<Insn>, target: &Target) {
    // seccomp_data: nr at 0, arch at 4, args at 16
    p.push(insn(LD_W_ABS, 0, 0, 4));
    p.push(insn(JEQ_K, 1, 0, target.arch));
    p.push(errno(EPERM));
    p.push(insn(LD_W_ABS, 0, 0, 0));
    if target.x32 {
        p.push(insn(JGE_K, 0, 1, X32));
        p.push(errno(EPERM));
    }
}

/// The denied calls.
fn push_denied(p: &mut Vec<Insn>, denied: &[i64], denied_errno: u32) {
    let mut i = 0;
    while i < denied.len() {
        p.push(insn(JEQ_K, 0, 1, denied[i] as u32));
        p.push(errno(denied_errno));
        i += 1;
    }
}

/// The rules on an argument, from the one at `r` (recursion as in
/// `valid_rules`: the depth is the number of rules).
fn push_rules(p: &mut Vec<Insn>, only: &[OnlyIf], r: usize) {
    if r < only.len() {
        push_rule(p, only[r].nr, only[r].arg, only[r].values);
        push_rules(p, only, r + 1);
    }
}

fn push_rule(p: &mut Vec<Insn>, nr: i64, arg: usize, values: &[u32]) {
    let k = values.len();
    // (`valid` made these fit)
    // the call, else past the block; the argument; one jump per value
    // to the allow at the end; a refusal; the allow
    p.push(insn(JEQ_K, 0, (k + 3) as u8, nr as u32));
    p.push(insn(LD_W_ABS, 0, 0, 16 + 8 * arg as u32));
    let mut j = 0;
    while j < k {
        p.push(insn(JEQ_K, (k - j) as u8, 0, values[j]));
        j += 1;
    }
    p.push(errno(EPERM));
    p.push(insn(RET_K, 0, 0, RET_ALLOW));
}

/// `clone3` and `clone`, and the allow at the end.
fn push_clone(p: &mut Vec<Insn>, target: &Target) {
    p.push(insn(JEQ_K, 0, 1, target.clone3));
    p.push(errno(ENOSYS));
    // clone: a thread, and no new namespace
    p.push(insn(JEQ_K, 0, 4, target.clone));
    p.push(insn(LD_W_ABS, 0, 0, 16));
    p.push(insn(JSET_K, 1, 0, CLONE_NEW_FLAGS));
    p.push(insn(JSET_K, 1, 0, CLONE_THREAD));
    p.push(errno(EPERM));
    p.push(insn(RET_K, 0, 0, RET_ALLOW));
}

/// The word of `seccomp_data` that a load at `k` reads: the number, the
/// architecture, or half of an argument; `None` for any other offset.
fn load(k: u32, nr: u32, arch: u32, args: &[u64; 6]) -> Option<u32> {
    if k == 0 {
        Some(nr)
    } else if k == 4 {
        Some(arch)
    } else if k > 15 && k < 64 && k & 3 == 0 {
        let arg = args[(k as usize - 16) / 8];
        if k & 7 == 4 {
            Some((arg >> 32) as u32)
        } else {
            Some(arg as u32)
        }
    } else {
        None
    }
}

/// What `program` returns for the call `nr` of the architecture `arch` with
/// the arguments `args` (`SECCOMP_RET_*`): `None` when it does an
/// instruction or a load that is not known here, or runs off its end.  The
/// jumps go forward only, so it ends after as many steps as it has
/// instructions.
pub fn run(program: &[Insn], nr: u32, arch: u32, args: [u64; 6]) -> Option<u32> {
    let mut pc = 0;
    let mut a = 0u32;
    let mut answer = None;
    let mut running = true;
    while running && pc < program.len() {
        let i = program[pc];
        pc += 1;
        if i.code == LD_W_ABS {
            match load(i.k, nr, arch, &args) {
                Some(w) => a = w,
                None => running = false,
            }
        } else if i.code == ALU_AND_K {
            a &= i.k;
        } else if i.code == JA {
            pc += i.k as usize;
        } else if i.code == RET_K {
            answer = Some(i.k);
            running = false;
        } else if i.code == JEQ_K || i.code == JGT_K || i.code == JGE_K || i.code == JSET_K {
            let hit = if i.code == JEQ_K {
                a == i.k
            } else if i.code == JGT_K {
                a > i.k
            } else if i.code == JGE_K {
                a >= i.k
            } else {
                a & i.k != 0
            };
            pc += usize::from(if hit { i.jt } else { i.jf });
        } else {
            running = false;
        }
    }
    answer
}

#[cfg(any(test, feature = "check"))]
pub mod check;

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: Target = Target {
        arch: 0xc000_003e,
        x32: false,
        clone: 56,
        clone3: 435,
    };

    fn table<'a>(denied: &'a [i64], only: &'a [OnlyIf<'a>]) -> Table<'a> {
        Table {
            denied,
            only,
            errno: 0x2_0003,
        }
    }

    /// The program of one denied call and one rule, instruction by
    /// instruction.
    #[test]
    fn a_small_table_makes_this_program() {
        let only = [OnlyIf {
            nr: 41,
            arg: 1,
            values: &[1, 2],
        }];
        let got = deny_program(&table(&[7], &only), &TARGET).unwrap();
        let want = [
            insn(LD_W_ABS, 0, 0, 4),
            insn(JEQ_K, 1, 0, 0xc000_003e),
            insn(RET_K, 0, 0, 0x0005_0001),
            insn(LD_W_ABS, 0, 0, 0),
            insn(JEQ_K, 0, 1, 7),
            insn(RET_K, 0, 0, 0x0005_0003),
            insn(JEQ_K, 0, 5, 41),
            insn(LD_W_ABS, 0, 0, 24),
            insn(JEQ_K, 2, 0, 1),
            insn(JEQ_K, 1, 0, 2),
            insn(RET_K, 0, 0, 0x0005_0001),
            insn(RET_K, 0, 0, 0x7fff_0000),
            insn(JEQ_K, 0, 1, 435),
            insn(RET_K, 0, 0, 0x0005_0026),
            insn(JEQ_K, 0, 4, 56),
            insn(LD_W_ABS, 0, 0, 16),
            insn(JSET_K, 1, 0, 0x7e02_0080),
            insn(JSET_K, 1, 0, 0x0001_0000),
            insn(RET_K, 0, 0, 0x0005_0001),
            insn(RET_K, 0, 0, 0x7fff_0000),
        ];
        assert_eq!(got, want);
    }

    /// A jump that does not fit a byte, a number that is not 32 bits and
    /// an argument that does not exist make no program; the largest rule
    /// that fits does.
    #[test]
    fn a_table_that_does_not_fit_is_an_error() {
        let values = [9u32; 253];
        let rule = |n: usize, nr: i64, arg: usize| {
            [OnlyIf {
                nr,
                arg,
                values: &values[..n],
            }]
        };
        let program = |only: &[OnlyIf]| deny_program(&table(&[], only), &TARGET);
        assert!(program(&rule(252, 1, 5)).is_ok());
        assert_eq!(program(&rule(253, 1, 5)), Err(Error::Jump));
        assert_eq!(program(&rule(1, 1, 6)), Err(Error::Argument));
        assert_eq!(program(&rule(1, -1, 0)), Err(Error::Number));
        assert_eq!(program(&rule(1, 1 << 32, 0)), Err(Error::Number));
        assert!(program(&rule(1, i64::from(u32::MAX), 0)).is_ok());
        assert_eq!(
            deny_program(&table(&[-1], &[]), &TARGET),
            Err(Error::Number)
        );
    }

    /// A program that leaves the loads it knows, or does not return,
    /// answers nothing.
    #[test]
    fn a_program_that_does_not_return_answers_nothing() {
        let run = |p: &[Insn]| run(p, 1, 2, [0; 6]);
        assert_eq!(run(&[]), None);
        assert_eq!(run(&[insn(LD_W_ABS, 0, 0, 4)]), None);
        assert_eq!(run(&[insn(LD_W_ABS, 0, 0, 8), insn(RET_K, 0, 0, 3)]), None);
        assert_eq!(run(&[insn(LD_W_ABS, 0, 0, 64), insn(RET_K, 0, 0, 3)]), None);
        assert_eq!(run(&[insn(JEQ_K, 5, 5, 0), insn(RET_K, 0, 0, 3)]), None);
        assert_eq!(run(&[insn(0x99, 0, 0, 0), insn(RET_K, 0, 0, 3)]), None);
        assert_eq!(run(&[insn(RET_K, 0, 0, 3)]), Some(3));
    }

    /// A load reads the number, the architecture, or the low or high word
    /// of an argument, and no other offset.
    #[test]
    fn a_load_reads_a_word_of_the_data() {
        let args: [u64; 6] =
            std::array::from_fn(|i| (0x2000 + i as u64) << 32 | (0x1000 + i as u64));
        // the program returns 1 when the load gave `want`
        let reads = |k: u32, want: u32| {
            let p = [
                insn(LD_W_ABS, 0, 0, k),
                insn(JEQ_K, 1, 0, want),
                insn(RET_K, 0, 0, 0),
                insn(RET_K, 0, 0, 1),
            ];
            run(&p, 7, 9, args)
        };
        assert_eq!(reads(0, 7), Some(1));
        assert_eq!(reads(4, 9), Some(1));
        for i in 0..6u32 {
            assert_eq!(reads(16 + 8 * i, 0x1000 + i), Some(1), "low {i}");
            assert_eq!(reads(20 + 8 * i, 0x2000 + i), Some(1), "high {i}");
        }
        for k in [1, 8, 12, 15, 17, 18, 19, 64, 68] {
            assert_eq!(reads(k, 0), None, "{k}");
        }
    }
}
