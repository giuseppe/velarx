// SPDX-License-Identifier: Apache-2.0
//! What a program must answer, said without looking at the generator
//! (`expected`), and the comparison of a program with it over the inputs
//! that matter (`agrees`): every call the table names and its neighbours,
//! every listed value and its neighbours, the high word of the arguments,
//! other architectures.  The tests of this crate run it over small tables;
//! the owners of the real tables run it over theirs (feature `check`).

use crate::{
    deny_program, run, Insn, Table, Target, CLONE_NEW_FLAGS, CLONE_THREAD, ENOSYS, EPERM,
    RET_ALLOW, RET_ERRNO, X32,
};

/// What a call is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// With this errno (16 bits)
    Errno(u32),
}

impl Verdict {
    /// The value `SECCOMP_RET_*` of the verdict.
    pub fn ret(self) -> u32 {
        match self {
            Verdict::Allow => RET_ALLOW,
            Verdict::Errno(e) => RET_ERRNO | e,
        }
    }
}

/// What a program of `table` for `target` answers to the call `nr` of the
/// architecture `arch` with the arguments `args`.  The rules, in order: see
/// the header of the crate.
pub fn expected(table: &Table, target: &Target, nr: u32, arch: u32, args: [u64; 6]) -> Verdict {
    let denied = |e: u32| Verdict::Errno(e & 0xffff);
    if arch != target.arch {
        return denied(EPERM);
    }
    if target.x32 && nr >= X32 {
        return denied(EPERM);
    }
    if table.denied.iter().any(|&d| d == i64::from(nr)) {
        return denied(table.errno);
    }
    if let Some(rule) = table.only.iter().find(|r| r.nr == i64::from(nr)) {
        let word = args[rule.arg] as u32;
        return if rule.values.contains(&word) {
            Verdict::Allow
        } else {
            denied(EPERM)
        };
    }
    if nr == target.clone3 {
        return denied(ENOSYS);
    }
    if nr == target.clone {
        let flags = args[0] as u32;
        return if flags & CLONE_THREAD != 0 && flags & CLONE_NEW_FLAGS == 0 {
            Verdict::Allow
        } else {
            denied(EPERM)
        };
    }
    Verdict::Allow
}

/// The program has only the instructions the generator emits, every jump
/// goes to an instruction of the program and the last one returns: a run
/// never leaves the program.
pub fn well_formed(program: &[Insn]) -> bool {
    let jumps = [crate::JEQ_K, crate::JGE_K, crate::JSET_K];
    let others = [crate::LD_W_ABS, crate::RET_K];
    let in_program = |at: usize, jump: u8| at + 1 + usize::from(jump) < program.len();
    program.last().is_some_and(|i| i.code == crate::RET_K)
        && program.iter().enumerate().all(|(at, i)| {
            others.contains(&i.code)
                || (jumps.contains(&i.code) && in_program(at, i.jt) && in_program(at, i.jf))
        })
}

fn near(n: u32) -> [u32; 3] {
    [n.wrapping_sub(1), n, n.wrapping_add(1)]
}

/// The numbers worth asking about: those of the table and of `clone` and
/// `clone3`, their neighbours and their x32 twins, and the ends.
fn numbers(table: &Table, target: &Target) -> Vec<u32> {
    let mut named: Vec<u32> = vec![target.clone, target.clone3];
    named.extend(table.denied.iter().map(|&n| n as u32));
    named.extend(table.only.iter().map(|r| r.nr as u32));
    let mut all: Vec<u32> = vec![0, 1, u32::MAX, X32 - 1, X32, X32 + 1];
    for n in named {
        all.extend(near(n));
        all.extend(near(n | X32));
    }
    all.sort_unstable();
    all.dedup();
    all
}

/// The values of one argument worth asking about: ends, the values of the
/// rules on it with their neighbours and with a high word, and for the
/// first argument the flags of `clone`.
fn values(table: &Table, slot: usize) -> Vec<u64> {
    let mut all: Vec<u64> = vec![0, 1, u64::MAX, 1 << 32, u64::MAX << 32];
    for rule in table.only.iter().filter(|r| r.arg == slot) {
        for &v in rule.values {
            for w in near(v) {
                all.extend([
                    u64::from(w),
                    u64::from(w) | 1 << 32,
                    u64::from(w) | u64::MAX << 32,
                ]);
            }
        }
    }
    if slot == 0 {
        let news = (0..32)
            .map(|b| 1u32 << b)
            .filter(|f| f & CLONE_NEW_FLAGS != 0);
        for flag in news {
            for with in [0, CLONE_THREAD] {
                all.push(u64::from(flag | with));
                all.push(u64::from(flag | with) | 1 << 32);
            }
        }
        for flags in [
            CLONE_THREAD,
            CLONE_THREAD | CLONE_NEW_FLAGS,
            CLONE_NEW_FLAGS,
        ] {
            all.extend([
                u64::from(flags),
                u64::from(flags) | 1 << 32,
                u64::from(flags) | 1 << 63,
            ]);
            all.push(u64::from(flags) | u64::from(!0u32) << 32);
        }
    }
    all.sort_unstable();
    all.dedup();
    all
}

/// The arguments worth asking about: all zero or all ones, and one
/// argument (the first, and those that a rule looks at) with each of its
/// values.
fn arguments(table: &Table) -> Vec<[u64; 6]> {
    let mut slots: Vec<usize> = vec![0];
    slots.extend(table.only.iter().map(|r| r.arg));
    slots.sort_unstable();
    slots.dedup();
    let mut all = Vec::new();
    for base in [0, u64::MAX] {
        all.push([base; 6]);
        for &slot in &slots {
            for v in values(table, slot) {
                let mut args = [base; 6];
                args[slot] = v;
                all.push(args);
            }
        }
    }
    all
}

/// The program of `table` for `target` is well formed and answers what
/// `expected` says to every input worth asking about.  The number of the
/// inputs, or the first that differs.
pub fn agrees(table: &Table, target: &Target) -> Result<usize, String> {
    let program = deny_program(table, target).map_err(|e| format!("no program: {e:?}"))?;
    if !well_formed(&program) {
        return Err(format!("not well formed: {program:?}"));
    }
    let numbers = numbers(table, target);
    let arguments = arguments(table);
    // (the architecture is looked at before the arguments)
    // x86_64, aarch64, i386 and AArch32, and the ends
    let others = [
        0xc000_003e,
        0xc000_00b7,
        0x4000_0003,
        0x4000_0028,
        0,
        u32::MAX,
    ];
    let foreign: Vec<u32> = others.into_iter().filter(|&a| a != target.arch).collect();
    let mut asked = Vec::new();
    for &nr in &numbers {
        for &args in &arguments {
            asked.push((target.arch, nr, args));
        }
        for &arch in &foreign {
            asked.push((arch, nr, arguments[0]));
        }
    }
    let mut count = 0;
    for (arch, nr, args) in asked {
        let want = expected(table, target, nr, arch, args).ret();
        let got = run(&program, nr, arch, args);
        if got != Some(want) {
            return Err(format!(
                "arch {arch:#x} nr {nr:#x} args {args:x?}: the program says {got:x?}, \
                 the statement {want:#x}; table {table:?}, target {target:?}"
            ));
        }
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OnlyIf;

    const CLONE: u32 = 20;
    const CLONE3: u32 = 21;

    fn target(arch: u32, x32: bool) -> Target {
        Target {
            arch,
            x32,
            clone: CLONE,
            clone3: CLONE3,
        }
    }

    /// The ordered choices of at most `len` of `alphabet`, repeats included.
    fn sequences<T: Clone>(alphabet: &[T], len: usize) -> Vec<Vec<T>> {
        let mut all = vec![Vec::new()];
        let mut last = vec![Vec::new()];
        for _ in 0..len {
            let mut next = Vec::new();
            for s in &last {
                for a in alphabet {
                    let mut t = s.clone();
                    t.push(a.clone());
                    next.push(t);
                }
            }
            all.extend(next.iter().cloned());
            last = next;
        }
        all
    }

    /// Every table of the small alphabet: the calls that are denied (in
    /// every order, repeated or not), the calls with a rule on an
    /// argument (the same), with every list of values, `clone` and
    /// `clone3` among them; both errnos (one with bits above 16, not those of `RET_ERRNO`),
    /// three targets (x86_64 with and without the x32 rule, aarch64).
    #[test]
    fn a_program_answers_what_its_table_says_for_every_small_table() {
        let value_lists = sequences(&[0u32, 7], 2);
        let mut rules = Vec::new();
        for nr in [10i64, i64::from(CLONE)] {
            for arg in [0usize, 1] {
                for values in &value_lists {
                    rules.push((nr, arg, values.clone()));
                }
            }
        }
        let denied_lists = sequences(&[10i64, 11, i64::from(CLONE), i64::from(CLONE3)], 2);
        let rule_lists = sequences(&rules, 2);
        let (mut tables, mut inputs) = (0, 0);
        for denied in &denied_lists {
            for chosen in &rule_lists {
                let only: Vec<OnlyIf> = chosen
                    .iter()
                    .map(|(nr, arg, values)| OnlyIf {
                        nr: *nr,
                        arg: *arg,
                        values,
                    })
                    .collect();
                for errno in [5, 0x2_0026] {
                    for (arch, x32) in [
                        (0xc000_003e, false),
                        (0xc000_003e, true),
                        (0xc000_00b7, false),
                    ] {
                        let table = Table {
                            denied,
                            only: &only,
                            errno,
                        };
                        inputs += agrees(&table, &target(arch, x32)).unwrap();
                        tables += 1;
                    }
                }
            }
        }
        eprintln!("{tables} tables, {inputs} inputs");
    }
}
