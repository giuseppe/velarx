#![no_main]
// SPDX-License-Identifier: Apache-2.0
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    velarx::fuzzing::run("policy", data);
});
