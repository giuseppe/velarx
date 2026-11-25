// SPDX-License-Identifier: Apache-2.0
//! The one rule for the name of an object a user gives (a container, a
//! volume, a secret, a name in a pod file).

/// Whether `name` starts with a letter or a digit and goes on with letters,
/// digits, `_`, `.` or `-`: never empty, never `.` or `..`.  Each kind of
/// object adds its own limit on the length.
pub fn is_object_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

#[cfg(test)]
mod tests {
    use super::is_object_name;

    #[test]
    fn a_name_starts_with_a_letter_or_a_digit() {
        for ok in ["a", "0", "web_1", "a.b-c", "A9"] {
            assert!(is_object_name(ok), "{ok}");
        }
        for bad in ["", ".", "..", "-a", "_a", ".a", "a/b", "a b", "é", "a\0"] {
            assert!(!is_object_name(bad), "{bad:?}");
        }
    }
}
