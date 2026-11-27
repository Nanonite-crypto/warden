//! Whether a command line starts a file.
//!
//! The rule is a plain one: the file's full path stands in the command
//! line, as the program or as something passed to the program. It is not
//! an attempt to run the command line in one's head. A bare name that
//! Windows would look up along its search path is not followed, and
//! neither is a script that names the file somewhere inside. Leaving an
//! entry in place that does start the file is the smaller mistake:
//! Windows then reports that it cannot find the file. Removing one that
//! has nothing to do with the file is the larger one.

/// The ways the full path of one file is written: as it was given, with
/// its short names, and whatever else the system knows it by. Kept in the
/// form they are compared in.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Spellings(Vec<Vec<char>>);

impl Spellings {
    /// The spellings among `paths` that are full paths: a drive with a
    /// folder, or a share on another machine. Anything else is dropped,
    /// because it could stand in a command line by accident.
    #[must_use]
    pub fn new(paths: impl IntoIterator<Item = String>) -> Self {
        let mut spellings: Vec<Vec<char>> = Vec::new();
        for path in paths {
            let folded = fold(&without_long_path_mark(&path));
            if is_full_path(&folded) && !spellings.contains(&folded) {
                spellings.push(folded);
            }
        }
        Self(spellings)
    }

    /// Whether there is nothing to look for.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Whether one of the command lines starts the file.
#[must_use]
pub fn starts(lines: &[String], file: &Spellings) -> bool {
    lines.iter().any(|line| stands_in(line, file))
}

/// Whether the file's path stands in a command line: written out in
/// full, in any of its spellings, in upper or lower case, and with
/// something before and after it that ends a path.
#[must_use]
pub fn stands_in(line: &str, file: &Spellings) -> bool {
    let line = fold(line);
    file.0.iter().any(|path| occurs(&line, path))
}

fn occurs(line: &[char], path: &[char]) -> bool {
    if path.is_empty() || path.len() > line.len() {
        return false;
    }
    (0..=line.len() - path.len()).any(|at| {
        line[at..at + path.len()] == *path
            && begins_a_path(&line[..at])
            && ends_a_path(&line[at + path.len()..])
    })
}

/// Whether a path can begin after this text: at the very start, or after
/// a character that separates words or opens a quotation. The mark that
/// Windows puts before a long path does not count as part of the path.
fn begins_a_path(before: &[char]) -> bool {
    const LONG: [char; 4] = ['\\', '\\', '?', '\\'];
    const KERNEL: [char; 4] = ['\\', '?', '?', '\\'];
    let before = match before {
        [rest @ .., a, b, c, d] if [*a, *b, *c, *d] == LONG || [*a, *b, *c, *d] == KERNEL => rest,
        all => all,
    };
    before
        .last()
        .is_none_or(|last| matches!(last, '"' | '\'' | ' ' | '\t' | ',' | '=' | ';' | ':' | '('))
}

/// Whether a path can end before this text.
fn ends_a_path(after: &[char]) -> bool {
    after
        .first()
        .is_none_or(|next| matches!(next, '"' | '\'' | ' ' | '\t' | ',' | ';' | ')'))
}

/// The form two texts are compared in: every character in upper case, as
/// Windows compares file names, and both kinds of slash the same.
fn fold(text: &str) -> Vec<char> {
    text.chars()
        .map(|character| {
            if character == '/' {
                return '\\';
            }
            let mut upper = character.to_uppercase();
            match (upper.next(), upper.next()) {
                // One character stays one character, or the lengths of a
                // path and of its place in a line would differ.
                (Some(single), None) => single,
                _ => character,
            }
        })
        .collect()
}

/// A path without the mark that Windows puts before a long one:
/// `\\?\C:\x` is `C:\x`, and `\\?\UNC\server\share` is `\\server\share`.
fn without_long_path_mark(path: &str) -> String {
    if let Some(share) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{share}")
    } else {
        path.strip_prefix(r"\\?\").unwrap_or(path).to_owned()
    }
}

fn is_full_path(path: &[char]) -> bool {
    match path {
        // A drive, a colon, a backslash, and something after them.
        [drive, ':', '\\', _, ..] => drive.is_ascii_alphabetic(),
        // A share on another machine.
        ['\\', '\\', server, ..] => *server != '?' && *server != '.' && *server != '\\',
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn file() -> Spellings {
        Spellings::new([
            r"C:\Program Files\Thing\thing.exe".to_owned(),
            r"C:\PROGRA~1\Thing\thing.exe".to_owned(),
        ])
    }

    #[test]
    fn the_path_stands_in_a_line_as_program_or_as_something_passed() {
        let lines = [
            r"C:\Program Files\Thing\thing.exe",
            r#""C:\Program Files\Thing\thing.exe""#,
            r#""C:\Program Files\Thing\thing.exe" --tray"#,
            r"C:\Program Files\Thing\thing.exe --tray",
            r"c:\program files\thing\THING.EXE /s",
            r"C:/Program Files/Thing/thing.exe",
            r"C:\PROGRA~1\Thing\thing.exe -x",
            r"rundll32.exe C:\PROGRA~1\Thing\thing.exe,Start",
            r#"C:\Windows\System32\cmd.exe /c start "" "C:\Program Files\Thing\thing.exe""#,
            r#"launcher.exe --target=C:\PROGRA~1\Thing\thing.exe"#,
            r#"launcher.exe /run:"C:\Program Files\Thing\thing.exe""#,
            r"launcher.exe /run:C:\PROGRA~1\Thing\thing.exe;more",
            r"'C:\Program Files\Thing\thing.exe'",
            r"\\?\C:\Program Files\Thing\thing.exe",
            r#""\\?\C:\Program Files\Thing\thing.exe" -k"#,
            r"\??\C:\PROGRA~1\Thing\thing.exe",
            "\tC:\\PROGRA~1\\Thing\\thing.exe\t",
            r"wrapper.exe (C:\PROGRA~1\Thing\thing.exe)",
        ];
        for line in lines {
            assert!(stands_in(line, &file()), "{line}");
        }
    }

    #[test]
    fn what_only_resembles_the_path_does_not_count() {
        let lines = [
            "",
            "thing.exe",
            r"Thing\thing.exe",
            r"C:\Program Files\Thing\thing.exe.bak",
            r"C:\Program Files\Thing\thing.exe2",
            r"C:\Program Files\Thing\thing.exe\more",
            r"C:\Program Files\Thing\thing",
            r"C:\Program Files\Thing\other.exe",
            r"D:\Program Files\Thing\thing.exe",
            r"XC:\Program Files\Thing\thing.exe",
            r"D:\backup\C:\Program Files\Thing\thing.exe",
            r"C:\Program Files\Thing2\thing.exe",
            r"\\server\C:\Program Files\Thing\thing.exe",
            r"C:\Program Files\Thing\thing.exe-old",
        ];
        for line in lines {
            assert!(!stands_in(line, &file()), "{line}");
        }
    }

    #[test]
    fn only_full_paths_are_looked_for() {
        let nothing = Spellings::new([
            String::new(),
            "thing.exe".to_owned(),
            r"Thing\thing.exe".to_owned(),
            r"C:".to_owned(),
            r"C:\".to_owned(),
            r"\thing.exe".to_owned(),
            r"\\?\".to_owned(),
            r"\\.\pipe\thing".to_owned(),
        ]);
        assert!(nothing.is_empty());
        assert!(!stands_in("thing.exe", &nothing));

        let share = Spellings::new([r"\\server\share\thing.exe".to_owned()]);
        assert!(stands_in(r#""\\SERVER\share\thing.exe" /x"#, &share));
        // The long form of a share is the same share.
        let long_share = Spellings::new([r"\\?\UNC\server\share\thing.exe".to_owned()]);
        assert_eq!(share, long_share);
        // And the long form of a path the same path.
        assert_eq!(
            Spellings::new([r"\\?\C:\x\a.exe".to_owned()]),
            Spellings::new([r"c:\X\A.EXE".to_owned(), r"C:/x/a.exe".to_owned()])
        );
    }

    #[test]
    fn letters_outside_ascii_are_compared_without_regard_to_case() {
        let file = Spellings::new([r"C:\Übung\Ärger.exe".to_owned()]);
        assert!(stands_in(r"c:\übung\ärger.EXE", &file));
        // A letter whose upper case is two letters is left as it is, on
        // both sides.
        let sharp = Spellings::new([r"C:\Straße\a.exe".to_owned()]);
        assert!(stands_in(r"C:\STRAßE\A.EXE", &sharp));
        assert!(!stands_in(r"C:\STRASSE\A.EXE", &sharp));
    }

    #[test]
    fn one_line_among_several_is_enough() {
        let lines = [
            r"%SystemRoot%\x.exe".to_owned(),
            r"C:\PROGRA~1\Thing\thing.exe".to_owned(),
        ];
        assert!(starts(&lines, &file()));
        assert!(!starts(&lines[..1], &file()));
        assert!(!starts(&[], &file()));
    }

    proptest! {
        #[test]
        fn any_text_can_be_looked_through(line in ".{0,200}", path in ".{0,60}") {
            let _ = stands_in(&line, &Spellings::new([path]));
        }

        #[test]
        fn the_path_is_found_between_what_ends_a_path(
            before in r#"[a-z ]{0,20}[ "=,;(]"#,
            after in r#"[ ",;)][a-z ]{0,20}"#,
            name in "[a-zA-Z0-9_ ]{1,20}",
        ) {
            let path = format!(r"C:\dir\{name}.exe");
            let file = Spellings::new([path.clone()]);
            let line = format!("{before}{path}{after}");
            prop_assert!(stands_in(&line, &file));
            let upper = line.to_uppercase();
            prop_assert!(stands_in(&upper, &file));
        }

        #[test]
        fn a_longer_name_is_another_file(
            name in "[a-zA-Z0-9_]{1,20}",
            more in "[a-zA-Z0-9_.~\\\\-]{1,5}",
        ) {
            let path = format!(r"C:\dir\{name}.exe");
            let file = Spellings::new([path.clone()]);
            let line = format!("{path}{more}");
            prop_assert!(!stands_in(&line, &file));
        }
    }
}
