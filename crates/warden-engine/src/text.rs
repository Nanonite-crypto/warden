//! Making text that comes from outside safe to show.
//!
//! File names inside archives, and descriptions inside rule files, are
//! written by someone else. Before such text reaches a report or a terminal
//! it goes through [`printable`].

/// Returns `text` with misleading characters replaced, cut to `max_chars`.
///
/// Control characters could rewrite a terminal line, and the Unicode
/// characters that change text direction can make `gpj.exe` display as
/// `exe.jpg`. Both are replaced with U+FFFD. Text longer than `max_chars`
/// characters is cut and ends in `...`.
#[must_use]
pub fn printable(text: &str, max_chars: usize) -> String {
    let mut shown = String::with_capacity(text.len().min(max_chars.saturating_mul(4)));
    for (index, character) in text.chars().enumerate() {
        if index == max_chars {
            shown.push_str("...");
            break;
        }
        if character.is_control() || changes_direction(character) {
            shown.push(char::REPLACEMENT_CHARACTER);
        } else {
            shown.push(character);
        }
    }
    shown
}

/// Unicode characters that change the direction text is displayed in.
fn changes_direction(character: char) -> bool {
    matches!(
        character,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_text_is_left_alone() {
        assert_eq!(printable("docs/readme.txt", 200), "docs/readme.txt");
        assert_eq!(
            printable("файл ディレクトリ.bin", 200),
            "файл ディレクトリ.bin"
        );
    }

    #[test]
    fn control_characters_are_replaced() {
        assert_eq!(
            printable("evil\u{1b}[2Kname\r\n", 200),
            "evil\u{fffd}[2Kname\u{fffd}\u{fffd}"
        );
    }

    #[test]
    fn direction_overrides_are_replaced() {
        // With a right-to-left override this would display as "photoexe.jpg".
        assert_eq!(
            printable("photo\u{202e}gpj.exe", 200),
            "photo\u{fffd}gpj.exe"
        );
    }

    #[test]
    fn long_text_is_cut() {
        let shown = printable(&"a".repeat(500), 200);
        assert_eq!(shown.chars().count(), 203);
        assert!(shown.ends_with("..."));
        assert_eq!(printable("abc", 3), "abc");
    }
}
