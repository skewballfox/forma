//! A reader for systemd unit files, which Quadlet files are.
//!
//! It yields one [`Entry`] per `key=value` line. It borrows from the file
//! text and allocates only for a value that spans several lines.

use std::borrow::Cow;

/// One `key=value` setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry<'a> {
    /// The section the setting is in, without brackets. Empty before the
    /// first section header.
    pub section: &'a str,
    /// The key.
    pub key: &'a str,
    /// The value, with continuation lines joined by one space.
    pub value: Cow<'a, str>,
    /// The line the setting starts on, counted from 1.
    pub line: usize,
}

/// Reads the settings of a unit file, in file order.
///
/// It follows systemd's syntax: `[Section]` headers, `key=value` lines,
/// comments that start with `#` or `;`, and a trailing `\` that continues a
/// value on the next line. A comment line inside a continued value is
/// skipped. Lines that are none of these are skipped too: forma checks
/// only the keys it knows, and systemd reports the rest.
pub fn entries(text: &str) -> impl Iterator<Item = Entry<'_>> {
    Entries {
        lines: text.lines().enumerate(),
        section: "",
    }
}

struct Entries<'a> {
    lines: std::iter::Enumerate<std::str::Lines<'a>>,
    section: &'a str,
}

fn is_comment(line: &str) -> bool {
    line.starts_with('#') || line.starts_with(';')
}

impl<'a> Iterator for Entries<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (index, raw) = self.lines.next()?;
            let line = raw.trim();
            if line.is_empty() || is_comment(line) {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
                self.section = name;
                continue;
            }
            let Some((key, first)) = line.split_once('=') else {
                continue;
            };
            let first = first.trim_start();
            let Some(mut head) = first.strip_suffix('\\') else {
                return Some(Entry {
                    section: self.section,
                    key: key.trim_end(),
                    value: Cow::Borrowed(first),
                    line: index + 1,
                });
            };
            let mut joined = String::new();
            loop {
                joined.push_str(head.trim_end());
                joined.push(' ');
                let Some((_, next)) = self.lines.by_ref().find(|(_, next)| !is_comment(next.trim_start())) else {
                    break;
                };
                let next = next.trim();
                if let Some(more) = next.strip_suffix('\\') {
                    head = more;
                } else {
                    joined.push_str(next);
                    break;
                }
            }
            return Some(Entry {
                section: self.section,
                key: key.trim_end(),
                value: Cow::Owned(joined.trim_end().to_owned()),
                line: index + 1,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> Vec<(String, String, String, usize)> {
        entries(text)
            .map(|entry| {
                (
                    entry.section.to_owned(),
                    entry.key.to_owned(),
                    entry.value.into_owned(),
                    entry.line,
                )
            })
            .collect()
    }

    fn row(section: &str, key: &str, value: &str, line: usize) -> (String, String, String, usize) {
        (section.to_owned(), key.to_owned(), value.to_owned(), line)
    }

    #[test]
    fn sections_keys_and_repeated_keys_come_in_file_order() {
        let text = "# comment\n[Unit]\nDescription=x y\n\n[Container]\nVolume=a:/a\n; other comment\nVolume = b:/b \n";
        assert_eq!(
            read(text),
            [
                row("Unit", "Description", "x y", 3),
                row("Container", "Volume", "a:/a", 6),
                row("Container", "Volume", "b:/b", 8),
            ]
        );
    }

    #[test]
    fn a_trailing_backslash_continues_the_value() {
        let text = "[Service]\nExecStart=/usr/bin/a \\\n    b \\\n# skipped\n    c\nRestart=no\n";
        assert_eq!(
            read(text),
            [
                row("Service", "ExecStart", "/usr/bin/a b c", 2),
                row("Service", "Restart", "no", 6)
            ]
        );
    }

    #[test]
    fn single_line_values_borrow() {
        let text = "[Container]\nImage=localhost/a:b\nExec=a \\\n b\n";
        let all: Vec<Entry<'_>> = entries(text).collect();
        assert!(matches!(all[0].value, Cow::Borrowed(_)));
        assert!(matches!(all[1].value, Cow::Owned(_)));
    }

    #[test]
    fn a_continuation_at_the_end_of_the_file_ends_the_value() {
        assert_eq!(read("[S]\nA=b \\\n"), [row("S", "A", "b", 2)]);
    }

    #[test]
    fn values_keep_equals_signs_and_lines_without_one_are_skipped() {
        let text = "[Container]\nEnvironment=A=b=c\nnot a setting\nKey=\n";
        assert_eq!(
            read(text),
            [
                row("Container", "Environment", "A=b=c", 2),
                row("Container", "Key", "", 4)
            ]
        );
    }

    #[test]
    fn keys_before_any_section_have_an_empty_section() {
        assert_eq!(read("A=b\n"), [row("", "A", "b", 1)]);
    }
}
