//! Reads the module list `semodule -lfull` prints.

use thiserror::Error;

/// A module in the policy store, as `semodule -lfull` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledModule {
    /// The priority it is installed at: 100 for the distribution, 400 for
    /// local administrators, forma's own for forma's.
    pub priority: u16,
    /// The module name.
    pub name: String,
    /// The language it was installed from, such as `cil` or `pp`.
    pub language: String,
    /// False if the module is installed but disabled.
    pub enabled: bool,
}

/// A line of `semodule -lfull` output that is not a module.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("semodule -lfull printed {line:?}, which is not `<priority> <name> <language> [disabled]`")]
pub struct ListError {
    /// The line.
    pub line: String,
}

/// Reads `semodule -lfull` output: one `<priority> <name> <language>` line
/// per module, with `disabled` after a disabled one. Blank lines are skipped.
///
/// # Errors
///
/// Returns [`ListError`] for the first line in any other shape.
pub fn parse_full_list(text: &str) -> Result<Vec<InstalledModule>, ListError> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let bad = || ListError { line: line.to_owned() };
            let fields: Vec<&str> = line.split_whitespace().collect();
            let enabled = match fields.as_slice() {
                [_, _, _] => true,
                [_, _, _, "disabled"] => false,
                _ => return Err(bad()),
            };
            Ok(InstalledModule {
                priority: fields[0].parse().map_err(|_| bad())?,
                name: fields[1].to_owned(),
                language: fields[2].to_owned(),
                enabled,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(priority: u16, name: &str, language: &str, enabled: bool) -> InstalledModule {
        InstalledModule {
            priority,
            name: name.to_owned(),
            language: language.to_owned(),
            enabled,
        }
    }

    #[test]
    fn each_line_is_a_module() {
        let text = "100 abrt             pp\n300 harden_userns    cil\n350 moonshine        cil\n\n400 local pp disabled\n";
        assert_eq!(
            parse_full_list(text).unwrap(),
            [
                module(100, "abrt", "pp", true),
                module(300, "harden_userns", "cil", true),
                module(350, "moonshine", "cil", true),
                module(400, "local", "pp", false),
            ]
        );
    }

    #[test]
    fn other_lines_are_refused() {
        for line in ["350 moonshine", "x moonshine cil", "350 moonshine cil enabled", "350 a b c d"] {
            assert_eq!(
                parse_full_list(line),
                Err(ListError { line: line.to_owned() }),
                "{line}"
            );
        }
    }
}
