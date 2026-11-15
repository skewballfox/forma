//! Rewrites shebang heredocs so they build with `buildah --isolation chroot`.
//!
//! Buildah runs a heredoc whose body starts with a shebang (`RUN <<EOF`,
//! then `#!/bin/bash`) from a file under `/dev/pipes`. Chroot isolation
//! does not provide that directory, so the step fails with exit code 127.
//!
//! Feeding the body to the interpreter on standard input does the same
//! work: `RUN <<EOF` and `#!/bin/bash` become `RUN /bin/bash <<'EOF'`. The
//! quoted delimiter leaves variable expansion to that shell at run time,
//! as with the shebang form.
//!
//! This is `fix_heredoc_shebangs.py` from corectl, as a pure function.
//! Spike 0(g) of the architecture plan may make it unnecessary.

use std::borrow::Cow;

/// A `RUN` line that is only flags and one heredoc.
struct HeredocRun<'a> {
    /// `RUN` and its flags, such as `RUN --mount=type=cache,target=/x`.
    run: &'a str,
    /// `-` if the heredoc strips leading tabs.
    dash: &'a str,
    /// The delimiter, without quotes.
    delimiter: &'a str,
}

/// Reads a line of the form `RUN [--flag…] <<[-]["']WORD["']`.
///
/// A `RUN` with a command in front of the heredoc (`RUN python3 <<EOF`) is
/// not matched: there the body is the command's input, and a leading `#!`
/// is just text.
fn heredoc_run(line: &str) -> Option<HeredocRun<'_>> {
    let (run, heredoc) = line.trim_end().rsplit_once("<<")?;
    let run = run.trim_end();
    let mut words = run.split_whitespace();
    if words.next() != Some("RUN") || !run.starts_with("RUN") || words.any(|word| !word.starts_with("--")) {
        return None;
    }
    let (dash, quoted) = heredoc.strip_prefix('-').map_or(("", heredoc), |rest| ("-", rest));
    let delimiter = match quoted.chars().next()? {
        quote @ ('"' | '\'') => quoted.strip_prefix(quote)?.strip_suffix(quote)?,
        _ => quoted,
    };
    let word = !delimiter.is_empty() && delimiter.chars().all(|ch| ch.is_alphanumeric() || ch == '_');
    word.then_some(HeredocRun { run, dash, delimiter })
}

/// Rewrites every shebang heredoc of a Containerfile. Returns the text
/// unchanged, and without a copy, when it has none.
#[must_use]
pub fn rewrite(containerfile: &str) -> Cow<'_, str> {
    let mut lines = containerfile.split_inclusive('\n').peekable();
    let mut result = String::new();
    let mut changed = false;
    // Until the first rewrite nothing is copied; `consumed` counts what was passed over.
    let mut consumed = 0;
    while let Some(line) = lines.next() {
        let body = lines.peek().copied().unwrap_or_default();
        match heredoc_run(line.trim_end_matches(['\n', '\r'])) {
            Some(found) if body.starts_with("#!") => {
                if !changed {
                    result.push_str(&containerfile[..consumed]);
                    changed = true;
                }
                let interpreter = body[2..].trim();
                result.push_str(found.run);
                result.push(' ');
                result.push_str(interpreter);
                result.push_str(" <<");
                result.push_str(found.dash);
                result.push('\'');
                result.push_str(found.delimiter);
                result.push_str("'\n");
                consumed += line.len() + body.len();
                lines.next();
            }
            _ => {
                if changed {
                    result.push_str(line);
                }
                consumed += line.len();
            }
        }
    }
    if changed {
        Cow::Owned(result)
    } else {
        Cow::Borrowed(containerfile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shebang_heredoc_becomes_the_interpreters_input() {
        let text = "FROM x\nRUN <<EOF\n#!/bin/bash\nset -e\necho $HOME\nEOF\nCMD true\n";
        assert_eq!(
            rewrite(text),
            "FROM x\nRUN /bin/bash <<'EOF'\nset -e\necho $HOME\nEOF\nCMD true\n"
        );
    }

    #[test]
    fn flags_dashes_and_quotes_are_kept() {
        let text = "RUN --mount=type=cache,target=/var/cache --network=none <<-\"SCRIPT\"\n#!/usr/bin/env -S bash -eu\n\tx\n\tSCRIPT\n";
        assert_eq!(
            rewrite(text),
            "RUN --mount=type=cache,target=/var/cache --network=none /usr/bin/env -S bash -eu <<-'SCRIPT'\n\tx\n\tSCRIPT\n"
        );
    }

    #[test]
    fn several_heredocs_are_all_rewritten() {
        let text = "RUN <<A\n#!/bin/sh\na\nA\nRUN echo between\nRUN <<'B'\n#!/usr/bin/python3\nb\nB\n";
        assert_eq!(
            rewrite(text),
            "RUN /bin/sh <<'A'\na\nA\nRUN echo between\nRUN /usr/bin/python3 <<'B'\nb\nB\n"
        );
    }

    #[test]
    fn text_without_a_shebang_heredoc_is_not_copied() {
        for text in [
            "FROM x\nRUN echo hi\n",
            // No shebang: buildah runs the body with the default shell.
            "RUN <<EOF\necho hi\nEOF\n",
            // A command in front: the body is its input.
            "RUN python3 <<EOF\n#!/not/a/shebang\nEOF\n",
            "RUN cat <<EOF > /x\n#!/bin/sh\nEOF\n",
            "COPY <<EOF /x\n#!/bin/sh\nEOF\n",
            "RUN <<EOF",
            "",
        ] {
            assert!(matches!(rewrite(text), Cow::Borrowed(_)), "{text:?}");
        }
    }

    #[test]
    fn the_last_line_needs_no_newline() {
        assert_eq!(rewrite("RUN <<EOF\n#!/bin/sh"), "RUN /bin/sh <<'EOF'\n");
    }
}
