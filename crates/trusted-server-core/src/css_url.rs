//! Shared scanner for CSS `url(...)` values.
//!
//! CSS carries URLs in exactly one syntactic place, `url(...)`, and three
//! quoting forms are legal inside it: unquoted, single-quoted and
//! double-quoted. Two rewriters need those URLs, the creative pipeline in
//! [`crate::creative`] and the publisher's inline `style` attribute rewriting
//! in [`crate::html_processor`], so the scan lives here once rather than
//! twice.
//!
//! This is a scanner, not a CSS parser. It finds `url(` and the matching `)`,
//! trims the whitespace and quotes CSS allows inside, and hands what is left
//! to the caller. It does not understand comments, at-rules or nesting.

/// Rewrite every `url(...)` value in `css` through `rewrite`.
///
/// `rewrite` receives the URL with any surrounding whitespace and quotes
/// already removed, and returns `Some(replacement)` to substitute it or `None`
/// to leave that occurrence exactly as written. Everything outside a
/// substituted value is copied verbatim, so quoting, spacing and case are
/// preserved for anything not rewritten.
///
/// Returns `None` when no occurrence was rewritten, so a caller can keep the
/// original allocation and, on the HTML path, avoid a `set_attribute` that
/// would re-serialize the start tag for no reason.
///
/// An unterminated `url(` ends the scan: whatever follows is copied through
/// untouched rather than guessed at.
pub(crate) fn rewrite_css_url_values(
    css: &str,
    rewrite: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    // `to_ascii_lowercase` maps only A-Z, so every byte offset in `lower` is
    // the same offset in `css` and either string can be indexed with it. The
    // lowercase copy exists so the `url(` keyword matches whatever case the
    // author used.
    let lower = css.to_ascii_lowercase();
    let bytes = css.as_bytes();
    let mut out = String::with_capacity(css.len());
    let mut write_pos = 0_usize;
    let mut scan = 0_usize;
    let mut replaced_any = false;

    while let Some(offset) = lower[scan..].find("url(") {
        let open = scan + offset + 4;
        let Some(close_offset) = lower[open..].find(')') else {
            break;
        };
        let close = open + close_offset;

        let mut start = open;
        while start < close && bytes[start].is_ascii_whitespace() {
            start += 1;
        }
        let mut end = close;
        while end > start && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        // A quoted value keeps its quotes: only what is between them is a URL.
        if end > start + 1 && matches!(bytes[start], b'"' | b'\'') && bytes[end - 1] == bytes[start]
        {
            start += 1;
            end -= 1;
        }

        if let Some(replacement) = rewrite(&css[start..end]) {
            out.push_str(&css[write_pos..start]);
            out.push_str(&replacement);
            write_pos = end;
            replaced_any = true;
        }

        scan = close + 1;
    }

    if !replaced_any {
        return None;
    }

    out.push_str(&css[write_pos..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_proxy(url: &str) -> Option<String> {
        url.strip_prefix("https://origin.example.com")
            .map(|rest| format!("https://proxy.example.com{rest}"))
    }

    #[test]
    fn rewrites_each_quoting_form() {
        let cases = [
            (
                "background-image: url(https://origin.example.com/bg.png)",
                "background-image: url(https://proxy.example.com/bg.png)",
            ),
            (
                "background-image: url('https://origin.example.com/bg.png')",
                "background-image: url('https://proxy.example.com/bg.png')",
            ),
            (
                "background-image: url(\"https://origin.example.com/bg.png\")",
                "background-image: url(\"https://proxy.example.com/bg.png\")",
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(
                rewrite_css_url_values(input, to_proxy),
                Some(expected.to_string()),
                "should rewrite `{input}`"
            );
        }
    }

    #[test]
    fn preserves_whitespace_and_keyword_case_around_a_rewritten_value() {
        assert_eq!(
            rewrite_css_url_values(
                "a{background:URL(  https://origin.example.com/b.png  )}",
                to_proxy
            ),
            Some("a{background:URL(  https://proxy.example.com/b.png  )}".to_string()),
            "should replace only the URL and leave the keyword and spacing alone"
        );
    }

    #[test]
    fn rewrites_every_occurrence_in_one_value() {
        assert_eq!(
            rewrite_css_url_values(
                "background: url(https://origin.example.com/a.png), url(https://origin.example.com/b.png)",
                to_proxy
            ),
            Some(
                "background: url(https://proxy.example.com/a.png), url(https://proxy.example.com/b.png)"
                    .to_string()
            ),
            "should rewrite both occurrences"
        );
    }

    #[test]
    fn returns_none_when_nothing_matches() {
        assert_eq!(
            rewrite_css_url_values("background: url(/local/a.png)", to_proxy),
            None,
            "should leave a value the caller declines untouched"
        );
        assert_eq!(
            rewrite_css_url_values("color: red", to_proxy),
            None,
            "should return none when there is no url() at all"
        );
    }

    #[test]
    fn leaves_an_unterminated_url_alone() {
        assert_eq!(
            rewrite_css_url_values("background: url(https://origin.example.com/a.png", to_proxy),
            None,
            "should not guess at an unterminated url()"
        );
    }

    #[test]
    fn keeps_a_declined_occurrence_verbatim_next_to_a_rewritten_one() {
        assert_eq!(
            rewrite_css_url_values(
                "background: url( '/local/a.png' ), url(https://origin.example.com/b.png)",
                to_proxy
            ),
            Some(
                "background: url( '/local/a.png' ), url(https://proxy.example.com/b.png)"
                    .to_string()
            ),
            "should copy the declined occurrence through byte for byte"
        );
    }

    #[test]
    fn handles_an_empty_url() {
        assert_eq!(
            rewrite_css_url_values("background: url()", to_proxy),
            None,
            "should not panic on an empty url()"
        );
    }
}
