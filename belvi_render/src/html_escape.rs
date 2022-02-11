// SPDX-License-Identifier: Apache-2.0
use std::fmt;

pub fn entity_escape_char(khar: &char) -> String {
    format!("&#x{:X};", (*khar) as u32)
}

/// Escapes a string to allow it to be used in HTML as:
/// - an element value
/// - an attribute value
///
/// This works by replacing every character with it's HTML entity, except for letters, numbers,
/// spaces, etc. This *does* mean that we sometimes "over-escape", but it's worth it for more
/// security.
pub fn html_escape(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for khar in text.chars() {
        match khar {
            _c @ '0'..='9' | _c @ 'A'..='Z' | _c @ 'a'..='z' => result.push(khar),
            ' ' | '.' => result.push(khar),
            c => result.push_str(&entity_escape_char(&c)),
        }
    }
    result
}

pub trait HtmlEscapable {
    fn html_escape(&self) -> String;
}

impl<T> HtmlEscapable for T
where
    T: fmt::Display,
{
    fn html_escape(&self) -> String {
        html_escape(&format!("{}", self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_escape() {
        assert_eq!(entity_escape_char(&'<'), "&#x3C;");
        assert_eq!(entity_escape_char(&'a'), "&#x61;");
    }

    #[test]
    fn html_escape_doesnt_change_valid() {
        let s = "This is all spaces letters and 123numbers456";
        assert_eq!(html_escape(s), s);
    }

    #[test]
    fn html_escape_escapes_xss() {
        let s = "<script>alert(1)</script>";
        assert_eq!(
            html_escape(s),
            "&#x3C;script&#x3E;alert&#x28;1&#x29;&#x3C;&#x2F;script&#x3E;"
        );
    }
}
