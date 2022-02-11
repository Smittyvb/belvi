// SPDX-License-Identifier: Apache-2.0
use super::{html_escape::HtmlEscapable, Render};

impl Render for x509_certificate::asn1time::UtcTime {
    fn render(&self) -> String {
        (**self).render() // get inner chrono::DateTime
    }
}

impl Render for chrono::DateTime<chrono::Utc> {
    fn render(&self) -> String {
        format!(
            r#"<time datetime="{}">{}</time>"#,
            self.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            self.format("%B %e, %Y, %k:%M:%S").html_escape()
        )
    }
}

#[cfg(test)]
mod test {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn simple_date() {
        let date = chrono::Utc.ymd(2022, 01, 01).and_hms(00, 00, 00);
        assert_eq!(
            date.render(),
            "<time datetime=\"2022-01-01T00:00:00.000Z\">January  1&#x2C; 2022&#x2C;  0&#x3A;00&#x3A;00</time>"
                .to_string()
        );
    }
}
