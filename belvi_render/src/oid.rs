// SPDX-License-Identifier: Apache-2.0
use bcder::oid::Oid;
use std::collections::HashMap;

mod parse;

use super::{html_escape::HtmlEscapable, Render};

lazy_static::lazy_static! {
    static ref COMMON_OIDS: HashMap<Oid<bytes::Bytes>, String> = {
        let mut hm = HashMap::new();
        {
            let oid_data = include_str!("oid/dumpasn1.txt");
            let mut oid = None;
            for line in oid_data.lines() {
                if line.is_empty() || line.starts_with("#") { continue; }
                let mut parts = line.split(" = ");
                match parts.next().unwrap() {
                    "OID" => oid = Some(parse::parse_oid(parts.next().unwrap())),
                    "Description" => {
                        let desc = parts.next().unwrap().to_string();
                        hm.insert(oid.unwrap(), desc);
                        oid = None;
                    }
                    "Comment" | "Warning" => {},
                    p => panic!("invalid dumpasn1 data: prefix of {}", p),
                }
            }
        }
        {
            let oid_data = include_str!("oid/oids.txt");
            for line in oid_data.lines() {
                if line.is_empty() || line.starts_with("#") { continue; }
                let mut parts = line.split("=");
                hm.insert(parse::parse_oid(parts.next().unwrap()), parts.next().unwrap().to_string());
            }
        }
        hm
    };
}

impl Render for Oid<bytes::Bytes> {
    fn render(&self) -> String {
        if let Some(val) = COMMON_OIDS.get(self) {
            format!(
                r#"<span class="bvcert-oid" data-oid="{oid}">{name}</span>"#,
                oid = self.html_escape(),
                name = val,
            )
        } else {
            format!(
                r#"<span class="bvcert-oid" data-oid="{oid}">{oid}</span>"#,
                oid = self.html_escape()
            )
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn unknown_oid() {
        let oid = Oid(bytes::Bytes::from(&[192, 200, 50, 30][..]));
        assert_eq!(
            Render::render(&oid),
            "<span class=\"bvcert-oid\" data-oid=\"2.1057762.30\">2.1057762.30</span>".to_string()
        );
    }
}
