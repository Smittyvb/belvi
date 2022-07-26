// SPDX-License-Identifier: Apache-2.0

use regex::bytes::{Regex, RegexBuilder};
use rusqlite::{functions::FunctionFlags, Connection};
use std::sync::Arc;

fn configure_regex(b: &mut RegexBuilder) {
    b
        // certificates usually (but not always) write names in lowercase
        .case_insensitive(true)
        .size_limit(27500)
        .nest_limit(18);
}

pub fn domrev(dom: &[u8]) -> Vec<u8> {
    if dom.contains(&b'@') {
        // looks like an email, don't modify
        return dom.to_vec();
    }
    let mut v = Vec::with_capacity(2);
    for part in dom.rsplit(|c| *c == b'.') {
        v.extend_from_slice(part);
        v.push(b'.');
    }
    v.pop(); // remove last dot
    v.shrink_to_fit();
    v
}

pub fn register(db: &mut Connection) {
    // https://docs.rs/rusqlite/latest/rusqlite/functions/index.html
    db.create_scalar_function(
        "regex",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            assert_eq!(ctx.len(), 2, "wrong argument count to regex()");
            let regex: Arc<Regex> = ctx.get_or_create_aux(
                0,
                |vr| -> Result<_, Box<dyn std::error::Error + Send + Sync + 'static>> {
                    let mut builder = RegexBuilder::new(vr.as_str()?);
                    configure_regex(&mut builder);
                    Ok(builder.build()?)
                },
            )?;
            Ok(match ctx.get_raw(1).as_bytes() {
                Ok(text) => regex.is_match(text),
                Err(rusqlite::types::FromSqlError::InvalidType) => false,
                Err(e) => panic!("unexpected error {:#?}", e),
            })
        },
    )
    .unwrap();

    db.create_scalar_function(
        "domrev",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| match ctx.get_raw(0).as_bytes() {
            Ok(text) => Ok(domrev(text)),
            Err(e) => panic!("unexpected error {:#?}", e),
        },
    )
    .unwrap();
}

#[cfg(test)]
mod test {
    use super::*;
    use rusqlite::{types::FromSql, ToSql};
    use std::fmt;

    #[test]
    fn regex() {
        let mut db = Connection::open_in_memory().unwrap();
        register(&mut db);
        fn assert_match(db: &mut Connection, query: &'static str, matches: bool) {
            println!("Trying {}", query);
            let val: bool = db
                .prepare(&format!("SELECT {}", query))
                .unwrap()
                .query([])
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .get(0)
                .unwrap();
            assert_eq!(val, matches);
        }
        assert_match(&mut db, "regex('a', 'b')", false);
        assert_match(&mut db, "regex('a', 'B')", false);
        assert_match(&mut db, "regex('a', 'A')", true);
        assert_match(&mut db, "regex('bc', 'AbCd')", true);
        assert_match(&mut db, "regex('^b', 'bcd')", true);
        assert_match(&mut db, "regex('c', 'bcd')", true);
        assert_match(&mut db, "regex('^c', 'bcd')", false);
        assert_match(&mut db, "regex('^e', 'bcd')", false);
    }

    /// Ensures that the regex complexity limits still allow certain regexes.
    #[test]
    fn complexity() {
        fn test_regex(r: &'static str, valid: bool) {
            let mut builder = RegexBuilder::new(r);
            configure_regex(&mut builder);
            assert_eq!(builder.build().is_ok(), valid);
        }
        // email regex, https://stackoverflow.com/a/201378/10113238
        test_regex(
            r#"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"#,
            true,
        );
        test_regex(r"^d(i|l|1)[a-z0-9]{3,6}ds?(-[a-z0-9-]{0,10})?(\.[a-z]{1,4}){1,3}$", true);
    }

    #[test]
    fn domrev() {
        let mut db = Connection::open_in_memory().unwrap();
        register(&mut db);

        fn t<T: PartialEq + fmt::Debug + ToSql + FromSql>(
            db: &mut Connection,
            query: &str,
            result: &T,
        ) {
            println!("Trying {}", query);
            let val: T = db
                .prepare(&format!("SELECT {}", query))
                .unwrap()
                .query([])
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .get(0)
                .unwrap();
            assert_eq!(val, *result);
        }

        t(&mut db, "domrev('abc')", b"abc");
        t(&mut db, "domrev('abc.def')", b"def.abc");
        t(&mut db, "domrev('abc.def.ghi')", b"ghi.def.abc");
        t(&mut db, "domrev('a.')", b".a");
        t(&mut db, "domrev('.a')", b"a.");
        t(&mut db, "domrev('.')", b".");
        t(&mut db, "domrev('.a.')", b".a.");
        t(&mut db, "domrev('abc@example.com')", b"abc@example.com");
        t(&mut db, "domrev('abc.com') >= '.com'", &true);
    }
}
