// SPDX-License-Identifier: Apache-2.0

use regex::Regex;
use rusqlite::{functions::FunctionFlags, Connection};
use std::sync::Arc;

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
                    Ok(Regex::new(vr.as_str()?)?)
                },
            )?;
            let is_match = {
                let text = ctx
                    .get_raw(1)
                    .as_str()
                    .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;

                regex.is_match(text)
            };

            Ok(is_match)
        },
    )
    .unwrap();
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn regex() {
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
        assert_match(&mut db, "regex('a', 'a')", true);
        assert_match(&mut db, "regex('bc', 'abcd')", true);
        assert_match(&mut db, "regex('^b', 'bcd')", true);
        assert_match(&mut db, "regex('c', 'bcd')", true);
        assert_match(&mut db, "regex('^c', 'bcd')", false);
        assert_match(&mut db, "regex('^e', 'bcd')", false);
    }
}