// SPDX-License-Identifier: Apache-2.0
use rusqlite::ToSql;
use std::io::{self, Read};

fn main() {
    let db = belvi_db::memory();
    let mut query = String::new();
    io::stdin().read_to_string(&mut query).unwrap();
    let mut stmt = db
        .prepare(&format!("EXPLAIN QUERY PLAN {}", query))
        .unwrap();
    let param_count: usize = std::env::args().nth(1).unwrap().parse().unwrap();
    let params: Vec<&dyn ToSql> = vec![&42; param_count];
    let mut r = stmt.query(&*params).unwrap();
    while let Ok(Some(r)) = r.next() {
        println!(
            "{} {} {} {}",
            r.get::<_, usize>(0).unwrap(),
            r.get::<_, usize>(1).unwrap(),
            r.get::<_, usize>(2).unwrap(),
            r.get::<_, String>(3).unwrap(),
        );
    }
}
