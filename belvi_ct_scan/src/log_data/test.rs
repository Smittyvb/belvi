// SPDX-License-Identifier: Apache-2.0
use super::*;

#[test]
fn argon2021() {
    let data = include_str!("../../test_data/argon2021-get-entries?start=0&end=1.json");
    GetEntriesItem::parse(data).unwrap();
}
