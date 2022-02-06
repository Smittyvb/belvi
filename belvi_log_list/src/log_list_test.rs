// SPDX-License-Identifier: Apache-2.0
use super::*;

#[test]
fn parse_list() {
    let log_list = serde_json::from_str::<LogList>(include_str!("../log_list.json")).unwrap();
    assert_eq!(log_list.operators[0].name, "Google".to_string());
}
