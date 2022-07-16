// SPDX-License-Identifier: Apache-2.0
//! This library has modules useful for the frontend. It is seperate from the binary target to
//! allow it to be tested seperately.

pub mod db;
pub mod domain_sort;
pub mod exts;
pub mod res;
pub mod search;

pub const PRODUCT_NAME: &str = match option_env!("BELVI_PRODUCT_NAME") {
    // unwrap_or isn't const stable
    Some(name) => name,
    None => "Belvi",
};
