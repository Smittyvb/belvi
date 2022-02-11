// SPDX-License-Identifier: Apache-2.0
use super::Render;
use bcder::oid::Oid;

impl Render for Oid {
    fn render(&self) -> String {
        // TODO: common names for standard OIDs
        format!("{}", self)
    }
}
