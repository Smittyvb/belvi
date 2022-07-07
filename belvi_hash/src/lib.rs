// SPDX-License-Identifier: Apache-2.0
use ring::digest;

/// 128-bit hash for storing in DB
#[must_use]
pub fn db(bytes: &[u8]) -> [u8; 16] {
    digest::digest(&digest::SHA256, bytes).as_ref()[0..16]
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn right_db_hash() {
        assert_eq!(
            db(b"hello!"),
            // 16 byte hash
            [206, 6, 9, 47, 185, 72, 217, 255, 172, 125, 26, 55, 110, 64, 75, 38]
        );
    }
}
