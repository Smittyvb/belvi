// SPDX-License-Identifier: LicenseRef-NLnet
// based on https://github.com/NLnetLabs/bcder/blob/main/src/bin/mkoid.rs
use bcder::oid::Oid;
use std::str::FromStr;

fn from_str(s: &str) -> Result<u32, &'static str> {
    u32::from_str(s).map_err(|_| "only integer components allowed")
}

pub fn parse_oid(arg: &str) -> Oid {
    let mut components = arg.split(' ');
    let (first, second) = match (components.next(), components.next()) {
        (Some(first), Some(second)) => (first, second),
        _ => {
            panic!("at least two components required");
        }
    };
    let first = from_str(first).unwrap();
    if first > 2 {
        panic!("first component can only be 0, 1, or 2.")
    }
    let second = from_str(second).unwrap();
    if first < 2 && second >= 40 {
        panic!("second component for 0. and 1. must be less than 40");
    }
    let mut res = vec![40 * first + second];
    for item in components {
        res.push(from_str(item).unwrap());
    }

    let mut parts: Vec<u8> = Vec::with_capacity(res.len());
    for item in res {
        // 1111 1111  1111 1111  1111 1111  1111 1111
        // EEEE DDDD  DDDC CCCC  CCBB BBBB  BAAA AAAA
        if item > 0x0FFF_FFFF {
            parts.push(((item >> 28) | 0x80) as u8)
        }
        if item > 0x001F_FFFF {
            parts.push((((item >> 21) & 0x7F) | 0x80) as u8)
        }
        if item > 0x0000_3FFF {
            parts.push((((item >> 14) & 0x7F) | 0x80) as u8)
        }
        if item > 0x0000_007F {
            parts.push((((item >> 7) & 0x7F) | 0x80) as u8)
        }
        parts.push((item & 0x7F) as u8);
    }
    Oid(bytes::Bytes::copy_from_slice(&parts[..]))
}
