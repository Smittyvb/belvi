// SPDX-License-Identifier: Apache-2.0
use std::{env, fs};

use belvi_render::Render;

fn main() {
    let mut args = env::args_os();
    let path_str = args.nth(1).unwrap();
    let cert_bytes = fs::read(path_str).unwrap();
    let cert = x509_certificate::certificate::X509Certificate::from_der(&cert_bytes[..]).unwrap();
    println!(
        "<style>{}</style>{}",
        include_str!("../bvcert.css"),
        cert.render()
    );
}
