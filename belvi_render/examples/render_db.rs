use std::panic::catch_unwind;

use bcder::decode::Constructed;
use belvi_render::Render;

fn check(cert: Vec<u8>) {
    match Constructed::decode(cert.as_ref(), bcder::Mode::Der, |cons| {
        x509_certificate::rfc5280::TbsCertificate::take_from(cons)
    }) {
        Ok(tbs_cert) => (tbs_cert.render(), belvi_cert::get_cert_domains(&tbs_cert)),
        Err(_) => {
            let cert = Constructed::decode(cert.as_ref(), bcder::Mode::Der, |cons| {
                x509_certificate::rfc5280::Certificate::take_from(cons)
            })
            .expect("invalid cert in log");
            (
                cert.render(),
                belvi_cert::get_cert_domains(&cert.tbs_certificate),
            )
        }
    };
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let mut conn = belvi_cache::Connection::new().await;
    let keys = conn.cached_cert_key_list().await;

    let total = keys.len();
    for (idx, key) in keys.into_iter().enumerate() {
        let cert = conn.get_cert(&key[2..]).await.unwrap();
        if let Err(_) = catch_unwind(|| check(cert)) {
            panic!("Failed with cert {}", hex::encode(&key[2..]));
        };
        if idx % 1000 == 0 {
            println!(
                "Checked {:.2}% ({})",
                ((idx as f64) / (total as f64)) * 100.0,
                idx
            );
        }
    }
}
