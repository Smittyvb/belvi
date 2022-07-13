// SPDX-License-Identifier: Apache-2.0
use bcder::decode::Constructed;
use belvi_render::Render;

macro_rules! tests {
    (@makecert $name:ident , $path:expr , $bytes:expr , x509) => {
        x509_certificate::certificate::X509Certificate::from_der($bytes).unwrap()
    };
    (@makecert $name:ident , $path:expr , $bytes:expr , precert) => {
        Constructed::decode(($bytes).to_vec().as_ref(), bcder::Mode::Der, |cons| {
            x509_certificate::rfc5280::TbsCertificate::take_from(cons)
        }).unwrap()
    };
    ($($t:ident $name:ident $path:expr),*,) => {
        $(
            #[test]
            fn $name() {
                let bytes = include_bytes!(concat!(concat!("../../test_certs/", $path), ".der"));
                tests!(@makecert $name , $path , bytes , $t).render();
            }
        )*
    };
}

tests![
    x509 alphassl "alphassl",
    x509 geckome "geckome",
    x509 haplorrhini "haplorrhini",
    x509 policesf "policesf",
    x509 ttw "ttw",
    precert webcares "webcares",
];
