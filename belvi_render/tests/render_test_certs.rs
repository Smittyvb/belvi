use belvi_render::Render;

macro_rules! tests {
    ($($name:ident $path:expr),*,) => {
        $(
            #[test]
            fn $name() {
                let cert_bytes = include_bytes!(concat!(concat!("../../test_certs/", $path), ".der"));
                let cert = x509_certificate::certificate::X509Certificate::from_der(&cert_bytes[..]).unwrap();
                cert.render();
            }
        )*
    };
}

tests![
    alphassl "alphassl",
    geckome "geckome",
    haplorrhini "haplorrhini",
    policesf "policesf",
    ttw "ttw",
];
