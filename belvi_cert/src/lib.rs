// SPDX-License-Identifier: Apache-2.0
use bcder::{
    decode::{self, Constructed, Content},
    Tag,
};
use log::warn;
use x509_certificate::rfc5280::TbsCertificate;

pub fn get_cert_domains(cert: &TbsCertificate) -> Vec<Vec<u8>> {
    let mut domains = Vec::new();
    for subject in &**cert.subject {
        for attr in &**subject {
            // 2.5.4.3 is OID for commonName
            if attr.typ.as_ref() == [85, 4, 3] {
                let next_dom =
                    Constructed::decode((**attr.value).clone(), bcder::Mode::Ber, take_tagged_ber);
                if let Ok(dom) = next_dom {
                    domains.push(dom);
                }
            }
        }
    }
    if let Some(exts) = &cert.extensions {
        for ext in &**exts {
            // 2.5.29.17 is OID for subjectAltName
            if ext.id.as_ref() == [85, 29, 17] {
                let doms = Constructed::decode(ext.value.to_bytes(), bcder::Mode::Ber, |cons| {
                    cons.take_sequence(|subcons| {
                        let mut doms = Vec::new();
                        loop {
                            match take_tagged_ber(subcons) {
                                Ok(dom) => doms.push(dom),
                                Err(decode::Error::Malformed) => break,
                                Err(decode::Error::Unimplemented) => {}
                            }
                        }
                        Ok(doms)
                    })
                });
                if let Ok(doms) = doms {
                    for dom in doms {
                        domains.push(dom);
                    }
                } else {
                    warn!("Cert has invalid subjectAltNames extension");
                }
            }
        }
    }
    domains
}

fn take_tagged_ber(cons: &mut Constructed<bytes::Bytes>) -> Result<Vec<u8>, bcder::decode::Error> {
    cons.take_value(|tag, content| {
        match content {
            Content::Primitive(prim) => {
                let bytes = prim.take_all()?;
                // tag can be from 0-8: https://datatracker.ietf.org/doc/html/rfc5280#page-128
                // in practice, almost always a DNS name
                // TODO: support IP addresses, tagged with CTX_7
                if
                // email
                tag == Tag::CTX_1 ||
                    // DNS name
                    tag == Tag::CTX_2 ||
                    // URI
                    tag == Tag::CTX_6
                {
                    Ok(ber_to_string(bytes))
                } else {
                    Err(decode::Error::Unimplemented)
                }
            }
            _ => Err(decode::Error::Malformed),
        }
    })
}

fn ber_to_string(bytes: bytes::Bytes) -> Vec<u8> {
    let str_decode = Constructed::decode(bytes.clone(), bcder::Mode::Ber, |cons| {
        if let Ok(str) = bcder::Utf8String::take_from(cons) {
            return Ok(str.to_bytes());
        }
        if let Ok(str) = bcder::Ia5String::take_from(cons) {
            return Ok(str.to_bytes());
        }
        Err(decode::Error::Malformed)
    });
    // TODO: normalize
    if let Ok(str) = str_decode {
        str.to_vec()
    } else {
        bytes.to_vec()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn ttw_domains() {
        let domains = get_cert_domains(
            &x509_certificate::certificate::X509Certificate::from_der(include_bytes!(
                "../../test_certs/ttw.der"
            ))
            .unwrap()
            .as_ref()
            .tbs_certificate,
        );
        let mut expected = Vec::new();
        expected.push(b"*.smitop.com".to_vec());
        expected.push(b"sni.cloudflaressl.com".to_vec());
        expected.push(b"smitop.com".to_vec());
        assert_eq!(domains, expected);
    }

    #[test]
    fn geckome_domains() {
        let domains = get_cert_domains(
            &x509_certificate::certificate::X509Certificate::from_der(include_bytes!(
                "../../test_certs/geckome.der"
            ))
            .unwrap()
            .as_ref()
            .tbs_certificate,
        );
        let mut expected = Vec::new();
        expected.push(b"*.gecko.me".to_vec());
        expected.push(b"gecko.me".to_vec());
        assert_eq!(domains, expected);
    }

    // haplorrhini.der
    #[test]
    fn haplorrhini_domains() {
        let domains = get_cert_domains(
            &x509_certificate::certificate::X509Certificate::from_der(include_bytes!(
                "../../test_certs/haplorrhini.der"
            ))
            .unwrap()
            .as_ref()
            .tbs_certificate,
        );
        let mut expected = Vec::new();
        expected.push(b"test1.http-01.production.haplorrhini.com".to_vec());
        expected.push(b"test2.http-01.production.haplorrhini.com".to_vec());
        expected.push(b"test3.http-01.production.haplorrhini.com".to_vec());
        // TODO: ip address
        assert_eq!(domains, expected);
    }
}
