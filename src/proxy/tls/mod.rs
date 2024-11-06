use std::sync::Arc;

use rcgen::{Certificate, CertificateParams};
use rustls_pki_types::CertificateDer;

pub mod resolv;
pub mod verify;
pub mod sign;
pub mod db;
pub mod store;

pub fn from_arc_to_static<'a>(r: &'a Arc<Certificate>) -> &'static Certificate {
    let r = r.as_ref();
    unsafe { std::mem::transmute(r) }
}

pub fn from_arc_to_static_der<'a>(r: &'a Arc<Certificate>) -> CertificateDer<'static> {
    let r = r.as_ref();
    let crt : &'static Certificate = unsafe { std::mem::transmute(r) };
    CertificateDer::from_slice(crt.der().as_ref())
}

pub fn from_utf32(bytes : &[u8]) -> String {
    let mut ret = String::with_capacity(bytes.len() / 4);
    for i in (0..bytes.len()).step_by(4) {
        let (a,b,c,d) = match (bytes.get(i), bytes.get(i + 1), bytes.get(i + 2), bytes.get(i+ 3)) {
            (Some(a), Some(b), Some(c), Some(d)) => (a,b,c,d),
            _ => break
        };
        let chr = match char::from_u32(u32::from_le_bytes([*a, *b, *c, *d])) {
            Some(v) => v,
            None => break
        };
        ret.push(chr);
    }
    ret
}

pub fn common_name_of_cert(cert : &Certificate) -> Option<String> {
    common_name_of_params(cert.params())
}

pub fn common_name_of_params(cert : &CertificateParams) -> Option<String> {
    let cn = match cert.distinguished_name.get(&rcgen::DnType::CommonName) {
        Some(v) => v,
        None => {
            match cert.distinguished_name.get(&rcgen::DnType::OrganizationalUnitName) {
                Some(v) => v,
                None => cert.distinguished_name.get(&rcgen::DnType::OrganizationName)?
            }
        }
    };
    let cn = match cn {
        rcgen::DnValue::BmpString(bmp_string) => String::from_utf8_lossy(bmp_string.as_bytes()).to_string(),
        rcgen::DnValue::Ia5String(ia5_string) => ia5_string.as_str().to_string(),
        rcgen::DnValue::PrintableString(printable_string) => printable_string.as_str().to_string(),
        rcgen::DnValue::TeletexString(teletex_string) => teletex_string.as_str().to_string(),
        rcgen::DnValue::UniversalString(universal_string) => from_utf32(universal_string.as_bytes()),
        rcgen::DnValue::Utf8String(v) => v.to_owned(),
        _ => return None,
    };
    Some(cn)
}