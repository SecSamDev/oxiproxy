use std::{fs::File, io::{Read, Write}, path::PathBuf};

use rustls_pki_types::{pem::PemObject, CertificateDer};

use crate::proxy::tls::resolv::clone_ca_cert;

pub fn clone_ca_certs(input : &str, output : &str) {
    let out_dir = PathBuf::from(output);
    if !out_dir.exists() {
        std::fs::create_dir_all(&out_dir).expect("Output cert directory should be created");
    }
    let dir = PathBuf::from(input);
    log::info!("Reading ROOT CA certs from: {input}");
    let rdir = std::fs::read_dir(&dir).expect("Should exsists folder");
    let mut buffer = Vec::with_capacity(10_000);
    for dir in rdir {
        let dir = dir.expect("Should have permission to read file");
        let stem_file = dir.path().file_stem().map(|v| v.to_string_lossy().to_string()).expect("Should ve a valid file");
        let file_name = dir.file_name().to_string_lossy().to_string();
        log::debug!("Reading certificate: {}", file_name);
        let mut file = File::open(dir.path()).expect("File should be opened");
        file.read_to_end(&mut buffer).expect("File should be readed");
        let buf_slice = buffer.trim_ascii_start();
        let cert = if buf_slice[0..5].iter().all(|&v| v == b'-') {
            match CertificateDer::from_pem_slice(buf_slice) {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("Cannot process file {}: {}", file_name, e);
                    continue
                }
            }
        }else {
            CertificateDer::from_slice(buf_slice)
        };
        let (new_cert, key) = clone_ca_cert(&cert).expect("Certificate should be cloned");
        let out_cert_file = out_dir.join(&file_name);
        let out_key_file = out_dir.join(format!("{stem_file}.key"));
        let mut out_file = std::fs::File::create(&out_cert_file).expect("Should create output cert file");
        out_file.write_all(new_cert.pem().as_bytes()).expect("Should write the new certificate");
        log::debug!("Created CERT file: {}", out_cert_file.to_string_lossy());
        let mut out_file = std::fs::File::create(&out_key_file).expect("Should create output cert key file");
        out_file.write_all(key.serialize_pem().as_bytes()).expect("Should write the new certificate key");
        log::debug!("Created KEY file: {}",  out_key_file.to_string_lossy());
        buffer.clear();
    }
    log::info!("All certificate files procesed");
}