use std::{collections::{BTreeMap, BTreeSet, HashMap}, fs::File, io::{ErrorKind, Read}, path::PathBuf, sync::Arc};

use rcgen::{Certificate, CertificateParams, KeyPair};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{pem::PemObject, CertificateDer};


use super::common_name_of_params;

/// Stores End-Certificates
pub struct CertDb {
    idx_name : BTreeMap<String, Arc<CertifiedKey>>,
    idx_hash : HashMap<Vec<u8>, Arc<CertifiedKey>>
}

impl CertDb {
    pub fn new() -> Self {
        Self {
            idx_hash : HashMap::new(),
            idx_name : BTreeMap::new()
        }
    }

    pub fn contains_name(&self, name : &str) -> bool {
        self.idx_name.contains_key(name)
    }

    pub fn contains_cert(&self, cert : &[u8]) -> bool {
        self.idx_hash.contains_key(cert)
    }

    pub fn get_by_name(&self, name : &str) -> Option<Arc<CertifiedKey>> {
        self.idx_name.get(name).map(|v| v.clone())
    }
    pub fn get_by_hash(&self, data : &[u8]) -> Option<Arc<CertifiedKey>> {
        self.idx_hash.get(data).map(|v| v.clone())
    }

    pub fn insert(&mut self, name : String, cert : Arc<CertifiedKey>) {
        self.idx_name.insert(name, cert.clone());
        if let Some(v) = cert.end_entity_cert().ok() {
            self.idx_hash.insert(v.to_vec(), cert);
        }
    }
}


/// Stores Root CA certificates
pub struct CaDb {
    idx_name : BTreeMap<String, (Arc<Certificate>, Arc<KeyPair>)>,
    idx_hash : HashMap<Vec<u8>, (Arc<Certificate>, Arc<KeyPair>)>,
    name : String
}

impl CaDb {
    pub fn new(name : String) -> Self {
        Self {
            name,
            idx_hash : HashMap::new(),
            idx_name : BTreeMap::new()
        }
    }

    pub fn from_dir(name : String, dir: &str) -> std::io::Result<Self> {
        let mut db = CaDb::new(name);
        let base_dir = PathBuf::from(dir);
        let rdir = std::fs::read_dir(&base_dir)?;
        let mut processed = BTreeSet::new();
        let mut buffer = Vec::with_capacity(10_000);
        let mut key_buffer = String::with_capacity(10_000);
        for dir in rdir {
            let dir = dir?;
            if !dir.file_type()?.is_file() {
                continue
            }
            if !dir.file_name().to_string_lossy().ends_with(".pem") {
                continue
            }
            let stem_file = dir.path().file_stem().map(|v| v.to_string_lossy().to_string()).expect("Should ve a valid file");
            if processed.contains(&stem_file) {
                continue
            }
            let key_pth = base_dir.join(format!("{stem_file}.key"));
            processed.insert(stem_file);
            let mut file = File::open(dir.path())?;
            file.read_to_end(&mut buffer)?;
            let cd = CertificateDer::from_pem_slice(buffer.as_ref()).map_err(|_| invalid_certificate(&dir.path()))?;
            let cp =  CertificateParams::from_ca_cert_der(&cd).map_err(|_| invalid_certificate(&dir.path()))?;
            let mut file = File::open(&key_pth)?;
            file.read_to_string(&mut key_buffer)?;
            let key = KeyPair::from_pem(&key_buffer).map_err(|_| invalid_certificate(&key_pth))?;
            let cert = cp.self_signed(&key).map_err(|_| invalid_certificate(&key_pth))?;
            db.insert(Arc::new(cert), Arc::new(key));
            key_buffer.clear();
            buffer.clear();
        }
        Ok(db)
    }

    pub fn contains_name(&self, name : &str) -> bool {
        self.idx_name.contains_key(name)
    }

    pub fn contains_cert(&self, cert : &[u8]) -> bool {
        self.idx_hash.contains_key(cert)
    }

    pub fn get_by_name(&self, name : &str) -> Option<(Arc<Certificate>, Arc<KeyPair>)> {
        self.idx_name.get(name).map(|v| v.clone())
    }
    pub fn get_by_hash(&self, data : &[u8]) -> Option<(Arc<Certificate>, Arc<KeyPair>)> {
        self.idx_hash.get(data).map(|v| v.clone())
    }

    pub fn insert(&mut self, cert : Arc<Certificate>, key : Arc<KeyPair>) {
        self.insert_name(&cert, &key);
        self.idx_hash.insert(cert.key_identifier(), (cert, key));
    }

    fn insert_name(&mut self, cert : &Arc<Certificate>, key : &Arc<KeyPair>) -> Option<()>{
        let name = common_name_of_params(&cert.params())?;
        if let Some(v) = self.idx_name.insert(name.clone(), (cert.clone(), key.clone())) {
            log::warn!("There was alredy a certificate with name {name} in CertDB {:?}:\n{}", self.name, v.0.pem());
        }
        None
    }
}


fn invalid_certificate(pth : &PathBuf) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidData, format!("Invalid certificate {}", pth.to_string_lossy()))
}