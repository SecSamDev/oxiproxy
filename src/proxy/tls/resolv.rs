use std::{
    collections::{BTreeSet, LinkedList},
    net::TcpStream,
    sync::{Arc, Mutex},
};

use rcgen::{Certificate, CertificateParams, Ia5String, IsCa, KeyPair};
use rustls::{
    server::ResolvesServerCert, sign::SigningKey, ClientConfig, ClientConnection, StreamOwned,
};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};

use super::{
    common_name_of_cert, common_name_of_params, db::{CaDb, CertDb}, from_arc_to_static, from_arc_to_static_der, sign::SignKeyWrapper
};

pub struct CertResolver {
    store: Arc<Mutex<CertDb>>,
    /// Pre generated ROOT CA list
    ca: Arc<CaDb>,
    inter: Arc<Mutex<CaDb>>,
    pinned: Arc<Mutex<BTreeSet<String>>>,
    cconfig: Arc<ClientConfig>,
}

impl CertResolver {
    pub fn new(cconfig: Arc<ClientConfig>, ca: Arc<CaDb>, pinned: Arc<Mutex<BTreeSet<String>>>) -> Self {
        Self {
            store: Arc::new(Mutex::new(CertDb::new())),
            ca,
            inter: Arc::new(Mutex::new(CaDb::new("Interm".into()))),
            pinned,
            cconfig,
        }
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = client_hello.server_name()?;
        let store = self.store.lock().ok()?;
        let store = if !store.contains_name(name) {
            drop(store);
            let conn = self.connect_to_real_server(name)?;
            log::debug!("Process {name} certs");
            if let None = self.process_conn_certs(&conn, name) {
                log::debug!("No certs processed??");
                self.set_server_as_pinned(name)?;
                return None
            };
            log::debug!("Certs correctly processed");
            self.store.lock().ok()?
        } else {
            store
        };
        store.get_by_name(name)
    }
}

impl CertResolver {

    fn set_server_as_pinned(&self, name : &str) -> Option<()> {
        let mut guard = self.pinned.lock().ok()?;
        guard.insert(name.to_string());
        None
    }

    pub fn connect_to_real_server(&self, name: &str) -> Option<ClientConnection> {
        log::debug!("Connecting to: {name}");
        let sn = ServerName::try_from(name.to_string()).ok()?;
        let mut conn = ClientConnection::new(self.cconfig.clone(), sn).ok()?;
        let mut stream = TcpStream::connect((name, 443)).ok()?;
        if let Err(e) = conn.complete_io(&mut stream) {
            log::trace!("Connection to {name} CompleteIO error: {e}");
            return None;
        }
        let real_server = StreamOwned::new(conn, stream);
        Some(real_server.conn)
    }

    pub fn process_conn_certs(&self, conn: &ClientConnection, name : &str) -> Option<()> {
        let certs = conn.peer_certificates()?;
        log::debug!("Cert number: {}", certs.len());
        if certs.len() < 2 {
            return None
        }
        let times = certs.len() - 2;
        let mut cert_keys = LinkedList::new();
        let mut iter = certs.iter().rev();
        let (prev_cert, prev_key);
        loop {
            let next = iter.next()?;
            (prev_cert, prev_key) = match self.get_ca_cert(next) {
                Some(v) => v,
                None => continue
            };
            cert_keys.push_back((prev_cert, prev_key));
            break
        }
        log::debug!("CA Certs");

        for _ in 0..times {
            let cert = iter.next()?;
            let (int_cert, int_key) = match self.get_intermediate_cert(cert) {
                Some(v) => v,
                None => {
                    let (prev_cert, prev_key) = cert_keys.front()?;
                    let (prev_cert, prev_key) =
                        clone_real_cert(cert, &prev_cert, &prev_key)?;
                    (prev_cert, Arc::new(prev_key))
                }
            };
            cert_keys.push_front((int_cert, int_key));
        }
        let _ = cert_keys.pop_back()?; //ROOT CA
        let end_cert = iter.next()?;
        let (prev_cert, prev_key) = cert_keys.front()?;
        let (server_cert, server_key) = clone_end_cert(end_cert, name, prev_cert, prev_key)?;
        let server_key = Arc::new(server_key);
        let mut int_certs = Vec::new();
        for (int_cert, _) in &cert_keys {
            int_certs.push(int_cert);
        }
        log::debug!("Intermediate certs: {}", int_certs.len());
        let server_certkey = self.to_certkey(server_cert, server_key, int_certs)?;
        let mut guard = self.store.lock().ok()?;
        guard.insert(name.to_string(), server_certkey);
        drop(guard);

        let mut guard = self.inter.lock().ok()?;
        for (int_cert, int_key) in cert_keys {
            guard.insert(int_cert, int_key);
        }
        Some(())
    }

    pub fn get_ca_cert(
        &self,
        cert: &CertificateDer<'_>,
    ) -> Option<(Arc<Certificate>, Arc<KeyPair>)> {
        let certp = CertificateParams::from_ca_cert_der(cert).ok()?;
        if certp.is_ca == IsCa::ExplicitNoCa || certp.is_ca == IsCa::NoCa {
            return None
        }
        if let Some(sn) = &certp.serial_number {
            log::debug!("SN of CA: {:?}", sn.as_ref());
            if let Some(v) = self.ca.get_by_hash(sn.as_ref()) {
                return Some(v);
            }
        }
        
        let common_name = common_name_of_params(&certp)?;
        log::debug!("Common name of CA: {common_name}");
        self.ca.get_by_name(&common_name)
    }

    pub fn get_intermediate_cert(
        &self,
        cert: &CertificateDer<'_>,
    ) -> Option<(Arc<Certificate>, Arc<KeyPair>)> {
        let certp = CertificateParams::from_ca_cert_der(cert).ok()?;
        let guard = self.inter.lock().ok()?;
        if let Some(v) = guard.get_by_hash(certp.serial_number.as_ref()?.as_ref()) {
            return Some(v);
        }
        let common_name = common_name_of_params(&certp)?;
        guard.get_by_name(&common_name)
    }

    pub fn to_certkey(
        &self,
        cert: Arc<Certificate>,
        key_pair: Arc<KeyPair>,
        int_certs : Vec<&Arc<Certificate>>
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let cert2 = cert.clone();
        let cert = from_arc_to_static(&cert);

        let der = cert.der();
        let der = CertificateDer::from_slice(der.as_ref());
        let key = PrivateKeyDer::from_pem_slice(key_pair.serialize_pem().as_bytes()).ok()?;
        let key: Arc<dyn SigningKey> =
            rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&key).ok()?;
        let mut chain = Vec::with_capacity(3);
        chain.push(der);
        for crt in int_certs {
            let dr = from_arc_to_static_der(crt);
            chain.push(dr);
        }
        Some(Arc::new(rustls::sign::CertifiedKey::new(
            chain,
            Arc::new(SignKeyWrapper::new(key, cert2, key_pair)),
        )))
    }
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertResolver").finish()
    }
}


pub fn clone_ca_cert(cert: &CertificateDer<'_>) -> Option<(Arc<Certificate>, KeyPair)> {
    let cert = CertificateParams::from_ca_cert_der(cert).ok()?;
    let _ = cert.serial_number.as_ref()?;
    let keypair = KeyPair::generate().ok()?;
    let cert = cert.self_signed(&keypair).ok()?;
    Some((Arc::new(cert), keypair))
}

pub fn clone_real_cert(
    cert: &CertificateDer<'_>,
    prev_cert: &Certificate,
    prev_key: &KeyPair,
) -> Option<(Arc<Certificate>, KeyPair)> {
    let cert = CertificateParams::from_ca_cert_der(cert).ok()?;
    let keypair = KeyPair::generate().ok()?;
    let cert = cert.signed_by(&keypair, prev_cert, prev_key).ok()?;
    log::info!("INT CERT:\n{}", cert.pem());
    log::info!("INT KEY:\n{}", keypair.serialize_pem());
    Some((Arc::new(cert), keypair))
}

pub fn clone_end_cert(
    cert: &CertificateDer<'_>,
    name : &str,
    prev_cert: &Certificate,
    prev_key: &KeyPair,
) -> Option<(Arc<Certificate>, KeyPair)> {
    let mut cert = CertificateParams::from_ca_cert_der(cert).ok()?;
    cert.use_authority_key_identifier_extension = true;
    //cert.key_usages.push(rcgen::KeyUsagePurpose::DigitalSignature);
    //cert.extended_key_usages.push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    //cert.subject_alt_names.push(rcgen::SanType::DnsName(Ia5String::try_from(name).ok()?));
    if name.contains("*."){
        let new_name = name.replace("*.", "");
        cert.subject_alt_names.push(rcgen::SanType::DnsName(Ia5String::try_from(new_name).ok()?));
    }
    cert.is_ca = IsCa::NoCa;
    let keypair = KeyPair::generate().ok()?;
    let cert = cert.signed_by(&keypair, prev_cert, prev_key).ok()?;
    log::info!("CERT:\n{}", cert.pem());
    log::info!("KEY:\n{}", keypair.serialize_pem());
    Some((Arc::new(cert), keypair))
}