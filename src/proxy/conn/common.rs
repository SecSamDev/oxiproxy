use std::{
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpStream},
};

use crate::proxy::{
    conn::stream::original_dst,
    scap::common::{ScapProtocol, ScapSender, ScapStoreRef},
    socks5::client::Socks5Client,
    tls::store::TlsCertStore,
};
use rustls::{ClientConnection, ServerConnection, StreamOwned as TlsStream};
use rustls_pki_types::{DnsName, ServerName};

use super::{mitm::MitmStreamer, stream::NonBlock};

pub struct ConnectionState {
    pub buffer: Vec<u8>,
    pub scap: ScapStoreRef,
    pub conn_buffers: ConnectionBuffers,
    pub tls: TlsCertStore,
}

pub struct ConnectionBuffers {
    pub client_buffer: Vec<u8>,
    pub server_buffer: Vec<u8>,
    pub client_readed: usize,
    pub client_pos: usize,
    pub server_readed: usize,
    pub server_pos: usize,
    pub times_zero: usize,
}

pub struct ProxyConnectionManager {
    state: ConnectionState,
    socks5: String,
}

impl ConnectionBuffers {
    pub fn new() -> Self {
        Self {
            client_buffer: vec![0u8; 32_000],
            server_buffer: vec![0u8; 32_000],
            client_pos: 0,
            client_readed: 0,
            server_pos: 0,
            server_readed: 0,
            times_zero: 0,
        }
    }
    pub fn clear(&mut self) {
        self.client_pos = 0;
        self.server_pos = 0;
        self.client_readed = 0;
        self.server_readed = 0;
    }
}

impl ConnectionState {
    pub fn new(scap: ScapStoreRef, tls: TlsCertStore) -> Self {
        Self {
            buffer: vec![0; 4096],
            conn_buffers: ConnectionBuffers::new(),
            scap,
            tls,
        }
    }
    pub fn clear(&mut self) {
        self.conn_buffers.clear();
    }
}

impl ProxyConnectionManager {
    pub fn new(pcap_store: ScapStoreRef, tls_store: TlsCertStore, socks5: String) -> Self {
        Self {
            state: ConnectionState::new(pcap_store, tls_store),
            socks5,
        }
    }
    pub fn from_state(mut state: ConnectionState, socks5: String) -> Self {
        state.clear();
        Self { state, socks5 }
    }
    pub fn keep_state(self) -> ConnectionState {
        self.state
    }

    /// Initializes a Socks5 TCP proxy
    fn init_proxy(&mut self, dst: &SocketAddr) -> std::io::Result<Socks5Client> {
        Socks5Client::connect(&self.socks5, dst.clone())
    }

    pub fn handle_client(&mut self, client_stream: TcpStream) -> std::io::Result<()> {
        let dst = original_dst(&client_stream)?;
        let mut proxy_connection = self.init_proxy(&dst)?;
        proxy_connection.greet()?;
        proxy_connection.tcp_proxy()?;

        let cp = client_stream.peer_addr()?;

        let dst_ip = dst.ip().to_string();
        // Iniciar el proxy entre el cliente y el servidor
        let err = if dst.port() == 443 {
            if self.state.tls.is_disabled(&dst_ip) {
                let mut scap = self.state.scap.sender(
                    ScapProtocol::Tls,
                    (dst.ip(), dst.port()),
                    (cp.ip(), cp.port()),
                );
                self.mitm(dst, client_stream, proxy_connection, &mut scap)
            } else {
                let mut scap = self.state.scap.sender(
                    ScapProtocol::Http,
                    (dst.ip(), dst.port()),
                    (cp.ip(), cp.port()),
                );
                self.mitm(dst, client_stream, proxy_connection, &mut scap)
            }
        } else if dst.port() == 80 {
            let mut scap = self.state.scap.sender(
                ScapProtocol::Http,
                (dst.ip(), dst.port()),
                (cp.ip(), cp.port()),
            );
            self.proxy(client_stream, proxy_connection, &mut scap)
        } else {
            let mut scap = self.state.scap.sender(
                ScapProtocol::Tcp,
                (dst.ip(), dst.port()),
                (cp.ip(), cp.port()),
            );
            self.proxy(client_stream, proxy_connection, &mut scap)
        };
        if let Err(e) = err {
            match e.kind() {
                ErrorKind::WriteZero => {}
                _ => {
                    log::trace!("Proxy Error: {}", e);
                }
            }
        }
        log::trace!("Connection finished!");
        Ok(())
    }

    fn get_sn_of_server<B>(server: &mut TlsStream<ServerConnection, B>) -> std::io::Result<String>
    where
        B: Read + Write,
    {
        let name;
        loop {
            let n = match server.conn.server_name() {
                Some(v) => v,
                None => continue,
            };
            name = n.to_string();
            break;
        }
        Ok(name)
    }

    fn proxy<C, S>(
        &mut self,
        mut cstream: S,
        mut sstream: C,
        scap: &mut ScapSender,
    ) -> std::io::Result<()>
    where
        C: Read + Write + Send + NonBlock + 'static,
        S: Read + Write + Send + NonBlock + 'static,
    {
        log::debug!("No MITM");
        let mut mitm = MitmStreamer::new(&mut self.state, scap);
        mitm.intercept(&mut cstream, &mut sstream)
    }
    fn mitm<C, S>(
        &mut self,
        dst: SocketAddr,
        mut cstream: S,
        mut sstream: C,
        scap: &mut ScapSender,
    ) -> std::io::Result<()>
    where
        C: Read + Write + Send + NonBlock + 'static,
        S: Read + Write + Send + NonBlock + 'static,
    {
        let dst_ip = dst.ip().to_string();
        if self.state.tls.is_disabled(&dst_ip) {
            return self.proxy(cstream, sstream, scap);
        }
        let mut sconn = match ServerConnection::new(self.state.tls.sconfig.clone()) {
            Ok(v) => v,
            Err(_) => return self.proxy(cstream, sstream, scap),
        };
        if let Err(e) = sconn.complete_io(&mut cstream) {
            log::trace!("CompleteIO error: {e}");
            let server_name = sconn.server_name().unwrap_or_default();
            if !server_name.is_empty() {
                if self.state.tls.is_disabled(&server_name) {
                    self.state.tls.disable_addr(dst_ip.clone());
                }
            }
            let err = e.to_string();
            if err.contains("UnknownCA") {
                log::trace!("UnknownCA for {}", server_name);
                self.state.tls.disable_addr(server_name.to_string());
                self.state.tls.disable_addr(dst_ip);
            }
            return Err(e);
        }
        let mut fake_server = TlsStream::new(sconn, cstream);
        let name = Self::get_sn_of_server(&mut fake_server)?;
        let sn = ServerName::DnsName(
            DnsName::try_from(name.as_str())
                .map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "Invalid DNS Name"))?
                .to_lowercase_owned(),
        );
        log::trace!("Now connecting to: {}", sn.to_str());
        let mut conn = match ClientConnection::new(self.state.tls.cconfig.clone(), sn) {
            Ok(v) => v,
            Err(e) => {
                return Err(std::io::Error::new(
                    ErrorKind::NotConnected,
                    format!("Connecting to: {e}"),
                ))
            }
        };
        log::trace!("Server name: {}", name);
        if let Err(e) = conn.complete_io(&mut sstream) {
            log::trace!("Real Server CompleteIO error: {e}");
            let err = e.to_string();
            if err.contains("UnknownCA") {
                self.state.tls.disable_addr(dst.to_string());
                self.state.tls.disable_addr(name);
            }
            return Err(e);
        }
        log::debug!("Starting MITM");
        let mut real_server = TlsStream::new(conn, sstream);
        let mut mitm = MitmStreamer::new(&mut self.state, scap);
        mitm.intercept(&mut fake_server, &mut real_server)
    }
}
