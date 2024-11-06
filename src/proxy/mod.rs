use std::{collections::BTreeSet, net::{TcpListener, TcpStream}, sync::{Arc, Mutex}};

use conn::common::ProxyConnectionManager;
use crossbeam_channel::bounded;
use scap::{spawn_scap_store, common::{ScapStore, ScapStoreRef}};
use tls::store::TlsCertStore;

use crate::{pool::{ProxyThreadPool, Runner, WorkGen}, ProxyArguments};

pub mod conn;
pub mod tls;
pub mod scap;
pub mod socks5;


pub fn start_proxy(args : ProxyArguments) -> std::io::Result<()> {
    let listener = TcpListener::bind(format!("{}:{}", args.addr, args.port))?;
    log::info!("Sever listening on {}:{}", args.addr, args.port);
    let pinned = pinned_domains(&args.pinned_domain);
    let tls = TlsCertStore::new(&args.root_ca, pinned)?;
    let (scap_sender, scap_receiver) = bounded(1024);
    let scap = ScapStore::new(scap_sender);
    spawn_scap_store(scap_receiver, args.trace_folder.as_ref());
    let (th_sender, th_receiver) = bounded(1024);
    let proxy_worker = ProxyWorkerSpawner::neew(scap.reference(), tls, args.socks5_server.clone());
    let mut th_pool = ProxyThreadPool::new(args.workers, th_receiver, proxy_worker);
    th_pool.init()?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let _ = th_sender.send(stream);
            }
            Err(e) => {
                log::error!("Cannot accept new connection: {}", e);
            }
        }
    }
    
    Ok(())
}


pub struct ProxyWorkerSpawner {
    scap : ScapStoreRef,
    tls : TlsCertStore,
    socks5 : String
}
pub struct ProxyWorker {
    proxy : ProxyConnectionManager
}

impl ProxyWorkerSpawner {
    pub fn neew(scap : ScapStoreRef, tls : TlsCertStore, socks5 : String) -> Self {
        Self {
            scap,
            tls,
            socks5
        }
    }
}

impl WorkGen<TcpStream> for ProxyWorkerSpawner {
    fn gen(&self) -> impl Runner<TcpStream> + Send + 'static {
        ProxyWorker {
            proxy : ProxyConnectionManager::new(self.scap.clone(), self.tls.clone(), self.socks5.clone())
        }
    }
}

impl Runner<TcpStream> for ProxyWorker {
    fn run(&mut self, v : TcpStream) {
        if let Err(e) = runneer_wrapper(&mut self.proxy, v) {
            log::error!("Error in runner execution: {e}");
        }
    }
}


fn pinned_domains(list : &Vec<String>) -> Arc<Mutex<BTreeSet<String>>> {
    let mut set = BTreeSet::new();
    for v in list {
        set.insert(v.to_lowercase());
    }
    Arc::new(Mutex::new(set))
}

fn runneer_wrapper(proxy : &mut ProxyConnectionManager, stream : TcpStream) -> std::io::Result<()> {
    log::debug!("Received connection {:?}", stream.peer_addr()?);
    proxy.handle_client(stream)
}