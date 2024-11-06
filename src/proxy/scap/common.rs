use std::{hash::{Hash, Hasher}, io::Write, net::IpAddr, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

use crossbeam_channel::Sender;
use serde::Serialize;


#[derive(Clone)]
pub struct ScapStore {
    pub channel : Sender<ScapEvent>,
    pub filter : Arc<ScapFilter>
}

#[derive(Clone)]
pub struct ScapStoreRef {
    pub channel : Sender<ScapEvent>,
    pub filter : Arc<ScapFilter>
}

#[derive(Debug, Clone)]
pub struct ScapSender {
    pub address :ScapAddresses,
    pub hash : u64,
    pub channel : Sender<ScapEvent>,
    pub capture : bool
}

#[derive(Debug, Clone)]
pub struct ScapSenderWrt <'a> {
    pub sender : &'a ScapSender,
    pub from_client : bool,
    pub capture : bool
}

#[derive(Debug, Clone)]
pub enum ScapEvent {
    Connect(ScapConnect),
    Receive(ScapData),
    Send(ScapData),
    Close(ScapAddresses)
}

#[derive(Debug, Clone)]
pub struct ScapData {
    pub id : u64,
    pub timestamp : Duration,
    pub data : Vec<u8>
}

#[derive(Debug, Clone, Hash, Serialize)]
pub struct ScapAddresses {
    pub remote : IpAddr,
    pub rport : u16,
    pub source : IpAddr,
    pub sport : u16
}

#[derive(Debug, Clone)]
pub struct ScapEntry {
    pub address : ScapAddresses,
    pub protocol : ScapProtocol,
    pub received : Vec<u8>,
    pub send : Vec<u8>
}
#[derive(Debug, Clone)]
pub struct  ScapConnect {
    pub address : ScapAddresses,
    pub protocol : ScapProtocol
}

#[derive(Debug, Clone)]
pub struct ScapRaw {
    pub address : ScapAddresses,
    pub received : Vec<u8>,
    pub send : Vec<u8>
}

#[derive(Debug, Clone, Default)]
pub struct ScapFilter {
    pub src_in : Vec<(IpAddr, u16)>,
    pub src_ex : Vec<(IpAddr, u16)>,
    pub dst_in : Vec<(IpAddr, u16)>,
    pub dst_ex : Vec<(IpAddr, u16)>,
    pub protocols : Vec<ScapProtocol>
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Copy)]
pub enum ScapProtocol {
    Http,
    Tcp,
    Tls,
    Udp,
    Dns
}

#[derive(Debug, Clone)]
pub struct ScapLayerFileHelper <'a> {
    pub address : &'a ScapAddresses,
    pub eth_address : (u64, u64)
}

impl ScapStore {
    pub fn new(channel : Sender<ScapEvent>) -> Self {
        Self {
            channel,
            filter : Arc::new(ScapFilter::default())
        }
    }
    pub fn with_filter(channel : Sender<ScapEvent>, filter : ScapFilter) -> Self {
        Self {
            channel,
            filter : Arc::new(filter)
        }
    }
    pub fn reference(&self) -> ScapStoreRef {
        ScapStoreRef::new(self.channel.clone(), self.filter.clone())
    }
}

impl ScapStoreRef {
    fn new(channel : Sender<ScapEvent>, filter : Arc<ScapFilter>) -> Self {
        Self {
            channel,
            filter
        }
    }
    pub fn sender(&self, protocol : ScapProtocol, remote : (IpAddr, u16), source : (IpAddr, u16)) -> ScapSender {
        let address = ScapAddresses::new(remote, source);
        let hash = address.get_hash();
        let _ = self.channel.send(ScapEvent::Connect(ScapConnect {
            address : address.clone(),
            protocol
        }));
        let capture = self.filter.matches(&address);
        ScapSender {
            address,
            hash,
            channel : self.channel.clone(),
            capture
        }
    }
}

impl ScapFilter {
    pub fn matches(&self, addr : &ScapAddresses) -> bool {
        for &(a, p) in &self.src_in {
            if addr.source == a && (p == 0 || p == addr.sport) {
                return true
            }
        }
        for &(a, p) in &self.dst_in {
            if addr.remote == a && (p == 0 || p == addr.rport) {
                return true
            }
        }
        for &(a, p) in &self.src_ex {
            if addr.source == a && (p == 0 || p == addr.sport) {
                return false
            }
        }
        for &(a, p) in &self.dst_ex {
            if addr.remote == a && (p == 0 || p == addr.rport) {
                return true
            }
        }
        true
    }
}

impl ScapAddresses {
    pub fn new(remote : (IpAddr, u16), source : (IpAddr, u16)) -> Self {
        Self {
            remote : remote.0,
            rport : remote.1,
            source : source.0,
            sport : source.1
        }
    }
    pub fn get_hash(&self) -> u64 {
        let mut hasher = std::hash::DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

impl ScapEntry {
    pub fn new(address : ScapAddresses, protocol : ScapProtocol) -> Self {
        Self {
            address,
            protocol,
            received : Vec::with_capacity(32_000),
            send : Vec::with_capacity(32_000)
        }
    }

    pub fn from_server(&mut self, data : &mut Vec<u8>)  {
        self.received.append(data);
    }
    pub fn from_client(&mut self, data : &mut Vec<u8>)  {
        self.send.append(data);
    }
}

impl ScapSender {

    pub fn from_server(&self) -> ScapSenderWrt {
        ScapSenderWrt {
            from_client : false,
            sender : &self,
            capture : self.capture
        }
    }
    pub fn from_client(&self) -> ScapSenderWrt {
        ScapSenderWrt {
            from_client : true,
            sender : &self,
            capture : self.capture
        }
    }
}

impl Drop for ScapSender {
    fn drop(&mut self) {
        if !self.capture {
            return
        }
        let _ = self.channel.send(ScapEvent::Close(self.address.clone()));
    }
}

impl<'a> Write for ScapSenderWrt<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.capture {
            return Ok(buf.len())
        }
        //println!("{}", String::from_utf8_lossy(buf));
        let data = ScapData {
            id : self.sender.hash,
            timestamp : SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default(),
            data : buf.to_vec()
        };
        let entry = if self.from_client {
            ScapEvent::Send(data)
        }else {
            ScapEvent::Receive(data)
        };
        let _ = self.sender.channel.send(entry);
        return Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}