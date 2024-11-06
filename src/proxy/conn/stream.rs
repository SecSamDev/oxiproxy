use std::{io::{ErrorKind, Read, Write}, net::{SocketAddr, TcpStream}, os::fd::AsRawFd};

use libc::{sockaddr_in, sockaddr_in6, socklen_t, IP6T_SO_ORIGINAL_DST, SOL_IP, SOL_IPV6, SO_ORIGINAL_DST};
use rustls::{ClientConnection, ServerConnection, StreamOwned as TlsStream};

pub enum ConnStream {
    Tls(TlsStream<ClientConnection, TcpStream>),
    Tcp(TcpStream),
}

pub trait NonBlock {
    fn set_non_blocking(&self, nonblocking : bool) -> std::io::Result<()>;
}

impl NonBlock for TcpStream {
    fn set_non_blocking(&self, nonblocking : bool) -> std::io::Result<()> {
        self.set_nonblocking(nonblocking)
    }
}
//impl<S> NonBlock for TlsStream<ClientConnection, &mut S> where S: Read + Write + Send + NonBlock + 'static {
//    fn set_non_blocking(&self, nonblocking : bool) -> std::io::Result<()> {
//        self.sock.set_non_blocking(nonblocking)
//    }
//}
//impl<S> NonBlock for TlsStream<ServerConnection, &mut S> where S: Read + Write + Send + NonBlock + 'static {
//    fn set_non_blocking(&self, nonblocking : bool) -> std::io::Result<()> {
//        self.sock.set_non_blocking(nonblocking)
//    }
//}

impl<S> NonBlock for TlsStream<ClientConnection, S> where S: Read + Write + Send + NonBlock + 'static {
    fn set_non_blocking(&self, nonblocking : bool) -> std::io::Result<()> {
        self.sock.set_non_blocking(nonblocking)
    }
}
impl<S> NonBlock for TlsStream<ServerConnection, S> where S: Read + Write + Send + NonBlock + 'static {
    fn set_non_blocking(&self, nonblocking : bool) -> std::io::Result<()> {
        self.sock.set_non_blocking(nonblocking)
    }
}

impl ConnStream {
    pub fn to_tls(stream: TcpStream) -> Self {
        //let tls = Self::Tls(TlsStream::new(ClientConnection::new(config, name), stream))
        Self::Tcp(stream)
    }
    pub fn set_nonblocking(&self, nonblocking : bool) -> std::io::Result<()> {
        match self {
            ConnStream::Tls(stream_owned) => stream_owned.sock.set_nonblocking(nonblocking),
            ConnStream::Tcp(tcp_stream) => tcp_stream.set_nonblocking(nonblocking),
        }
    }
}

impl Write for ConnStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            ConnStream::Tls(s) => s.write(buf),
            ConnStream::Tcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ConnStream::Tls(s) => s.flush(),
            ConnStream::Tcp(s) => s.flush(),
        }
    }
}

impl Read for ConnStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            ConnStream::Tls(s) => s.read(buf),
            ConnStream::Tcp(s) => s.read(buf),
        }
    }
}


pub fn write_no_wait<S>(stream: &mut S, buffer: &[u8]) -> std::io::Result<usize>
where
    S: Read + Write + Send + 'static,
{
    let writed = match stream.write(buffer) {
        Ok(v) => v,
        Err(e) => match e.kind() {
            std::io::ErrorKind::WouldBlock => return Ok(0),
            _ => return Err(e),
        },
    };
    Ok(writed)
}

pub fn read_no_wait<'a, S, P>(
    stream: &'a mut S,
    buffer: &'a mut [u8],
    pcap: &mut P,
) -> std::io::Result<usize>
where
    S: Read + Write + Send + 'static,
    P: Write + ?Sized,
{
    let readed = match stream.read(buffer) {
        Ok(v) => v,
        Err(e) => match e.kind() {
            std::io::ErrorKind::WouldBlock => return Ok(0),
            _ => return Err(e),
        },
    };
    if readed == 0 {
        return Err(std::io::Error::new(
            ErrorKind::WriteZero,
            "Connection Closed",
        ));
    }
    pcap.write_all(&buffer[0..readed])?;
    Ok(readed)
}

pub fn original_dst(stream : &TcpStream) -> std::io::Result<SocketAddr> {
    let peer_addr = stream.peer_addr()?;
    let fd = stream.as_raw_fd();
    
    if peer_addr.is_ipv4() {
        let mut addr: sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addr_len: socklen_t = std::mem::size_of::<sockaddr_in>() as socklen_t;
        let ret = unsafe { libc::getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &mut addr as *mut _ as *mut _, &mut addr_len as *mut _,) };
        if ret != 0 {
            return Err(std::io::Error::from_raw_os_error(ret))
        }
        let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        Ok(std::net::SocketAddr::new(std::net::IpAddr::V4(ip), 443))
    }else {
        let mut addr: sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut addr_len: socklen_t = std::mem::size_of::<sockaddr_in>() as socklen_t;
        let ret = unsafe { libc::getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &mut addr as *mut _ as *mut _, &mut addr_len as *mut _,) };
        if ret != 0 {
            return Err(std::io::Error::from_raw_os_error(ret))
        }
        let ip = std::net::Ipv6Addr::from(u128::from_be_bytes(addr.sin6_addr.s6_addr));
        let port = u16::from_be(addr.sin6_port);
        Ok(std::net::SocketAddr::new(std::net::IpAddr::V6(ip), 443))
    }
}