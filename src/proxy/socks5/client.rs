use std::{io::{Error, ErrorKind, Read, Write}, net::{SocketAddr, TcpStream, UdpSocket}};

use crate::proxy::conn::stream::NonBlock;

use super::common::{Socks5Greeting, Socks5MethodSelection, Socks5Request, Socks5Response, CMD_CONNECT, REP_ADDRESS_TYPE_NOT_SUPPORTED, REP_COMMAND_NOT_SUPPORTED, REP_CONNECTION_NOT_ALLOWED, REP_CONNECTION_REFUSED, REP_GENERAL_SOCKS_SERVER_FAILURE, REP_HOST_UNRECHABLE, REP_NETWORK_UNRECHABLE, REP_SUCCEEDED, REP_TTL_EXPIRED, SOCKS5_VERSION};

pub struct Socks5Client {
    pub dst : SocketAddr,
    pub conn : TcpStream,
    pub buffer : Vec<u8>,
}

pub struct Socks5UdpClient {
    pub dst : SocketAddr,
    pub conn : TcpStream,
    pub udp : UdpSocket,
    pub buffer : Vec<u8>,
}

impl Socks5Client {
    pub fn connect(addr : &str, dst : SocketAddr) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        let buffer = vec![0; 4096];
        Ok(Self {
            buffer,
            conn : stream,
            dst
        })
    }

    pub fn greet(&mut self) -> std::io::Result<Socks5MethodSelection> {
        log::debug!("Greetings");
        let hello = Socks5Greeting {
            no_auth : true,
            user_pass : false,
            version : SOCKS5_VERSION
        };
        hello.write_to(&mut self.conn)?;
        let method = Socks5MethodSelection::read_from(&mut self.conn, &mut self.buffer)?;
        log::debug!("Autenticado con el servidor");
        Ok(method)
    }

    pub fn tcp_proxy(&mut self) -> std::io::Result<()> {
        let req = Socks5Request {
            version : SOCKS5_VERSION,
            cmd : CMD_CONNECT,
            rsv : 0x0,
            dst_addr : self.dst.ip().into(),
            dst_port : self.dst.port()
        };
        log::debug!("Sending Socks5Request to: {}", self.dst.ip());
        req.write_to(&mut self.conn)?;
        log::debug!("Receiving response");
        let res = Socks5Response::read_from(&mut self.conn, &mut self.buffer)?;
        Self::raise_response(&res)?;
        self.bind_proxy(res)?;
        Ok(())
    }

    fn bind_proxy(&mut self, res : Socks5Response) -> std::io::Result<()> {
        log::debug!("Binding to: {}:{}", res.bnd_addr.to_ip_addr(), res.bnd_port);
        //log::debug!("ProxyRemote: {}", self.conn.peer_addr()?);
        //let stream = TcpStream::connect(SocketAddr::new(res.bnd_addr.to_ip_addr(), res.bnd_port))?;
        //self.conn = stream;
        Ok(())
    }

    pub fn udp_proxy(mut self) -> std::io::Result<Socks5UdpClient> {
        let req = Socks5Request {
            version : SOCKS5_VERSION,
            cmd : CMD_CONNECT,
            rsv : 0x0,
            dst_addr : self.dst.ip().into(),
            dst_port : self.dst.port()
        };
        req.write_to(&mut self.conn)?;
        let res = Socks5Response::read_from(&mut self.conn, &mut self.buffer)?;
        Self::raise_response(&res)?;
        let udp = UdpSocket::bind("127.0.0.1:0")?;
        let clnt = Socks5UdpClient {
            buffer : self.buffer,
            conn : self.conn,
            dst : self.dst,
            udp
        };
        Ok(clnt)
    }

    pub fn raise_response(res : &Socks5Response) -> std::io::Result<()> {
        Err(match res.reply {
            REP_SUCCEEDED => return Ok(()),
            REP_GENERAL_SOCKS_SERVER_FAILURE => Error::new(ErrorKind::Interrupted, "General server failure"),
            REP_CONNECTION_NOT_ALLOWED => Error::new(ErrorKind::ConnectionRefused, "Connection not allowed"),
            REP_NETWORK_UNRECHABLE => Error::new(ErrorKind::NotConnected, "Network unrechable"),
            REP_HOST_UNRECHABLE => Error::new(ErrorKind::NotConnected, "Host unrechable"),
            REP_CONNECTION_REFUSED => Error::new(ErrorKind::ConnectionRefused, "Connection refused"),
            REP_TTL_EXPIRED => Error::new(ErrorKind::NotConnected, "TTL Expired"),
            REP_COMMAND_NOT_SUPPORTED => Error::new(ErrorKind::Unsupported, "Command not supported"),
            REP_ADDRESS_TYPE_NOT_SUPPORTED => Error::new(ErrorKind::InvalidInput, "Address type not supported"),
            _ => Error::new(ErrorKind::Interrupted, "General server failure"),
        })
    }

    pub fn set_nonblocking(&self, nonblocking : bool) -> std::io::Result<()> {
        self.conn.set_nonblocking(nonblocking)
    }
}

impl Write for Socks5Client {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.conn.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.conn.flush()
    }
}

impl Read for Socks5Client {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.conn.read(buf)
    }
}

impl NonBlock for Socks5Client {
    fn set_non_blocking(&self, nonblocking : bool) -> std::io::Result<()> {
        self.conn.set_nonblocking(nonblocking)
    }
}