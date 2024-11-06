use std::{fmt::{Debug, Display}, io::{ErrorKind, Read, Result, Write}, net::{IpAddr, Ipv4Addr, Ipv6Addr}};

pub const SOCKS5_VERSION: u8 = 0x05;

pub const NO_AUTHENTICATION: u8 = 0x00;
pub const USERNAME_PASSWORD : u8 = 0x02;

pub const ADDR_TYPE_IPV4: u8 = 0x01;
pub const ADDR_TYPE_DOMAIN: u8 = 0x03;
pub const ADDR_TYPE_IPV6: u8 = 0x04;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const REP_SUCCEEDED : u8 = 0;
pub const REP_GENERAL_SOCKS_SERVER_FAILURE : u8 = 1;
pub const REP_CONNECTION_NOT_ALLOWED : u8 = 2;
pub const REP_NETWORK_UNRECHABLE : u8 = 3;
pub const REP_HOST_UNRECHABLE : u8 = 4;
pub const REP_CONNECTION_REFUSED : u8 = 5;
pub const REP_TTL_EXPIRED : u8 = 6;
pub const REP_COMMAND_NOT_SUPPORTED : u8 = 7;
pub const REP_ADDRESS_TYPE_NOT_SUPPORTED : u8 = 8;

// Estructura para el saludo SOCKS5 (Client Hello)
#[derive(Debug, Clone)]
pub struct Socks5Greeting  {
    pub version: u8,
    pub user_pass : bool,
    pub no_auth : bool
}

#[derive(Debug, Clone)]
pub struct Socks5MethodSelection {
    pub version: u8,
    pub method: u8,
}

#[derive(Debug, Clone)]
pub enum Socks5Address {
    V4(Ipv4Addr),
    Domain(String),
    V6(Ipv6Addr),
}

impl Display for Socks5Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Socks5Address::V4(v) => f.write_fmt(format_args!("{}", v)),
            Socks5Address::Domain(v) => f.write_str(&v),
            Socks5Address::V6(v) => f.write_fmt(format_args!("{}", v)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Socks5Request {
    pub version: u8,
    pub cmd: u8,
    pub rsv: u8,
    pub dst_addr: Socks5Address,
    pub dst_port: u16,
}

#[derive(Debug, Clone)]
pub struct Socks5Response {
    pub version: u8,
    pub reply: u8,
    pub rsv: u8,
    pub bnd_addr: Socks5Address,
    pub bnd_port: u16,
}

impl Socks5Greeting  {

    pub fn read_from<R: Read>(reader: &mut R, buffer : &mut [u8]) -> Result<Self> {
        reader.read_exact(&mut buffer[0..2])?;
        let version = buffer[0];
        let n_methods = buffer[1] as usize;
        if n_methods > buffer.len() {
            return Err(std::io::Error::new(ErrorKind::OutOfMemory, "Not enought buffer for methods"))
        }
        reader.read_exact(&mut buffer[0..n_methods])?;
        let mut user_pass = false;
        let mut no_auth = false;
        for &mthd in &buffer[0..n_methods] {
            match mthd {
                NO_AUTHENTICATION => {
                    no_auth = true;
                },
                USERNAME_PASSWORD => {
                    user_pass = true;
                },
                _ => continue
            }
        }
        Ok(Self { version, user_pass, no_auth })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut out = [self.version, 0, NO_AUTHENTICATION, NO_AUTHENTICATION];
        let mut n_methods = 0;
        if self.user_pass {
            n_methods += 1;
            out[2] = USERNAME_PASSWORD;
        }
        if self.no_auth {
            n_methods += 1;
        }
        out[1] = n_methods;
        writer.write_all(&out[0..n_methods as usize + 2])?;
        Ok(())
    }
}

impl Socks5MethodSelection {

    pub fn read_from<R: Read>(reader: &mut R, buffer : &mut [u8]) -> Result<Self> {
        reader.read_exact(&mut buffer[0..2])?;
        let version = buffer[0];
        let method = buffer[1];
        Ok(Self { version, method })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&[self.version, self.method])
    }
}


impl Socks5Address {
    pub fn read_from<R: Read>(reader: &mut R, addr_type: u8, buffer : &mut [u8]) -> std::io::Result<Self> {
        match addr_type {
            ADDR_TYPE_IPV4 => {
                reader.read_exact(&mut buffer[0..4])?;
                let addr : [u8; 4] = buffer[0..4].try_into().unwrap_or_default();
                Ok(Socks5Address::V4(Ipv4Addr::from(addr)))
            }
            ADDR_TYPE_DOMAIN => {
                reader.read_exact(&mut buffer[0..1])?;
                let len = buffer[0] as usize;
                reader.read_exact(&mut buffer[0..len])?;
                let domain = String::from_utf8(buffer[0..len].to_vec())
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid domain"))?;
                Ok(Socks5Address::Domain(domain))
            }
            ADDR_TYPE_IPV6 => {
                reader.read_exact(&mut buffer[0..16])?;
                let addr : [u8; 16] = buffer[0..16].try_into().unwrap_or_default();
                Ok(Socks5Address::V6(Ipv6Addr::from(addr)))
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unsupported address type: {}", addr_type),
            )),
        }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&[self.addr_type()])?;
        match self {
            Socks5Address::V4(addr) => writer.write_all(&addr.to_bits().to_be_bytes()),
            Socks5Address::Domain(domain) => {
                let domain_bytes = domain.as_bytes();
                writer.write_all(&[domain_bytes.len() as u8])?;
                writer.write_all(domain_bytes)
            }
            Socks5Address::V6(addr) => writer.write_all(&addr.to_bits().to_be_bytes()),
        }
    }

    pub fn addr_type(&self) -> u8 {
        match self {
            Socks5Address::V4(_) => ADDR_TYPE_IPV4,
            Socks5Address::Domain(_) => ADDR_TYPE_DOMAIN,
            Socks5Address::V6(_) => ADDR_TYPE_IPV6,
        }
    }
    pub fn to_ip_addr(&self) -> IpAddr {
        match self {
            Socks5Address::V4(v) => IpAddr::V4(v.clone()),
            Socks5Address::Domain(_) => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            Socks5Address::V6(v) => IpAddr::V6(*v),
        }
    }
}


impl Socks5Request {
    pub fn read_from<R: Read>(reader: &mut R, buffer : &mut [u8]) -> std::io::Result<Self> {
        reader.read_exact(&mut buffer[0..4])?;
        let version = buffer[0];
        let cmd = buffer[1];
        let rsv = buffer[2];
        let addr_type = buffer[3];
        let dst_addr = Socks5Address::read_from(reader, addr_type, buffer)?;
        reader.read_exact(&mut buffer[0..2])?;
        let dst_port = u16::from_be_bytes([buffer[0], buffer[1]]);
        Ok(Socks5Request {
            version,
            cmd,
            rsv,
            dst_addr,
            dst_port,
        })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&[self.version, self.cmd, self.rsv])?;
        self.dst_addr.write_to(writer)?;
        writer.write_all(&self.dst_port.to_be_bytes())
    }
}

impl Socks5Response {

    pub fn read_from<R: Read>(reader: &mut R, buffer : &mut [u8]) -> std::io::Result<Self> {
        reader.read_exact(&mut buffer[0..4])?;
        let version = buffer[0];
        let reply = buffer[1];
        let rsv = buffer[2];
        let addr_type = buffer[3];
        let bnd_addr = Socks5Address::read_from(reader, addr_type, buffer)?;
        reader.read_exact(&mut buffer[0..2])?;
        let bnd_port = u16::from_be_bytes([buffer[0], buffer[1]]);
        Ok(Self {
            version,
            reply,
            rsv,
            bnd_addr,
            bnd_port,
        })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&[
            self.version,
            self.reply,
            self.rsv
        ])?;
        self.bnd_addr.write_to(writer)?;
        writer.write_all(&self.bnd_port.to_be_bytes())
    }
}

impl From<IpAddr> for Socks5Address {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ipv4_addr) => Socks5Address::V4(ipv4_addr),
            IpAddr::V6(ipv6_addr) => Socks5Address::V6(ipv6_addr),
        }
    }
}