use httparse::Header;
use serde::{ser::SerializeSeq, Serialize};

use super::common::{ScapAddresses, ScapProtocol};

#[derive(Debug, Clone, Serialize)]
pub struct FileMetadata <'a>{
    pub address : ScapAddresses,
    pub protocol : ScapProtocol,
    pub meta : ScapProtocolMeta<'a>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub error : Option<String>
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ScapProtocolMeta<'a> {
    Http(ScapHttpMeta<'a>),
    Tcp(ScapTcpMeta)
}
#[derive(Debug, Clone, Serialize)]
pub struct ScapHttpMeta <'a>{
    pub request : ScapHttpReqMeta<'a>,
    pub response : ScapHttpResMeta<'a>
}

#[derive(Debug, Clone, Serialize)]
pub struct ScapHttpReqMeta <'a>{
    pub method : &'a str,
    pub version : u8,
    pub path : &'a str,
    pub headers : HttpHeaders<'a>,
    pub body_size : u64,
    pub raw_size : u64
}
#[derive(Debug, Clone, Serialize)]
pub struct ScapHttpResMeta <'a>{
    pub reason : &'a str,
    pub code : u16,
    pub version : u8,
    pub headers : HttpHeaders<'a>,
    pub body_size : u64,
    pub raw_size : u64
}

#[derive(Debug, Clone, Serialize)]
pub struct ScapTcpMeta {

}
#[derive(Debug, Clone)]
pub struct HttpHeaders<'a>(pub &'a [Header<'a>]);

impl<'a> Serialize for HttpHeaders<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        let mut map = serializer.serialize_seq(Some(self.0.len()))?;
        for header in self.0 {
            if header.name.is_empty() || header.value.is_empty() {
                break
            }
            map.serialize_element(&(header.name, String::from_utf8_lossy(header.value)))?;
        }
        map.end()
    }
}




#[test]
fn should_deserialize() {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    headers[0] = Header {
        name: "header1",
        value: b"header value"
    };
    let mut res_headers = [httparse::EMPTY_HEADER; 16];
    res_headers[0] = Header {
        name: "header1",
        value: b"header value"
    };
    let req = ScapHttpReqMeta {
        headers: HttpHeaders(&headers),
        method: "GET",
        version: 1,
        path: "/ROOT",
        body_size : 0,
        raw_size : 0
    };
    let res = ScapHttpResMeta {
        headers: HttpHeaders(&res_headers),
        reason: "OK",
        version: 1,
        code: 200,
        body_size : 0,
        raw_size : 0
    };

    let meta = ScapHttpMeta {
        request : req,
        response : res
    };

    let request = FileMetadata {
        address : ScapAddresses {
            remote : std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 0)),
            rport : 80,
            source : std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 0)),
            sport : 12345
        },
        meta : ScapProtocolMeta::Http(meta),
        protocol : ScapProtocol::Http,
        error: None,
    };
    let data = serde_json::to_string_pretty(&request).unwrap();
    println!("{}", data);
}