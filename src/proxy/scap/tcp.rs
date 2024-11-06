use std::{borrow::Cow, io::{ErrorKind, Write}, path::PathBuf};

use httparse::EMPTY_HEADER;

use crate::proxy::scap::file::{FileMetadata, HttpHeaders, ScapHttpMeta, ScapHttpReqMeta, ScapHttpResMeta, ScapProtocolMeta};

use super::{common::{ScapEntry, ScapProtocol}, file::ScapTcpMeta};

pub fn process_scap_entry(scap : ScapEntry, traces : Option<&PathBuf>) -> std::io::Result<()> {
    let traces = match traces {
        Some(v) => v,
        None => return Ok(())
    };
    let hash = scap.address.get_hash();
    let dst_folder = traces.join(format!("{}", hash));
    if !std::fs::exists(&dst_folder)? {
        if let Err(e) = std::fs::create_dir_all(&dst_folder) {
            log::error!("Cannot create dir {:?} for saving races", dst_folder.to_string_lossy());
            return Err(e)
        }
    }
    let mut file_meta = std::fs::File::create(&dst_folder.join("request.json"))?;
    let meta = FileMetadata {
        address : scap.address,
        meta : ScapProtocolMeta::Tcp(ScapTcpMeta {

        }),
        protocol : scap.protocol,
        error : None
    };
    serde_json::to_writer_pretty(&mut file_meta, &meta).expect("Cannot fail serialization");
    if scap.protocol == ScapProtocol::Tcp {
        if !scap.received.trim_ascii().is_empty() {
            let mut req_file  = std::fs::File::create(&dst_folder.join("request.scap"))?;
            req_file.write_all(&scap.received)?;
        }
    
        if !scap.send[..].trim_ascii().is_empty() {
            let mut res_file  = std::fs::File::create(&dst_folder.join("response.scap"))?;
            res_file.write_all(&scap.send[..])?;
        }
    }
    Ok(())
}


fn body_is_chunked(headers : &[httparse::Header]) -> bool {
    for header in headers {
        if header.name.is_empty() {
            break;
        }
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if header.value == b"chunked" {
                return true
            }
            break
        }
    }
    false
}

fn clean_headers(headers : &mut [httparse::Header]) {
    for header in headers {
        if header.name.is_empty() {
            break;
        }
        *header = EMPTY_HEADER;
    }
}

fn parse_chunked_body_raw(buffer: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(buffer.len());
    let mut remaining_buffer = &buffer[..];

    loop {
        if let Some((size, size_end)) = find_chunk_size(&remaining_buffer) {
            if size == 0 {
                break;
            }
            let chunk_start = size_end;
            let chunk_end = chunk_start + size;
            if chunk_end <= remaining_buffer.len() {
                remaining_buffer[chunk_start..chunk_end].iter().for_each(|&c| body.push(c));
                remaining_buffer = &remaining_buffer[chunk_end + 2..];
            }else {
                break
            }
        } else {
            break;
        }
    }
    body
}

fn parse_chunked_body(buffer: &[u8], utf8 : bool) -> String {
    let mut body = String::with_capacity(buffer.len());
    let mut remaining_buffer = &buffer[..];

    loop {
        if let Some((size, size_end)) = find_chunk_size(&remaining_buffer) {
            if size == 0 {
                break;
            }
            let chunk_start = size_end;
            let chunk_end = chunk_start + size;
            if chunk_end <= remaining_buffer.len() {
                if utf8 {
                    body.push_str(&String::from_utf8_lossy(&remaining_buffer[chunk_start..chunk_end]));
                }else {
                    remaining_buffer[chunk_start..chunk_end].iter().map(|&c| c as char).for_each(|c| body.push(c));
                }
                
                remaining_buffer = &remaining_buffer[chunk_end + 2..];
            }else {
                break
            }
        } else {
            break;
        }
    }
    body
}

fn find_chunk_size(buffer: &[u8]) -> Option<(usize, usize)> {
    let mut end = 0;
    for (i, &byte) in buffer.iter().enumerate() {
        if byte == b'\r' && i + 1 < buffer.len() && buffer[i + 1] == b'\n' {
            end = i + 2;
            break;
        }
    }
    let size_str = std::str::from_utf8(&buffer[..end - 2]).ok()?;
    let size = usize::from_str_radix(size_str, 16).ok()?;
    Some((size, end))
}