use std::{borrow::Cow, collections::BTreeMap, hash::{Hash, Hasher}, io::Write, net::IpAddr, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

use common::{ScapEntry, ScapEvent};
use crossbeam_channel::{Receiver, Sender};
use http::process_scap_entry;
use httparse::EMPTY_HEADER;

pub mod file;
pub mod common;
pub mod http;
pub mod tcp;

pub fn spawn_scap_store(receiver : Receiver<ScapEvent>, traces : Option<&String>) {
    let trace_location = traces.map(|v| std::path::PathBuf::from(v));
    std::thread::spawn(move || {
        let mut store = BTreeMap::new();
        let mut old_initialized: Vec<ScapEntry> = Vec::new();
        loop {
            let cmd = receiver.recv().unwrap();
            match cmd {
                ScapEvent::Connect(connect) => {
                    let hash = connect.address.get_hash();
                    let entry = match old_initialized.pop() {
                        Some(mut v) => {
                            v.address = connect.address;
                            v.received.clear();
                            v.send.clear();
                            v
                        },
                        None => ScapEntry::new(connect.address, connect.protocol)
                    };

                    store.insert(hash, entry);
                },
                ScapEvent::Receive(mut scap_data) => {
                    let data = match store.get_mut(&scap_data.id) {
                        Some(v) => v,
                        None => continue
                    };
                    data.from_server(&mut scap_data.data);
                },
                ScapEvent::Send(mut scap_data) => {
                    let data = match store.get_mut(&scap_data.id) {
                        Some(v) => v,
                        None => continue
                    };
                    data.from_client(&mut scap_data.data);
                },
                ScapEvent::Close(scap_addresses) => {
                    let scap = match store.remove(&scap_addresses.get_hash()) {
                        Some(v) => v,
                        None => continue
                    };
                    log::info!("---- scap----");
                    log::info!("{:?} ({:?})", scap.address, scap.protocol);
                    let res = match scap.protocol {
                        common::ScapProtocol::Http => http::process_scap_entry(scap, trace_location.as_ref()),
                        common::ScapProtocol::Tcp => tcp::process_scap_entry(scap, trace_location.as_ref()),
                        common::ScapProtocol::Tls => tcp::process_scap_entry(scap, trace_location.as_ref()),
                        _ => continue
                    };
                    if let Err(e) = res {
                        log::error!("{e}");
                    }
                },
            }
        }
    });
}
