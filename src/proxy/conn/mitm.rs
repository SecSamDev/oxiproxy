use std::{io::{Read, Write}, time::Duration};

use crate::proxy::scap::common::ScapSender;

use super::{common::ConnectionState, stream::{read_no_wait, write_no_wait, NonBlock}};

pub struct MitmStreamer<'a>{
    pub state : &'a mut ConnectionState,
    pub scap : &'a mut ScapSender,
    pub creaded : usize,
    pub sreaded : usize,
    pub cpos : usize,
    pub spos : usize,
    pub zero_counter : u64,
}

impl<'a> MitmStreamer<'a> {
    pub fn new(state : &'a mut ConnectionState, scap : &'a mut ScapSender) -> Self {
        Self {
            state,
            scap,
            creaded : 0,
            sreaded : 0,
            cpos : 0,
            spos : 0,
            zero_counter : 0
        }
    }
    /// Intercept any Stream connection
    pub fn intercept<C, S>(&mut self, cstream : &mut C, sstream : &mut S) -> std::io::Result<()>
    where
        C: Read + Write + Send + NonBlock + 'static,
        S: Read + Write + Send + NonBlock + 'static
    {
        cstream.set_non_blocking(true)?;
        sstream.set_non_blocking(true)?;
        loop {
            if self.creaded == 0 {
                let mut scap = self.scap.from_client();
                self.creaded = read_no_wait(sstream, &mut self.state.conn_buffers.client_buffer, &mut scap)?;
            } else {
                if self.cpos < self.creaded {
                    self.cpos +=
                        write_no_wait(cstream, &&self.state.conn_buffers.client_buffer[self.cpos..self.creaded])?;
                } else {
                    self.creaded = 0;
                    self.cpos = 0;
                }
            }

            if self.sreaded == 0 {
                let mut scap = self.scap.from_server();
                self.sreaded = read_no_wait(cstream, &mut self.state.conn_buffers.server_buffer, &mut scap)?;
            } else {
                if self.spos < self.sreaded {
                    self.spos += write_no_wait(
                        sstream,
                        &&self.state.conn_buffers.server_buffer[self.spos..self.sreaded],
                    )?;
                } else {
                    self.sreaded = 0;
                    self.spos = 0;
                }
            }
            if self.creaded == 0 && self.sreaded == 0 {
                self.zero_counter += 1;
            } else {
                self.zero_counter = 0;
            }

            if self.zero_counter > 0 {
                if self.zero_counter > 32 {
                    break
                }
                std::thread::sleep(Duration::from_millis(self.zero_counter * 10));
            }
        }
        Ok(())
    }
}