use cclone::clone_ca_certs;
use clap::Parser;
use proxy::start_proxy;

pub mod proxy;
pub mod pool;
pub mod cclone;

#[derive(Parser, Debug, Clone)]
pub enum ProxyCommand {
    Proxy(ProxyArguments),
    CloneCa(CloneCaArguments)
}

#[derive(Parser, Debug, Clone)]
pub struct CloneCaArguments {
    /// Folder with all the ROOT CA certificates
    #[clap(short='i', long)]
    pub input : String,
    /// Where to store cloned certificates
    #[clap(short='o', long)]
    pub output : String,
    /// Log level. 1=ERROR, 2=Warning, 3=Info, 4=Debug, 5=Trace
    #[clap(short='l', long, default_value="3")]
    pub log_level : u8,
}

#[derive(Parser, Debug, Clone)]
pub struct ProxyArguments {
    /// Listen port for the proxy
    #[clap(short='p', long)]
    pub port : u16,
    /// Listen address
    #[clap(short='b', long)]
    pub addr : String,
    /// List of pinned domains
    #[clap(short='d', long, value_parser, num_args = 1, value_delimiter = ' ')]
    pub pinned_domain : Vec<String>,
    /// Folder with all the ROOT CA certificates
    #[clap(short='r', long)]
    pub root_ca : String,
    /// Log level. 1=ERROR, 2=Warning, 3=Info, 4=Debug, 5=Trace
    #[clap(short='l', long, default_value="3")]
    pub log_level : u8,
    /// Where to save SCAPs (Socket Captures)
    #[clap(short='c', long, default_value="None")]
    pub trace_folder : Option<String>,
    /// Where to save SCAPs (Socket Captures)
    #[clap(short='w', long, default_value="128")]
    pub workers : u16,
    #[clap(short='s', long)]
    pub socks5_server : String
}

fn main() {
    let arguments = ProxyCommand::parse();
    match arguments {
        ProxyCommand::Proxy(args) => {
            init_log(args.log_level);
            start_proxy(args).unwrap();
        },
        ProxyCommand::CloneCa(args) => {
            init_log(args.log_level);
            clone_ca_certs(&args.input, &args.output);
        },
    }

}


fn init_log(level : u8) {
    let lg = match level {
        5 => "trace",
        4 => "debug",
        3 => "info",
        2 => "warn",
        1 => "error",
        0 => "error",
        _ => "trace"
    };
    std::env::set_var("RUST_LOG", lg);
    env_logger::init();
}