extern crate atty;
extern crate clap;
extern crate env_logger;
extern crate getopts;
extern crate log;
extern crate serde_json;
extern crate solana;

use atty::{is, Stream};
use clap::{App, Arg};
use solana::crdt::{ReplicatedData, TestNode};
use solana::fullnode::{FullNode, InFile, OutFile};
use solana::service::Service;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::exit;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
//use std::time::Duration;

fn main() -> () {
    env_logger::init();
    let matches = App::new("fullnode")
        .arg(
            Arg::with_name("identity")
                .short("l")
                .long("local")
                .value_name("FILE")
                .takes_value(true)
                .help("run with the identity found in FILE"),
        )
        .arg(
            Arg::with_name("testnet")
                .short("t")
                .long("testnet")
                .value_name("HOST:PORT")
                .takes_value(true)
                .help("testnet; connect to the network at this gossip entry point"),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("FILE")
                .takes_value(true)
                .help("output log to FILE, defaults to stdout (ignored by validators)"),
        )
        .get_matches();
    if is(Stream::Stdin) {
        eprintln!("nothing found on stdin, expected a log file");
        exit(1);
    }

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8000);
    let mut repl_data = ReplicatedData::new_leader(&bind_addr);
    if let Some(l) = matches.value_of("identity") {
        let path = l.to_string();
        if let Ok(file) = File::open(path.clone()) {
            if let Ok(data) = serde_json::from_reader(file) {
                repl_data = data;
            } else {
                eprintln!("failed to parse {}", path);
                exit(1);
            }
        } else {
            eprintln!("failed to read {}", path);
            exit(1);
        }
    }
    let mut node = TestNode::new_with_bind_addr(repl_data, bind_addr);
    let exit = Arc::new(AtomicBool::new(false));
    let fullnode = if let Some(t) = matches.value_of("testnet") {
        let testnet_address_string = t.to_string();
        let testnet_addr = testnet_address_string.parse().unwrap();
        FullNode::new(node, false, InFile::StdIn, Some(testnet_addr), None, exit)
    } else {
        node.data.current_leader_id = node.data.id.clone();

        let outfile = if let Some(o) = matches.value_of("output") {
            OutFile::Path(o.to_string())
        } else {
            OutFile::StdOut
        };
        FullNode::new(node, true, InFile::StdIn, None, Some(outfile), exit)
    };
    fullnode.join().expect("join");
}
