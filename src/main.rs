#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate pnet;
extern crate ra;
use clap::{App, ArgMatches};
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{DataLinkSender, MacAddr, NetworkInterface};
use pnet::packet::ethernet::EtherType;
use pnet::packet::Packet;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::thread;
use std::time;

use ra::packet_builder::*;
use ra::packet_config::*;
use ra::packet_sender::*;

fn main() {
    env_logger::init();

    let yaml = load_yaml!("opt.yml");
    let app = App::from_yaml(yaml)
        .name(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .author(crate_authors!());

    let args = app.get_matches();

    // set upper layer first
    // parse parameters
    let interface = get_interface(&args);
    let ip_src = get_src_ip(&args);
    let ip_dst = get_dst_ip(&args);

    // router advertisement, L4
    let rt_advt = set_router_advt(ip_src, ip_dst, &args);

    // create ipv6 packet, L3
    let ipv6 = build_ipv6_of_rt_advt(ip_src, ip_dst, rt_advt.packet());

    // TODO: need arp function
    // Create a new channel, dealing with layer 2 packets
    let mut tx: Box<DataLinkSender> = match get_connection(&interface) {
        Ethernet(tx, _) => tx,
        _ => panic!("get_connection: failed to get connection"),
    };

    // create ether, L2
    let src_mac = get_src_mac(&args);
    let dst_mac = get_dst_mac(&args);

    // L2 ether
    let ether = build_ether_packet(src_mac, dst_mac, EtherType::new(0x86dd), ipv6.packet());

    let count = args
        .value_of("count")
        .unwrap_or("1")
        .parse::<usize>()
        .unwrap();

    let interval = args
        .value_of("interval")
        .unwrap_or("1")
        .parse::<u64>()
        .unwrap();

    let packet = ether.packet();

    for _ in 0..count {
        tx.send_to(&packet, None).unwrap().unwrap();
        thread::sleep(time::Duration::from_secs(interval));
    }
}

/// Find the network interface with the provided name
///
/// #Arguments
/// `interface_name` - interface name. exp.) enp1s0, wlan1
fn get_interface(args: &ArgMatches) -> NetworkInterface {
    let interface_name: &str = args.value_of("INTERFACE").unwrap();

    datalink::interfaces()
        .into_iter()
        .filter(|iface: &NetworkInterface| iface.name == interface_name)
        .next()
        .unwrap()
}

fn get_src_ip(args: &ArgMatches) -> Ipv6Addr {
    let interface = get_interface(args);

    if let Some(sip) = args.value_of("src-ip") {
        Ipv6Addr::from_str(sip).unwrap()
    } else {
        // TODO: need a test when a system has multiple v6 addr
        debug!("{:?}", interface.ips);

        let ips: Vec<Ipv6Addr> = interface
            .ips
            .iter()
            .map(|ip| ip.ip())
            .filter(|ip| ip.is_ipv6())
            .map(|ipv6| match ipv6 {
                IpAddr::V6(addr) => addr,
                _ => panic!("can't get ipv6 address: {:?}", ipv6), // TODO: convert ipv4 to ipv6
            })
            .filter(|ip| !ip.is_loopback()) // TODO: use link_local, but nightly
            .collect();

        ips[0]
    }
}

fn get_dst_ip(args: &ArgMatches) -> Ipv6Addr {
    Ipv6Addr::from_str(args.value_of("DST-IP").unwrap_or("ff02::1")).unwrap()
}

fn get_src_mac(args: &ArgMatches) -> MacAddr {
    if args.is_present("src-mac") {
        MacAddr::from_str(args.value_of("src-mac").unwrap()).unwrap()
    } else {
        get_interface(&args).mac_address()
    }
}

fn get_dst_mac(args: &ArgMatches) -> MacAddr {
    if let Some(dst) = args.value_of("dst-mac") {
        MacAddr::from_str(dst).unwrap()
    } else {
        MacAddr::from_str("ff:ff:ff:ff:ff:ff").unwrap()
    }
}
