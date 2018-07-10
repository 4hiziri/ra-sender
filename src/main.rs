#[macro_use]
extern crate clap;

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate pnet;
extern crate ra;
use clap::{App, ArgMatches};
use pnet::datalink;
use pnet::datalink::{MacAddr, NetworkInterface};
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

    let tx = get_sender(&args);

    let src_ip = get_src_ip(&args);
    let dst_ip = get_dst_ip(&args);

    let rt_advt = get_router_advt(src_ip, dst_ip, &args);
    let ipv6 = build_ipv6_of_rt_advt(src_ip, dst_ip, rt_advt.packet());

    debug!("rt_advt: {:?}", rt_advt);
    debug!("ipv6: {:?}", ipv6);

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

    debug!("Send from {:?} to {:?}", src_ip, dst_ip);

    match tx {
        Sender::L2Sender(mut tx) => {
            debug!("Use layer2 sender");
            let src_mac = get_src_mac(&args);
            let dst_mac = get_dst_mac(&args);
            let ether = build_ether_packet(src_mac, dst_mac, EtherType::new(0x86dd), ipv6.packet());
            let ether = ether.packet();

            debug!("Send from {:?} to {:?}", src_mac, dst_mac);
            debug!("packet dump: {:x?}", ether);

            for _ in 0..count {
                tx.send_to(&ether, None).unwrap().unwrap();
                thread::sleep(time::Duration::from_secs(interval));
            }
        }
        Sender::L3Sender(mut tx) => {
            debug!("Use layer3 sender");
            let ipv6 = ipv6.packet();

            debug!("packet dump: {:x?}", ipv6);

            for _ in 0..count {
                tx.send_to(&ipv6, None).unwrap().unwrap();
                thread::sleep(time::Duration::from_secs(interval));
            }
        }
        Sender::L4Sender(mut tx) => {
            debug!("Use layer4 sender");
            let packet = rt_advt.to_immutable();
            let packet = packet.packet();
            debug!("packet dump: {:x?}", packet);

            panic!("This does not work! You should set --src-ip");

            for _ in 0..count {
                let packet = rt_advt.to_immutable();
                tx.send_to(packet, IpAddr::from(dst_ip)).unwrap();
                thread::sleep(time::Duration::from_secs(interval));
            }
        }
    };
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

fn host_ipv6_addr(interface: &NetworkInterface) -> Option<Ipv6Addr> {
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

    if ips.len() != 0 {
        Some(ips[0])
    } else {
        None
    }
}

/// Return source ipv6 address
/// If src-ip option doesn't exist, this return one of host ipv6 addresses
fn get_src_ip(args: &ArgMatches) -> Ipv6Addr {
    let interface = get_interface(args);

    args.value_of("src-ip")
        .map_or(host_ipv6_addr(&interface).unwrap(), |sip| {
            Ipv6Addr::from_str(sip).unwrap()
        })
}

/// Return destination address
/// If dst-ip option doesn't exist, this return all node broadcast(?) address.
/// TODO: fix
fn get_dst_ip(args: &ArgMatches) -> Ipv6Addr {
    Ipv6Addr::from_str(args.value_of("DST-IP").unwrap_or("ff02::1")).unwrap()
}

/// Return source MAC address
/// If src-mac option doesn't exist, this return MAC of selected host's interface.
fn get_src_mac(args: &ArgMatches) -> MacAddr {
    args.value_of("src-mac")
        .map_or(get_interface(&args).mac_address(), |mac| {
            MacAddr::from_str(mac).unwrap()
        })
}

/// Return destination MAC
/// If dst-mac option doesn't exist, this return broadcast address
fn get_dst_mac(args: &ArgMatches) -> MacAddr {
    MacAddr::from_str(args.value_of("dst-mac").unwrap_or("33:33:00:00:00:01")).unwrap()
}

// TODO: impl some functions likearp to controll everything
/// If options need layer2 sender, this return true
fn is_layer2(args: &ArgMatches) -> bool {
    args.is_present("src-mac") || args.is_present("dst-mac")
}

/// If options need layer3 sender, this return true
fn is_layer3(args: &ArgMatches) -> bool {
    args.is_present("src-ip")
}

/// If options doesn't need layer2 or layer3 sender, this return true
fn is_layer4(args: &ArgMatches) -> bool {
    !is_layer2(args) && !is_layer3(args)
}

/// Return proper sender according to options
fn get_sender(args: &ArgMatches) -> Sender {
    let interface = get_interface(&args);

    if is_layer2(&args) {
        // specify src-mac or dst-mac
        get_connection_layer2(&interface)
    } else if is_layer3(&args) {
        // specify src-ip
        get_connection_layer3(&interface)
    } else if is_layer4(&args) {
        // not specify src-mac, src-ip, dst-ip
        get_connection_layer4()
    } else {
        panic!("Arg pattern bugs!")
    }
}
