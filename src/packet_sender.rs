use pnet::datalink::{self, Channel, Config, DataLinkSender, NetworkInterface};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{
    transport_channel, TransportChannelType, TransportProtocol, TransportSender,
};
use std::boxed::Box;

pub enum Sender {
    L2Sender(Box<DataLinkSender>),
    L3Sender(Box<DataLinkSender>),
    L4Sender(TransportSender),
}

// TODO: set Config.channel_type = Layer3
pub fn get_connection(interface: &NetworkInterface) -> Channel {
    // datalink::channel(&interface, Default::default()).map_err();
    match datalink::channel(&interface, Default::default()) {
        Ok(ether) => ether,
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    }
}

// send just bytes
pub fn get_connection_layer2(interface: &NetworkInterface) -> Sender {
    let config = Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
    };

    let tx = match datalink::channel(&interface, config).unwrap() {
        Channel::Ethernet(tx, _) => tx,
        _ => panic!("Cannot get layer2 channel"), // to option?
    };

    Sender::L2Sender(tx)
}

// need make Ip header
pub fn get_connection_layer3(interface: &NetworkInterface) -> Sender {
    let ethernet = 0x800; // ether type of ethernet == 1

    let config = Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: datalink::ChannelType::Layer3(ethernet),
        bpf_fd_attempts: 1000,
    };

    let tx = match datalink::channel(&interface, config).unwrap() {
        Channel::Ethernet(tx, _) => tx,
        _ => panic!("Cannot get layer3 channel"), // to option?
    };

    Sender::L3Sender(tx)
}

// need destination addr, set Packet
pub fn get_connection_layer4() -> Sender {
    let channel = transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)),
    );

    Sender::L4Sender(channel.unwrap().0)
}
