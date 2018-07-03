use pnet::datalink::{self, Channel, Config, NetworkInterface};

// TODO: set Config.channel_type = Layer3
pub fn get_connection(interface: &NetworkInterface) -> Channel {
    match datalink::channel(&interface, Default::default()) {
        Ok(ether) => ether,
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    }
}

pub fn get_connectionL2(interface: &NetworkInterface) -> Channel {
    let config = Config {};

    datalink::channel(&interface).unwrap()
}
