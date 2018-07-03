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
    let config = Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
    };

    datalink::channel(&interface, config).unwrap()
}

pub fn get_connectionL3(interface: &NetworkInterface) -> Channel {
    let ethernet = 1; // ether type of ethernet == 1
    let config = Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: datalink::ChannelType::Layer3(ethernet),
        bpf_fd_attempts: 1000,
    };

    datalink::channel(&interface, config).unwrap()
}
