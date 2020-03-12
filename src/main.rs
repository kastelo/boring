use boringtun::noise::{Tunn, TunnResult};
use clap::{App, Arg};
use std::net::UdpSocket;
use std::str;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
const MAX_PACKET: usize = 65536;

struct KeyPair {
    private: &'static str,
    public: &'static str,
}

fn main() {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .args(&[
            Arg::with_name("listenport")
                .takes_value(true)
                .value_name("PORT")
                .long("listen-port")
                .short("l")
                .help("Listen port for \"server\" (srcport for \"client\")")
                .default_value("2121"),
            Arg::with_name("endpoint")
                .takes_value(true)
                .value_name("HOST:PORT")
                .long("endpoint")
                .short("e")
                .help("Connect to this \"server\""),
        ])
        .get_matches();
    let endpoint = matches.is_present("endpoint");
    let listenport = matches.value_of("listenport").unwrap();

    let net_sock = if !endpoint {
        UdpSocket::bind(format!("0.0.0.0:{}", listenport)).unwrap()
    } else {
        let hostport = matches.value_of("endpoint").unwrap();
        let sock = UdpSocket::bind(format!("0.0.0.0:{}", listenport)).unwrap();
        sock.connect(hostport)
            .unwrap_or_else(|e| panic!("connect {}: {}", hostport, e));
        sock
    };

    let client_pair = KeyPair {
        private: "6FWqlhJJd4rCdamaRfjTxyVBllwCqwDiGDVf2PBqmEQ=",
        public: "AVbCPrafj2II/ZT3xOdSwWYNDYgTR9tdiNlKJ6Uvb3U=",
    };

    let server_pair = KeyPair {
        private: "WOrGm3kEvdDI5OnjlYUrpL2bIhx++cZ/cq+XE7ZhHm8=",
        public: "/sx0Z0YvqP0Tazmxbi3YvfYMP4FQy3bYpANJFqiHjSs=",
    };

    if !endpoint {
        // We're the echo side
        let peer = Tunn::new(
            Arc::new(server_pair.private.parse().unwrap()),
            Arc::new(client_pair.public.parse().unwrap()),
            None,
            None,
            100,
            None,
        )
        .unwrap();
        echo_loop(&net_sock, peer);
    }

    // We're the sender
    let peer = Tunn::new(
        Arc::new(client_pair.private.parse().unwrap()),
        Arc::new(server_pair.public.parse().unwrap()),
        None,
        None,
        100,
        None,
    )
    .unwrap();
    sender_loop(&net_sock, peer);
}

fn echo_loop(net_sock: &UdpSocket, peer: Box<Tunn>) {
    let mut recv_buf = [0u8; MAX_PACKET];
    let mut dest_buf = [0u8; MAX_PACKET];
    loop {
        match read_packet(&net_sock, &mut recv_buf, &mut dest_buf, &peer) {
            Some(pkt) => {
                let pkt_str = str::from_utf8(pkt.as_slice()).unwrap();
                eprintln!("got packet: {}", pkt_str);

                write_packet(&net_sock, pkt.as_slice(), &mut dest_buf, &peer);
                eprintln!("sent response: {}", pkt_str);
            }
            None => {}
        };
    }
}

fn sender_loop(net_sock: &UdpSocket, peer: Box<Tunn>) {
    let peer: Arc<Box<Tunn>> = Arc::from(peer);
    {
        let peer = peer.clone();
        let net_sock = net_sock.try_clone().unwrap();
        thread::spawn(move || {
            let mut recv_buf = [0u8; MAX_PACKET];
            let mut dest_buf = [0u8; MAX_PACKET];
            loop {
                match read_packet(&net_sock, &mut recv_buf, &mut dest_buf, &peer) {
                    Some(pkt) => {
                        eprintln!("got response: {}", str::from_utf8(pkt.as_slice()).unwrap());
                    }
                    None => {}
                };
            }
        });
    }

    let mut i = 0;
    let mut dest_buf = [0u8; MAX_PACKET];
    loop {
        let data = format!("number-{}", i);
        write_packet(&net_sock, data.as_bytes(), &mut dest_buf, &peer);
        eprintln!("sent packet: {}", data);

        thread::sleep(Duration::from_millis(750));
        i += 1;
    }
}

fn read_packet(
    net_sock: &UdpSocket,
    recv_buf: &mut [u8],
    dest_buf: &mut [u8],
    peer: &Tunn,
) -> Option<Vec<u8>> {
    let (n, src) = net_sock.recv_from(recv_buf).unwrap();
    match peer.decapsulate(None, &recv_buf[..n], dest_buf) {
        TunnResult::WriteToNetwork(packet) => {
            net_sock.connect(src).unwrap();
            net_sock.send(packet).unwrap();
            loop {
                let mut send_buf = [0u8; MAX_PACKET];
                match peer.decapsulate(None, &[], &mut send_buf) {
                    TunnResult::WriteToNetwork(packet) => {
                        net_sock.send(packet).unwrap();
                    }
                    TunnResult::Done => {
                        break;
                    }
                    TunnResult::Err(err) => {
                        panic!(err);
                    }
                    _ => {
                        continue;
                    }
                }
            }
            None
        }
        TunnResult::WriteToTunnelV4(packet, _) => Some(unwrap_from_ipv4(packet)),
        TunnResult::WriteToTunnelV6(_, _) => None,
        TunnResult::Err(err) => {
            panic!(err);
        }
        TunnResult::Done => None,
    }
}

fn write_packet(net_sock: &UdpSocket, data: &[u8], dest_buf: &mut [u8], peer: &Tunn) {
    let pkt = wrap_in_ipv4(data);
    match peer.encapsulate(pkt.as_slice(), dest_buf) {
        TunnResult::WriteToNetwork(packet) => {
            net_sock.send(packet).unwrap();
        }
        _ => {}
    };
}

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;

fn wrap_in_ipv4(data: &[u8]) -> Vec<u8> {
    let mut header = [0u8; IPV4_MIN_HEADER_SIZE];
    let mut packet = Vec::new();
    let packet_len = data.len() + header.len();
    header[0] = 4 << 4;
    header[IPV4_LEN_OFF] = (packet_len >> 8) as u8;
    header[IPV4_LEN_OFF + 1] = packet_len as u8;
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&data);
    packet
}

fn unwrap_from_ipv4(data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&data[IPV4_MIN_HEADER_SIZE..]);
    packet
}
