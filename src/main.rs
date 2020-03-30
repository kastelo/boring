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
    let mut dest2_buf = [0u8; MAX_PACKET];
    loop {
        match read_packet(&net_sock, &mut recv_buf, &mut dest_buf, &peer) {
            Some(pkt) => {
                let pkt_str = str::from_utf8(pkt).unwrap();
                eprintln!("got packet: {}", pkt_str);

                write_packet(&net_sock, pkt, &mut dest2_buf, &peer);
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
                        eprintln!("got response: {}", str::from_utf8(pkt).unwrap());
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

fn read_packet<'a>(
    net_sock: &UdpSocket,
    recv_buf: &mut [u8],
    dest_buf: &'a mut [u8],
    peer: &Tunn,
) -> Option<&'a [u8]> {
    let (n, src) = match net_sock.recv_from(recv_buf) {
        Ok((n, src)) => (n, src),
        Err(err) => {
            eprintln!("recv_from: {:?}", err);
            return None;
        }
    };
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
                        eprintln!("decapsulate(inner): {:?}", err);
                        break;
                    }
                    _ => {
                        continue;
                    }
                }
            }
            None
        }
        TunnResult::WriteToTunnelV4(packet, _) => Some(packet),
        TunnResult::WriteToTunnelV6(_, _) => None,
        TunnResult::Err(err) => {
            eprintln!("decapsulate: {:?}", err);
            None
        }
        TunnResult::Done => None,
    }
}

fn write_packet(net_sock: &UdpSocket, data: &[u8], dest_buf: &mut [u8], peer: &Tunn) {
    match peer.encapsulate(data, dest_buf) {
        TunnResult::WriteToNetwork(packet) => {
            net_sock.send(packet).unwrap();
        }
        _ => {}
    };
}
