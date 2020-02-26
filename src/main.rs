use boringtun::noise::{Tunn, TunnResult, Verbosity};
use clap::{App, Arg};
use std::net::UdpSocket;
use std::str;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
const MAX_PACKET: usize = 65536;

const SERVER: &str = "***REMOVED***:2121";

struct KeyPair {
    private: &'static str,
    public: &'static str,
}

fn main() {
    let matches = App::new("bt")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Daniel Lublin <d@lublin.se>")
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

    let close = Arc::new(AtomicBool::new(false));

    let client_pair = KeyPair {
        private: "6FWqlhJJd4rCdamaRfjTxyVBllwCqwDiGDVf2PBqmEQ=",
        public: "AVbCPrafj2II/ZT3xOdSwWYNDYgTR9tdiNlKJ6Uvb3U=",
    };

    let server_pair = KeyPair {
        private: "WOrGm3kEvdDI5OnjlYUrpL2bIhx++cZ/cq+XE7ZhHm8=",
        public: "/sx0Z0YvqP0Tazmxbi3YvfYMP4FQy3bYpANJFqiHjSs=",
    };

    let peer_sock = if !endpoint {
        wireguard_test_peer(
            net_sock,
            &server_pair.private,
            &client_pair.public,
            Box::new(|e: &str| eprintln!("server: {}", e)),
            close.clone(),
        )
    } else {
        wireguard_test_peer(
            net_sock,
            &client_pair.private,
            &server_pair.public,
            Box::new(|e: &str| eprintln!("client: {}", e)),
            close.clone(),
        )
    };

    if !endpoint {
        loop {
            let data = read_ipv4_packet(&peer_sock);
            eprintln!("sending back: {}", str::from_utf8(&data).unwrap());
            write_ipv4_packet(&peer_sock, &data);
        }
    } else {
        peer_sock
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .unwrap();
        peer_sock
            .set_write_timeout(Some(Duration::from_millis(1000)))
            .unwrap();

        for i in 0..64 {
            write_ipv4_packet(&peer_sock, format!("number-{}", i).as_bytes());
            let r = read_ipv4_packet(&peer_sock);
            eprintln!("response: {}", str::from_utf8(&r).unwrap());
        }
    }

    close.store(true, Ordering::Relaxed);
}

// Simple counter, atomically increasing by one each call
struct AtomicCounter {
    ctr: AtomicUsize,
}
impl AtomicCounter {
    pub fn next(&self) -> usize {
        self.ctr.fetch_add(1, Ordering::Relaxed)
    }
}
static NEXT_PORT: AtomicCounter = AtomicCounter {
    ctr: AtomicUsize::new(30000),
};

// Start a WireGuard peer
fn wireguard_test_peer(
    network_socket: UdpSocket,
    static_private: &str,
    peer_static_public: &str,
    logger: Box<dyn Fn(&str) + Send>,
    close: Arc<AtomicBool>,
) -> UdpSocket {
    let static_private = static_private.parse().unwrap();
    let peer_static_public = peer_static_public.parse().unwrap();

    let mut peer = Tunn::new(
        Arc::new(static_private),
        Arc::new(peer_static_public),
        None,
        None,
        100,
        None,
    )
    .unwrap();
    peer.set_logger(logger, Verbosity::Debug);

    let peer: Arc<Box<Tunn>> = Arc::from(peer);

    let (iface_socket_ret, iface_socket) = connected_sock_pair();

    network_socket
        .set_read_timeout(Some(Duration::from_millis(1000)))
        .unwrap();
    iface_socket
        .set_read_timeout(Some(Duration::from_millis(1000)))
        .unwrap();

    // The peer has three threads:
    // 1) listens on the network for encapsulated packets and decapsulates them
    {
        let network_socket = network_socket.try_clone().unwrap();
        let iface_socket = iface_socket.try_clone().unwrap();
        let peer = peer.clone();
        let close = close.clone();

        thread::spawn(move || loop {
            // Listen on the network
            let mut recv_buf = [0u8; MAX_PACKET];
            let mut send_buf = [0u8; MAX_PACKET];

            let (n, src) = match network_socket.recv_from(&mut recv_buf) {
                Ok((n, src)) => (n, src),
                Err(_) => {
                    if close.load(Ordering::Relaxed) {
                        return;
                    }
                    continue;
                }
            };

            match peer.decapsulate(None, &recv_buf[..n], &mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    network_socket.connect(src).unwrap();
                    network_socket.send(packet).unwrap();
                    // Send form queue?
                    loop {
                        let mut send_buf = [0u8; MAX_PACKET];
                        match peer.decapsulate(None, &[], &mut send_buf) {
                            TunnResult::WriteToNetwork(packet) => {
                                network_socket.send(packet).unwrap();
                            }
                            _ => {
                                break;
                            }
                        }
                    }
                }
                TunnResult::WriteToTunnelV4(packet, _) => {
                    network_socket.connect(src).unwrap();
                    iface_socket.send(packet).unwrap();
                }
                TunnResult::WriteToTunnelV6(packet, _) => {
                    network_socket.connect(src).unwrap();
                    iface_socket.send(packet).unwrap();
                }
                _ => {}
            }
        });
    }

    // 2) listens on the iface for raw packets and encapsulates them
    {
        let network_socket = network_socket.try_clone().unwrap();
        let iface_socket = iface_socket.try_clone().unwrap();
        let peer = peer.clone();
        let close = close.clone();

        thread::spawn(move || loop {
            let mut recv_buf = [0u8; MAX_PACKET];
            let mut send_buf = [0u8; MAX_PACKET];

            let n = match iface_socket.recv(&mut recv_buf) {
                Ok(n) => n,
                Err(_) => {
                    if close.load(Ordering::Relaxed) {
                        return;
                    }
                    continue;
                }
            };

            match peer.encapsulate(&recv_buf[..n], &mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    network_socket.send(packet).unwrap();
                }
                _ => {}
            }
        });
    }

    // 3) times maintenance function responsible for state expiration
    thread::spawn(move || loop {
        if close.load(Ordering::Relaxed) {
            return;
        }

        let mut send_buf = [0u8; MAX_PACKET];
        match peer.update_timers(&mut send_buf) {
            TunnResult::WriteToNetwork(packet) => {
                network_socket.send(packet).unwrap();
            }
            _ => {}
        }

        thread::sleep(Duration::from_millis(200));
    });

    iface_socket_ret
}

fn connected_sock_pair() -> (UdpSocket, UdpSocket) {
    let addr_a = format!("localhost:{}", NEXT_PORT.next());
    let addr_b = format!("localhost:{}", NEXT_PORT.next());
    let sock_a = UdpSocket::bind(&addr_a).unwrap();
    let sock_b = UdpSocket::bind(&addr_b).unwrap();
    sock_a.connect(&addr_b).unwrap();
    sock_b.connect(&addr_a).unwrap();
    (sock_a, sock_b)
}

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
// const IPV4_SRC_IP_OFF: usize = 12;
// const IPV4_DST_IP_OFF: usize = 16;
// const IPV4_IP_SZ: usize = 4;

// Reads a decapsulated packet and strips its IPv4 header
fn read_ipv4_packet(socket: &UdpSocket) -> Vec<u8> {
    let mut data = [0u8; MAX_PACKET];
    let mut packet = Vec::new();
    let len = socket.recv(&mut data).unwrap();
    packet.extend_from_slice(&data[IPV4_MIN_HEADER_SIZE..len]);
    packet
}

// Appends an IPv4 header to a buffer and writes the resulting "packet"
fn write_ipv4_packet(socket: &UdpSocket, data: &[u8]) {
    let mut header = [0u8; IPV4_MIN_HEADER_SIZE];
    let mut packet = Vec::new();
    let packet_len = data.len() + header.len();
    header[0] = 4 << 4;
    header[IPV4_LEN_OFF] = (packet_len >> 8) as u8;
    header[IPV4_LEN_OFF + 1] = packet_len as u8;
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&data);
    socket.send(&packet).unwrap();
}
