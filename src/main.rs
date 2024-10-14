use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tokio::time::{sleep, timeout};
use socket2::{Domain, Protocol, Type, Socket};
use rand::Rng;
use pnet::datalink;
use clap::Parser;
use tokio_stream;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use futures::StreamExt;
use pnet::packet::Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket, TcpFlags};
use std::mem::MaybeUninit;

const MAX_RETRIES: u8 = 1;
const PACKET_DELAY: Duration = Duration::from_millis(1050);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);
const TCP_HEADER_SIZE: usize = 20;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    target: String,
    #[arg(short, long, default_value = "1")]
    start_port: u16,
    #[arg(short, long, default_value = "1024")]
    end_port: u16,
    #[arg(short, long, default_value = "100")]
    concurrency: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PortStatus {
    Open,
    Closed,
    Filtered,
}

struct Scanner {
    socket: Arc<Mutex<Socket>>,
}

impl Scanner {
    async fn syn_scan(&self, target: IpAddr, start_port: u16, end_port: u16, source_ip: Ipv4Addr, concurrency: usize) -> Vec<u16> {
        let (input_tx, input_rx) = mpsc::channel(concurrency);
        let (output_tx, output_rx) = mpsc::channel(concurrency);

        tokio::spawn(async move {
            for port in start_port..=end_port {
                let _ = input_tx.send(port).await;
            }
        });

        let socket = self.socket.clone();
        let input_rx_stream = tokio_stream::wrappers::ReceiverStream::new(input_rx);
        input_rx_stream
            .for_each_concurrent(concurrency, |port| {
                let output_tx = output_tx.clone();
                let socket = socket.clone();
                async move {
                    let status = scan_port(&socket, target, port, source_ip).await;
                    if status == PortStatus::Open {
                        let _ = output_tx.send(port).await;
                    }
                }
            })
            .await;

        drop(output_tx);
        let output_rx_stream = tokio_stream::wrappers::ReceiverStream::new(output_rx);
        output_rx_stream.collect().await
    }
}

async fn scan_port(socket: &Arc<Mutex<Socket>>, target: IpAddr, port: u16, source_ip: Ipv4Addr) -> PortStatus {
    let source_port: u16 = rand::thread_rng().gen_range(49152..65535);
    let seq_num: u32 = rand::thread_rng().gen();

    for _ in 0..MAX_RETRIES {
        let packet = create_syn_packet(source_ip, target.to_string().parse().unwrap(), source_port, port, seq_num);
        let status = {
            let socket = socket.lock().await;
            match socket.send_to(&packet, &socket2::SockAddr::from(SocketAddr::new(target, port))) {
                Ok(_) => {
                    println!("Sent SYN packet to port {} from source port {}", port, source_port);
                    listen_for_response(&socket, target, port, source_port, seq_num).await
                },
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        sleep(PACKET_DELAY).await;
                        continue;
                    } else {
                        eprintln!("Failed to send packet to port {}: {}", port, e);
                        PortStatus::Filtered
                    }
                }
            }
        };

        if status != PortStatus::Filtered {
            return status;
        }

        sleep(PACKET_DELAY).await;
    }

    PortStatus::Filtered
}

fn create_syn_packet(source_ip: Ipv4Addr, dest_ip: Ipv4Addr, source_port: u16, dest_port: u16, seq_num: u32) -> Vec<u8> {
    let mut packet = vec![0u8; TCP_HEADER_SIZE];
    let mut tcp_packet = MutableTcpPacket::new(&mut packet).unwrap();

    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(dest_port);
    tcp_packet.set_sequence(seq_num);
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5);  // 5 32-bit words
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(65535);
    tcp_packet.set_urgent_ptr(0);

    let checksum = pnet::packet::tcp::ipv4_checksum(
        &tcp_packet.to_immutable(),
        &source_ip,
        &dest_ip
    );
    tcp_packet.set_checksum(checksum);

    packet
}

async fn listen_for_response(socket: &Socket, target: IpAddr, dest_port: u16, source_port: u16, seq_num: u32) -> PortStatus {
    let mut buf = [MaybeUninit::uninit(); 1500];
    
    match timeout(RESPONSE_TIMEOUT, async {
        loop {
            match socket.recv_from(&mut buf) {
                Ok((size, addr)) => {
                    let received_data = unsafe {
                        std::slice::from_raw_parts(buf.as_ptr() as *const u8, size)
                    };
                    
                    if let Some(ip_packet) = Ipv4Packet::new(received_data) {
                        if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            let tcp_payload = ip_packet.payload();
                            if let Some(tcp_packet) = TcpPacket::new(tcp_payload) {
                                let packet_source_port = tcp_packet.get_source();
                                let packet_dest_port = tcp_packet.get_destination();
                                let flags = tcp_packet.get_flags();

                                println!("Received packet: {}:{} -> {}:{} [Flags: {:?}]", 
                                         ip_packet.get_source(), packet_source_port,
                                         ip_packet.get_destination(), packet_dest_port, flags);

                                if ip_packet.get_source() == target.to_string().parse::<Ipv4Addr>().unwrap()
                                    && packet_source_port == dest_port
                                    && packet_dest_port == source_port {
                                    
                                    if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                                        println!("Port {} is open", dest_port);
                                        return PortStatus::Open;
                                    } else if flags & TcpFlags::RST != 0 {
                                        println!("Port {} is closed", dest_port);
                                        return PortStatus::Closed;
                                    } else {
                                        println!("Unexpected flags for port {}: {:?}", dest_port, flags);
                                    }
                                }
                            }
                        }
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    sleep(Duration::from_millis(10)).await;
                },
                Err(e) => {
                    println!("Error receiving: {:?}", e);
                    return PortStatus::Filtered;
                },
            }
        }
    }).await {
        Ok(status) => status,
        Err(_) => {
            println!("Timeout waiting for response for port {}", dest_port);
            PortStatus::Filtered
        },
    }
}


fn get_local_ipv4(target: IpAddr) -> Option<Ipv4Addr> {
    let interfaces = datalink::interfaces();

    for interface in interfaces.iter() {
        if !interface.is_up() || interface.is_loopback() || interface.ips.is_empty() {
            continue;
        }

        for ip in &interface.ips {
            if let IpAddr::V4(ipv4) = ip.ip() {
                if is_route_to_target(ipv4, target) {
                    return Some(ipv4);
                }
            }
        }
    }

    None
}

fn is_route_to_target(source: Ipv4Addr, target: IpAddr) -> bool {
    use std::process::Command;

    let output = Command::new("ip")
        .args(&["route", "get", &target.to_string()])
        .output()
        .expect("Failed to execute ip route command");

    let output = String::from_utf8_lossy(&output.stdout);
    output.contains(&source.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let target: IpAddr = args.target.parse()?;
    
    let source_ip = get_local_ipv4(target).ok_or("Failed to get local IPv4 address")?;

    println!("[+] SYN Scan Starting from {} [+]", source_ip);

    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;

    let scanner = Scanner {
        socket: Arc::new(Mutex::new(socket)),
    };

    let open_ports = scanner.syn_scan(target, args.start_port, args.end_port, source_ip, args.concurrency).await;

    println!("\n[+] Scan Results [+]");
    if open_ports.is_empty() {
        println!("No open ports found for {}", target);
    } else {
        println!("Open ports for {}: {:?}", target, open_ports);
    }

    Ok(())
}