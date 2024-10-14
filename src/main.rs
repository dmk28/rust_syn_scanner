use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use pnet::packet::Packet;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::transport::{transport_channel, TransportChannelType,  TransportSender, TransportReceiver};
use clap::Parser;
use rand::Rng;
use rand::rngs::StdRng;
use pnet::datalink;
use rand::SeedableRng;

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
    concurrent: usize,
    #[arg(short, long)]
    wordlist: Option<String>,
    #[arg(long)]
    spoof_source: Option<String>,
}

fn get_local_ipv4() -> Option<Ipv4Addr> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
        .and_then(|iface| iface.ips.into_iter().find(|ip| ip.is_ipv4()).map(|ip| ip.ip()))
        .and_then(|ip| match ip {
            IpAddr::V4(ipv4) => Some(ipv4),
            _ => None,
        })
}

async fn syn_scan(
    tx: &Arc<Mutex<TransportSender>>,
    rx: &Arc<Mutex<TransportReceiver>>,
    target: IpAddr,
    source_ip: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    rng: &mut StdRng
) -> Vec<u16> {
    let mut open_ports = Vec::new();
    let mut handles = vec![];

    for port in start_port..=end_port {
        let tx = tx.clone();
        let rx = rx.clone();
        let target = target;
        let source_ip = source_ip;
        let seq_num: u32 = rng.gen();
        let source_port: u16 = rng.gen_range(49152..65535);

        let handle = tokio::spawn(async move {
            let mut ip_packet = [0u8; 66];
            let mut ip_header = MutableIpv4Packet::new(&mut ip_packet[..20]).unwrap();

            ip_header.set_version(4);
            ip_header.set_header_length(5);
            ip_header.set_total_length(66);
            ip_header.set_ttl(64);
            ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip_header.set_source(source_ip);
            ip_header.set_destination(match target {
                IpAddr::V4(ip) => ip,
                _ => return None,
            });
            
            let mut tcp_buffer = [0u8; 46];
            let mut tcp_header = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
            tcp_header.set_source(source_port);
            tcp_header.set_destination(port);
            tcp_header.set_sequence(seq_num);
            tcp_header.set_flags(TcpFlags::SYN);
            tcp_header.set_window(64240);
            tcp_header.set_data_offset(5);
            
            let checksum = pnet::packet::tcp::ipv4_checksum(&tcp_header.to_immutable(), &ip_header.get_source(), &ip_header.get_destination());
            tcp_header.set_checksum(checksum);

            // Copy TCP header into IP packet
            ip_packet[20..].copy_from_slice(tcp_header.packet());

            let mut tx = tx.lock().await;
            match tx.send_to(MutableIpv4Packet::new(&mut ip_packet).unwrap(), target) {
                Ok(_) => {
                    drop(tx);
                    if let Ok(is_open) = timeout(Duration::from_millis(2000), listen_for_response(&rx, target, source_ip, port, seq_num)).await {
                        if is_open {
                            Some(port)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                },
                Err(_) => None,
            }
        });
        handles.push(handle);

        if handles.len() >= 100 {  // Adjust this number for concurrency
            for handle in handles.drain(..) {
                if let Some(Some(port)) = handle.await.ok() {
                    open_ports.push(port);
                }
            }
        }

        sleep(Duration::from_millis(5)).await; // Rate limiting
    }

    for handle in handles {
        if let Some(Some(port)) = handle.await.ok() {
            open_ports.push(port);
        }
    }

    open_ports
}

async fn listen_for_response(
    rx: &Arc<Mutex<TransportReceiver>>,
    target: IpAddr,
    source_ip: Ipv4Addr,
    port: u16,
    sent_seq: u32
) -> bool {
    let rx = rx.lock().await;

    match timeout(Duration::from_secs(1), async {
        loop {
            let buffer = rx.buffer.clone(); // Clone the buffer
            if let Some(ip_packet) = Ipv4Packet::new(&buffer) {
                if ip_packet.get_source() == target.to_string().parse::<Ipv4Addr>().unwrap()
                    && ip_packet.get_destination() == source_ip {
                    if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                        if tcp_packet.get_destination() == port
                            && tcp_packet.get_flags() == TcpFlags::SYN| TcpFlags::ACK  // This is equivalent to 0x012
                            && tcp_packet.get_acknowledgement() == sent_seq + 1 {
                            return true;
                        }
                    }
                }
            }
            // If we haven't found a matching packet, wait a bit before checking again
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await {
        Ok(result) => result,
        Err(_) => false, // Timeout occurred
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let target: IpAddr = args.target.parse()?;
    
    let source_ip = if let Some(spoof_ip) = args.spoof_source {
        spoof_ip.parse::<Ipv4Addr>()?
    } else {
        get_local_ipv4().ok_or("Failed to get local IPv4 address")?
    };
    
    println!("[+] Syn Scan Starting from {} [+]", source_ip);
    
    let (tx, rx) = transport_channel(
        4096,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp)
    )?;
    let tx = Arc::new(Mutex::new(tx));
    let rx = Arc::new(Mutex::new(rx));
    let mut rng = StdRng::from_entropy();

    let open_ports = syn_scan(&tx, &rx, target, source_ip, args.start_port, args.end_port, &mut rng).await;

    println!("\n[+] Scan Results [+]");
    if open_ports.is_empty() {
        println!("No open ports found for {}", target);
    } else {
        println!("Open ports for {}: {:?}", target, open_ports);
    }

    Ok(())
}