use std::net::{IpAddr};
use std::sync::Arc;
use std::fs::File;
use std::io::{BufRead, BufReader, Write, Read};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol, TransportSender, TransportReceiver};
use clap::Parser;
use rand::Rng;
use rand::rngs::StdRng;
use rand::SeedableRng;
use chrono::Local;
use pnet::packet::Packet;
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let target: IpAddr = args.target.parse()?;
    println!("[+] Syn Scan Starting [+]");
    
    let (tx, _) = transport_channel(
        4096,
        TransportChannelType::Layer4(
            TransportProtocol::Ipv4(
                IpNextHeaderProtocols::Tcp
            )
        )
    )?;
    let tx = Arc::new(Mutex::new(tx));
    let semaphore = Arc::new(Semaphore::new(args.concurrent));
    let mut handles = vec![];

    let report = Arc::new(Mutex::new(Vec::new()));

    if let Some(wordlist_path) = args.wordlist {
        let file = File::open(wordlist_path)?;
        let reader = BufReader::new(file);
        
        for line in reader.lines() {
            let word = line?;
            let permit = semaphore.clone().acquire_owned().await?;
            let target = target;
            let tx = tx.clone();
            let report = report.clone();
            
            let handle = tokio::spawn(async move {
                let mut rng = StdRng::from_entropy();
                let result = syn_scan(&tx, target, args.start_port, args.end_port, &mut rng, &word).await;
                drop(permit);
                let mut report = report.lock().await;
                report.push(result);
            });
            
            handles.push(handle);
        }
    } else {
        for port in args.start_port..=args.end_port {
            let permit = semaphore.clone().acquire_owned().await?;
            let target = target;
            let tx = tx.clone();
            let report = report.clone();
            
            let handle = tokio::spawn(async move {
                let mut rng = StdRng::from_entropy();
                let result = syn_scan(&tx, target, port, port, &mut rng, "").await;
                drop(permit);
                let mut report = report.lock().await;
                report.push(result);
            });
            
            handles.push(handle);
        }
    }

    for handle in handles {
        if let Err(e) = handle.await {
            eprintln!("A task failed: {}", e);
        }
    }

    // Generate report
    let report = report.lock().await;
    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let filename = format!("/tmp/syn_scan_report_{}.txt", timestamp);
    let mut file = File::create(&filename)?;

    println!("\n[+] Scan Results [+]");
    for result in report.iter() {
        let line = format!("{}\n", result);
        print!("{}", line);
        file.write_all(line.as_bytes())?;
    }

    println!("\nReport saved to: {}", filename);

    Ok(())
}

async fn syn_scan(tx: &Arc<Mutex<TransportSender>>, target: IpAddr, start_port: u16, end_port: u16, rng: &mut StdRng, word: &str) -> String {
    let mut open_ports = Vec::new();

    for port in start_port..=end_port {
        let seq_num: u32 = rng.gen();
        let mut packet = [0u8; 66];
        let mut tcp_packet = MutableTcpPacket::new(&mut packet[..]).unwrap();
        
        tcp_packet.set_source(rng.gen_range(49152..65535));
        tcp_packet.set_destination(port);
        tcp_packet.set_sequence(seq_num);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(64240);
        tcp_packet.set_data_offset(8);
        
        let packet_data = tcp_packet.packet().to_vec();
        
        let mut retry_count = 0;
        let max_retries = 3;
        loop {
            let mut tx = tx.lock().await;
            match target {
                IpAddr::V4(ipv4) => {
                    let send_result = tx.send_to(MutableTcpPacket::new(&mut packet_data.clone()[..]).unwrap(), IpAddr::V4(ipv4));
                    match send_result {
                        Ok(_) => {
                            drop(tx);
                            // Wait for response
                            if let Ok(is_open) = timeout(Duration::from_millis(1000), listen_for_response(target, port, seq_num)).await {
                                if is_open {
                                    open_ports.push(port);
                                }
                            }
                            break;
                        },
                        Err(e) => {
                            if retry_count >= max_retries {
                                return format!("Error scanning port {} after {} retries: {}", port, max_retries, e);
                            }
                            retry_count += 1;
                            drop(tx);
                            sleep(Duration::from_millis(100)).await;
                        }
                    }
                },
                IpAddr::V6(_) => return "IPV6 not supported yet".to_string(),
            }
        }
        
        sleep(Duration::from_millis(10)).await; // Rate limiting
    }

    if open_ports.is_empty() {
        format!("No open ports found for {} (Word: {})", target, word)
    } else {
        format!("Open ports for {} (Word: {}): {:?}", target, word, open_ports)
    }
}



async fn listen_for_response(target: IpAddr, port: u16, sent_seq: u32) -> bool {
    let (_, mut rx): (_, TransportReceiver) = match transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp))
    ) {
        Ok(channel) => channel,
        Err(e) => {
            eprintln!("Error creating transport channel: {}", e);
            return false;
        }
    };

    match timeout(Duration::from_secs(1), async {
        loop {
            let buffer = rx.buffer.clone(); // Clone the buffer
            if let Some(tcp_packet) = TcpPacket::new(&buffer) {
                if tcp_packet.get_destination() == port &&
                   tcp_packet.get_flags() == TcpFlags::SYN | TcpFlags::ACK &&
                   tcp_packet.get_acknowledgement() == sent_seq + 1 {
                    return true;
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