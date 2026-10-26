//! Active-mode RPCAP receiver: rpcapd connects to our control listener, then
//! opens a separate TCP data connection back to us.

use std::io;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::time::Duration;

use ot_pcap_processor::Analyzer;
use pcap_file::DataLink;
use rpcap_rs::Capture;
use rpcap_rs::codec::RpcapFrame;
use rpcap_rs::protocol::capture::flags;
use rpcap_rs::protocol::header::{MessageDirection, MessageKind, RpcapHeader};
use rpcap_rs::protocol::{
    AuthReply, AuthRequest, BpfInstruction, BpfProgram, OpenReply, RpcapMessage, StartCaptureReply,
    StartCaptureRequest,
};
use rpcap_rs::transport::RpcapTransport;
use rpcap_rs::transport::tcp::TcpTransport;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{interval, timeout};

use crate::{export_otlp, export_pending_logs};

pub struct RemoteConfig {
    pub listen: SocketAddr,
    pub data_port: u16,
    pub interface: String,
    pub allowed_peer: Option<IpAddr>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub bacnet_ports: Vec<u16>,
    pub modbus_ports: Vec<u16>,
    pub otlp_endpoint: String,
    pub export_interval: Duration,
}

pub async fn run(config: RemoteConfig) -> io::Result<()> {
    if config.data_port == 0 || config.data_port == config.listen.port() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "RPCAP data port must be nonzero and differ from the control port",
        ));
    }
    if !config.listen.ip().is_loopback() && config.allowed_peer.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--rpcap-allow-peer is required for a non-loopback listener",
        ));
    }
    let listener = TcpListener::bind(config.listen).await?;
    let mut analyzer =
        Analyzer::with_ports(config.bacnet_ports.clone(), config.modbus_ports.clone());
    eprintln!("Waiting for rpcapd on {}", listener.local_addr()?);
    loop {
        let (stream, peer) = listener.accept().await?;
        if config
            .allowed_peer
            .is_some_and(|allowed| allowed != peer.ip())
        {
            eprintln!("Rejected RPCAP connection from {peer}");
            continue;
        }
        eprintln!("RPCAP control connection from {peer}");
        if let Err(error) = handle_session(stream, peer.ip(), &config, &mut analyzer).await {
            eprintln!("RPCAP session from {peer} ended: {error}");
        }
    }
}

async fn handle_session(
    stream: TcpStream,
    peer_ip: IpAddr,
    config: &RemoteConfig,
    analyzer: &mut Analyzer,
) -> io::Result<()> {
    let bind_ip = stream.local_addr()?.ip();
    let data_listener = TcpListener::bind(SocketAddr::new(bind_ip, config.data_port)).await?;
    stream.set_nodelay(true)?;
    let mut control = TcpTransport::new(stream);
    let auth = match (&config.username, &config.password) {
        (Some(user), Some(password)) => AuthRequest::password(user, password),
        (None, None) => AuthRequest::null(),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "set both --rpcap-user and RPCAP_PASSWORD, or neither",
            ));
        }
    };
    let auth_reply = roundtrip(&mut control, MessageKind::Auth, auth.encode()).await?;
    let version = AuthReply::decode(&auth_reply.payload).map_err(io::Error::other)?;
    if version.min_version > 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rpcapd requires an unsupported protocol version",
        ));
    }

    let open_reply = roundtrip(
        &mut control,
        MessageKind::Open,
        config.interface.as_bytes().to_vec(),
    )
    .await?;
    let open = OpenReply::decode(&open_reply.payload).map_err(io::Error::other)?;
    let raw_link = u32::try_from(open.linktype)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative RPCAP link type"))?;
    let link = if rpcap_rs::link::LinkType(raw_link).is_raw_ip() {
        DataLink::RAW
    } else {
        DataLink::from(raw_link)
    };
    if !matches!(
        link,
        DataLink::ETHERNET
            | DataLink::RAW
            | DataLink::IPV4
            | DataLink::IPV6
            | DataLink::LINUX_SLL
            | DataLink::LINUX_SLL2
            | DataLink::NULL
            | DataLink::LOOP
    ) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported RPCAP link type {raw_link}"),
        ));
    }
    eprintln!("RPCAP opened {} (link type {:?})", config.interface, link);

    let request = StartCaptureRequest {
        snaplen: 65_535,
        read_timeout: 1_000,
        flags: flags::SERVEROPEN,
        portdata: config.data_port,
        filter: compile_filter(link, &config.bacnet_ports, &config.modbus_ports).unwrap_or_else(|error| {
            eprintln!("RPCAP remote filter unavailable ({error}); rpcapd will send all frames and the processor will filter locally");
            BpfProgram::accept_all()
        }),
    };
    let reply = roundtrip(&mut control, MessageKind::StartCapture, request.encode()).await?;
    StartCaptureReply::decode(&reply.payload).map_err(io::Error::other)?;
    let data_stream = timeout(Duration::from_secs(15), async {
        loop {
            let (stream, peer) = data_listener.accept().await?;
            if peer.ip() == peer_ip {
                return Ok::<_, io::Error>(stream);
            }
            eprintln!("Rejected RPCAP data connection from {peer}");
        }
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "rpcapd did not open the data connection",
        )
    })??;
    data_stream.set_nodelay(true)?;
    eprintln!("RPCAP data connection established for {}", config.interface);

    let mut capture = Capture::new(TcpTransport::new(data_stream));
    let mut ticker = interval(config.export_interval);
    ticker.tick().await;
    loop {
        tokio::select! {
            result = capture.next_packet() => {
                match result.map_err(io::Error::other)? {
                    Some(packet) => {
                        analyzer.ingest_frame_at(link, &packet.data, packet.timestamp.as_duration());
                        if let Err(error) = export_pending_logs(&config.otlp_endpoint, analyzer) {
                            eprintln!("OTLP log export failed: {error}");
                        }
                    },
                    None => break,
                }
            }
            _ = ticker.tick() => {
                if let Err(error) = export_otlp(&config.otlp_endpoint, analyzer) {
                    eprintln!("OTLP export failed: {error}");
                }
            }
        }
    }
    if let Err(error) = export_otlp(&config.otlp_endpoint, analyzer) {
        eprintln!("Final OTLP export failed: {error}");
    }
    if let Err(error) = export_pending_logs(&config.otlp_endpoint, analyzer) {
        eprintln!("Final OTLP log export failed: {error}");
    }
    let _ = roundtrip(&mut control, MessageKind::EndCapture, Vec::new()).await;
    let close = RpcapFrame {
        header: RpcapHeader::new(MessageKind::Close, MessageDirection::Request, 0, 0),
        payload: Vec::new(),
    };
    let _ = control.send_frame(&close).await;
    Ok(())
}

fn compile_filter(
    link: DataLink,
    bacnet_ports: &[u16],
    modbus_ports: &[u16],
) -> io::Result<BpfProgram> {
    let expression = bacnet_ports
        .iter()
        .map(|port| format!("udp port {port}"))
        .chain(modbus_ports.iter().map(|port| format!("tcp port {port}")))
        .collect::<Vec<_>>()
        .join(" or ");
    if expression.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no protocol ports configured",
        ));
    }
    let mut empty_pcap = tempfile::NamedTempFile::new()?;
    let mut header = [0u8; 24];
    header[..4].copy_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    header[4..6].copy_from_slice(&2u16.to_le_bytes());
    header[6..8].copy_from_slice(&4u16.to_le_bytes());
    header[16..20].copy_from_slice(&65_535u32.to_le_bytes());
    header[20..24].copy_from_slice(&u32::from(link).to_le_bytes());
    empty_pcap.write_all(&header)?;
    empty_pcap.flush()?;
    let output = Command::new("tcpdump")
        .arg("-ddd")
        .arg("-r")
        .arg(empty_pcap.path())
        .arg(&expression)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    let text = std::str::from_utf8(&output.stdout).map_err(io::Error::other)?;
    let mut lines = text.lines();
    let count: usize = lines
        .next()
        .ok_or_else(|| io::Error::other("tcpdump emitted no BPF program"))?
        .parse()
        .map_err(io::Error::other)?;
    let mut instructions = Vec::with_capacity(count);
    for line in lines {
        let values = line
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(io::Error::other)?;
        if values.len() != 4 {
            return Err(io::Error::other("invalid BPF instruction from tcpdump"));
        }
        instructions.push(BpfInstruction {
            code: values[0].try_into().map_err(io::Error::other)?,
            jt: values[1].try_into().map_err(io::Error::other)?,
            jf: values[2].try_into().map_err(io::Error::other)?,
            k: values[3],
        });
    }
    if instructions.len() != count || count == 0 {
        return Err(io::Error::other("incomplete BPF program from tcpdump"));
    }
    Ok(BpfProgram { instructions })
}

async fn roundtrip(
    control: &mut TcpTransport,
    kind: MessageKind,
    payload: Vec<u8>,
) -> io::Result<RpcapFrame> {
    let frame = RpcapFrame {
        header: RpcapHeader::new(kind, MessageDirection::Request, 0, payload.len() as u32),
        payload,
    };
    timeout(Duration::from_secs(15), async {
        control.send_frame(&frame).await?;
        control.recv_frame().await
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("RPCAP {kind:?} request timed out"),
        )
    })?
    .and_then(|reply| {
        let info = reply.header.info();
        if reply.header.version != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported RPCAP version",
            ));
        }
        if info.kind == MessageKind::Error {
            let message =
                RpcapMessage::decode(&reply.header, &reply.payload).map_err(io::Error::other)?;
            return Err(io::Error::other(format!(
                "rpcapd error {}: {message:?}",
                reply.header.value
            )));
        }
        if info.kind != kind || info.direction != MessageDirection::Reply {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected RPCAP reply: {info:?}"),
            ));
        }
        Ok(reply)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener as StdTcpListener;

    async fn reply(control: &mut TcpTransport, kind: MessageKind, payload: Vec<u8>) {
        control
            .send_frame(&RpcapFrame {
                header: RpcapHeader::new(kind, MessageDirection::Reply, 0, payload.len() as u32),
                payload,
            })
            .await
            .unwrap();
    }

    fn whois_ethernet_frame() -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 20 + 8];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&36u16.to_be_bytes());
        frame[22] = 64;
        frame[23] = 17;
        frame[26..30].copy_from_slice(&[10, 0, 0, 1]);
        frame[30..34].copy_from_slice(&[10, 0, 0, 255]);
        frame[34..36].copy_from_slice(&47808u16.to_be_bytes());
        frame[36..38].copy_from_slice(&47808u16.to_be_bytes());
        frame[38..40].copy_from_slice(&16u16.to_be_bytes());
        frame.extend_from_slice(&[0x81, 0x0b, 0, 8, 1, 0, 0x10, 8]);
        frame
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn active_rpcap_session_decodes_and_exports() {
        let http = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let http_addr = http.local_addr().unwrap();
        let http_thread = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = http.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 4096];
                loop {
                    let n = stream.read(&mut buffer).unwrap();
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..n]);
                    if let Some(split) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..split]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .and_then(|n| n.parse::<usize>().ok())
                            })
                            .unwrap();
                        if request.len() >= split + 4 + length {
                            break;
                        }
                    }
                }
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                    .unwrap();
                requests.push(String::from_utf8_lossy(&request).into_owned());
            }
            requests
        });
        let control_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        let data_port = {
            let socket = StdTcpListener::bind("127.0.0.1:0").unwrap();
            socket.local_addr().unwrap().port()
        };
        let config = RemoteConfig {
            listen: control_addr,
            data_port,
            interface: "test0".into(),
            allowed_peer: None,
            username: None,
            password: None,
            bacnet_ports: vec![47808],
            modbus_ports: vec![502],
            otlp_endpoint: format!("http://{http_addr}"),
            export_interval: Duration::from_secs(30),
        };
        let simulated_daemon = tokio::spawn(async move {
            let stream = TcpStream::connect(control_addr).await.unwrap();
            let mut control = TcpTransport::new(stream);
            let auth = control.recv_frame().await.unwrap();
            assert_eq!(auth.header.info().kind, MessageKind::Auth);
            reply(&mut control, MessageKind::Auth, vec![]).await;
            let open = control.recv_frame().await.unwrap();
            assert_eq!(open.payload, b"test0");
            reply(
                &mut control,
                MessageKind::Open,
                [1i32.to_be_bytes(), 0i32.to_be_bytes()].concat(),
            )
            .await;
            let start = control.recv_frame().await.unwrap();
            assert_eq!(start.header.info().kind, MessageKind::StartCapture);
            assert_eq!(&start.payload[8..10], &flags::SERVEROPEN.to_be_bytes());
            assert_eq!(&start.payload[10..12], &data_port.to_be_bytes());
            reply(&mut control, MessageKind::StartCapture, vec![0; 8]).await;
            let data = TcpStream::connect(("127.0.0.1", data_port)).await.unwrap();
            let mut data = TcpTransport::new(data);
            let packet = whois_ethernet_frame();
            let mut payload = Vec::new();
            for field in [1u32, 0, packet.len() as u32, packet.len() as u32, 1] {
                payload.extend_from_slice(&field.to_be_bytes());
            }
            payload.extend_from_slice(&packet);
            data.send_frame(&RpcapFrame {
                header: RpcapHeader::new(
                    MessageKind::Packet,
                    MessageDirection::Request,
                    0,
                    payload.len() as u32,
                ),
                payload,
            })
            .await
            .unwrap();
            drop(data);
            let end = control.recv_frame().await.unwrap();
            assert_eq!(end.header.info().kind, MessageKind::EndCapture);
            reply(&mut control, MessageKind::EndCapture, vec![]).await;
            let close = control.recv_frame().await.unwrap();
            assert_eq!(close.header.info().kind, MessageKind::Close);
        });
        let (stream, peer) =
            tokio::time::timeout(Duration::from_secs(5), control_listener.accept())
                .await
                .unwrap()
                .unwrap();
        tokio::time::timeout(
            Duration::from_secs(5),
            handle_session(stream, peer.ip(), &config, &mut Analyzer::default()),
        )
        .await
        .unwrap()
        .unwrap();
        simulated_daemon.await.unwrap();
        let requests = http_thread.join().unwrap();
        assert!(
            requests
                .iter()
                .any(|request| request.contains("POST /v1/metrics")
                    && request.contains("bacnet_whois_requests_total"))
        );
        assert!(
            requests
                .iter()
                .any(|request| request.contains("POST /v1/logs")
                    && request.contains("broadcast@10.0.0.255"))
        );
    }
}
