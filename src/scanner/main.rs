use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::transport::{transport_channel, TransportChannelType::Layer3};
use std::net::Ipv4Addr;

// Nível mais alto: Forjando pacotes no Layer 3
fn send_syn_packet(target_ip: Ipv4Addr, port: u16) {
    let protocol = pnet::packet::ip::IpNextHeaderProtocols::Tcp;
    let (mut tx, _) = transport_channel(4096, Layer3(protocol)).unwrap();

    let mut ipv4_raw = [0u8; 40]; // IPv4 + TCP Header
    let mut ip_packet = MutableIpv4Packet::new(&mut ipv4_raw).unwrap();
    
    // Configurações avançadas de IP (High-level)
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(40);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(protocol);
    ip_packet.set_destination(target_ip);

    let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
    tcp_packet.set_destination(port);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    tcp_packet.set_sequence(rand::random());

    // Envio direto para o driver da placa de rede
    tx.send_to(ip_packet, target_ip.into()).unwrap();
}