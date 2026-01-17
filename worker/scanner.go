package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"os"
)

func main() {
	targetIP := "8.8.8.8" // Exemplo
	targetPort := 443
	srcIP := "Seu_IP_Local"

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Construção do pacote SYN (Stateless)
	packet := buildSynPacket(srcIP, targetIP, targetPort)

	// Envio em alta velocidade
	_, err = conn.WriteTo(packet, &net.IPAddr{IP: net.ParseIP(targetIP)})
	if err != nil {
		fmt.Printf("Erro ao enviar: %v\n", err)
	} else {
		fmt.Println("Pacote SYN enviado com sucesso!")
	}
}

func buildSynPacket(src, dst string, port int) []byte {
	ip := &layers.IPv4{
		SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst),
		Protocol: layers.IPProtocolTCP, Version: 4, TTL: 64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(54321), DstPort: layers.TCPPort(port),
		SYN: true, Seq: 12345, Window: 64240,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	gopacket.SerializeLayers(buf, opts, ip, tcp)
	return buf.Bytes()
}