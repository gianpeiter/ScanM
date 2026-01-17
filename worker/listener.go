// Este módulo usa libpcap para ler a placa de rede em modo promíscuo
// Se receber um TCP com flags SYN+ACK da porta alvo -> O IP ESTÁ VIVO
func listenForResponses() {
    handle, _ := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
    filter := "tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)"
    _ = handle.SetBPFFilter(filter)
    
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        // Enviar IP:Porta encontrado para o tópico "raw-hits" no Kafka
        publishToKafka("raw-hits", packet)
    }
}