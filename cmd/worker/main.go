package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"scan/internal/db"
	"scan/internal/kafka"
	kgo "github.com/segmentio/kafka-go"
)

var targetPorts = []int{22, 80, 443, 3389, 8080}

func main() {
	conn, err := db.Connect()
	if err != nil {
		fmt.Printf("❌ Erro ao conectar no ClickHouse: %v\n", err)
		return
	}

	// 1. Inicializa o Batcher (Pulmão do Banco)
	batcher := db.NewBatcher(conn)

	reader := kafka.NewReader("scan_tasks", "worker-group")

	enricherWriter := &kgo.Writer{
		Addr:     kgo.TCP("localhost:9092"),
		Topic:    "raw-hits",
		Balancer: &kgo.LeastBytes{},
	}
	defer enricherWriter.Close()

	// 2. SEMÁFORO: Limita a 5.000 conexões simultâneas para não derrubar a VPS
	sem := make(chan struct{}, 5000)

	fmt.Println("👷 Worker de Elite Iniciado (Multi-Port + Batching)...")

	for {
		m, err := reader.ReadMessage(context.Background())
		if err != nil {
			fmt.Printf("❌ Erro Kafka: %v\n", err)
			continue // Não sai do loop, tenta ler o próximo
		}
		
		targetIP := string(m.Value)

		// Criamos uma goroutine para o IP, e dentro dela gerenciamos as portas
		go func(ip string) {
			for _, port := range targetPorts {
				sem <- struct{}{} // Espera vaga sem travar o loop do Kafka
				
				go func(p int) {
					defer func() { <-sem }() 

					address := fmt.Sprintf("%s:%d", ip, p)
					
					// Dialer com controle total
					dialer := net.Dialer{Timeout: 1 * time.Second}
					connTCP, err := dialer.Dial("tcp", address)
					
					if err == nil {
						connTCP.Close()
						fmt.Printf("🔥 HIT: %s:%d\n", ip, p)

						_ = enricherWriter.WriteMessages(context.Background(),
							kgo.Message{Value: []byte(address)},
						)

						batcher.Add(db.ScanResult{
							IP:     ip,
							Port:   p,
							Status: "open",
						})
					}
				}(port)
			}
		}(targetIP)
	}
}