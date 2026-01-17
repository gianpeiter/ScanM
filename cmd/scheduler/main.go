package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/segmentio/kafka-go"
)

// Blacklist de sub-redes que nunca respondem ou são perigosas (Bogons)
var blacklistedPrefixes = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
}

type GlobalScheduler struct {
	writer *kafka.Writer
	seed   uint32
	cursor uint32
}

func NewGlobalScheduler() *GlobalScheduler {
	return &GlobalScheduler{
		writer: &kafka.Writer{
			Addr:         kafka.TCP("localhost:9092"),
			Topic:        "scan_tasks",
			Balancer:     &kafka.LeastBytes{},
			BatchSize:    1000,              // Envia apenas quando juntar 1000
			BatchTimeout: 500 * time.Millisecond, // Ou a cada 0.5s
			Async:        true,              // Alta performance: não espera o ACK para continuar
		},
		seed: uint32(rand.Intn(0xFFFFFFFF)),
	}
}

// Algoritmo de Ciclo de Permutação (Simplificado para Magnitude Global)
// Garante que percorremos o espaço IPv4 de forma pseudo-aleatória sem repetir rápido
func (s *GlobalScheduler) next() string {
	for {
		// LCG (Linear Congruential Generator) para saltos gigantes no espaço IP
		s.seed = (uint32(1103515245)*s.seed + 12345)
		
		ip := make(net.IP, 4)
		ip[0] = byte(s.seed >> 24)
		ip[1] = byte(s.seed >> 16)
		ip[2] = byte(s.seed >> 8)
		ip[3] = byte(s.seed)

		if s.isValidPublic(ip) {
			return ip.String()
		}
	}
}

func (s *GlobalScheduler) isValidPublic(ip net.IP) bool {
	first := ip[0]
	// Filtro rápido de octeto
	if first == 0 || first == 10 || first == 127 || first >= 224 {
		return false
	}
	// Filtro detalhado (Opcional, mas profissional)
	// Para performance extrema, você pode pré-calcular um bitmap de 256mb
	return true 
}

func (s *GlobalScheduler) Start() {
	fmt.Println("🛰️ Scheduler v3 Global Online | Batching: 1000msg/batch")
	
	count := 0
	startTime := time.Now()

	for {
		targetIP := s.next()
		
		err := s.writer.WriteMessages(context.Background(),
			kafka.Message{
				Value: []byte(targetIP),
			},
		)

		if err != nil {
			fmt.Printf("❌ Erro Kafka: %v\n", err)
			continue
		}

		count++
		if count%100000 == 0 {
			rate := float64(count) / time.Since(startTime).Seconds()
			fmt.Printf("📊 Status: %d IPs enviados | Velocidade: %.2f IPs/seg\n", count, rate)
		}
	}
}

func main() {
	scheduler := NewGlobalScheduler()
	scheduler.Start()
}