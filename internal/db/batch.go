package db

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

type ScanResult struct {
	IP              string
	Port            int
	Status          string
	Service         string
	Banner          string
	TLSDomain       string
	TLSIssuer       string
	// --- Campos de Vulnerabilidade ---
	CPE             string   // Ex: cpe:2.3:a:apache:http_server:2.4.41
	Vulnerabilities []string // Lista de CVEs detectadas
	JARM            string   // Fingerprint TLS
	HTMLTitle       string   // Título da página
	HeadersHash     string   // Hash dos headers
	// --- Contexto ---
	Country         string
	ASN             uint32
	ASNOrg          string
	DeviceType      string // Ex: "Firewall", "Router", "SCADA"
}

type Batcher struct {
	conn      clickhouse.Conn
	buffer    []ScanResult
	mu        sync.Mutex
	flushChan chan struct{}
}

func NewBatcher(conn clickhouse.Conn) *Batcher {
	b := &Batcher{
		conn:      conn,
		buffer:    make([]ScanResult, 0, 2000),
		flushChan: make(chan struct{}, 1),
	}
	go b.autoFlush()
	return b
}

func (b *Batcher) Add(res ScanResult) {
	b.mu.Lock()
	b.buffer = append(b.buffer, res)
	shouldFlush := len(b.buffer) >= 1000
	b.mu.Unlock()

	if shouldFlush {
		select {
		case b.flushChan <- struct{}{}:
			go b.Flush()
		default:
			// Já existe um flush em andamento, não bloqueia
		}
	}
}

func (b *Batcher) Flush() {
	defer func() { <-b.flushChan }()

	b.mu.Lock()
	if len(b.buffer) == 0 {
		b.mu.Unlock()
		return
	}
	tempBuffer := b.buffer
	b.buffer = make([]ScanResult, 0, 2000)
	b.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Prepare batch with all fields
	batch, err := b.conn.PrepareBatch(ctx, "INSERT INTO results (ip, port, status, service, banner, tls_domain, tls_issuer, cpe, jarm, html_title, headers_hash, country, asn, asn_org, device_type, timestamp)")
	if err != nil {
		fmt.Printf("❌ Erro ao preparar batch: %v\n", err)
		return
	}

	now := time.Now()
	for _, r := range tempBuffer {
		_ = batch.Append(r.IP, uint16(r.Port), r.Status, r.Service, r.Banner, r.TLSDomain, r.TLSIssuer, r.CPE, r.JARM, r.HTMLTitle, r.HeadersHash, r.Country, r.ASN, r.ASNOrg, r.DeviceType, now)
	}

	if err := batch.Send(); err != nil {
		fmt.Printf("❌ Erro ao enviar batch (%d registros): %v\n", len(tempBuffer), err)
	} else {
		fmt.Printf("📦 [DB] %d registros persistidos com sucesso.\n", len(tempBuffer))
	}
}

func (b *Batcher) autoFlush() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		select {
		case b.flushChan <- struct{}{}:
			go b.Flush()
		default:
		}
	}
}