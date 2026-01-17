package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"scan/internal/db"
	"github.com/segmentio/kafka-go"
	"github.com/oschwald/geoip2-golang"
)

const geoIPPath = "/var/lib/GeoIP/"

// Estrutura para armazenar achados de segurança
type SecurityFindings struct {
	InternalIPs      []string            `json:"internal_ips"`
	SecurityHeaders  map[string]string   `json:"security_headers"`
	DiscoveredPaths  []string            `json:"discovered_paths"`
	OtherTags        map[string]string   `json:"other_tags"` // Para cookies, frameworks, etc.
}

// Limitador de concorrência: Não queremos abrir 1 milhão de conexões TCP locais
var sem = make(chan struct{}, 5000)

var geoCityDB *geoip2.Reader
var geoAsnDB *geoip2.Reader
var geoCountryDB *geoip2.Reader

func initGeoIP() {
	var err error
	// Tenta carregar City
	geoCityDB, err = geoip2.Open(geoIPPath + "GeoLite2-City.mmdb")
	if err != nil {
		fmt.Println("⚠️  Aviso: Base GeoIP City não encontrada. Continuando sem geolocalização.")
	} else {
		fmt.Println("🌍 Base GeoIP City carregada com sucesso.")
	}

	// Tenta carregar ASN
	geoAsnDB, err = geoip2.Open(geoIPPath + "GeoLite2-ASN.mmdb")
	if err != nil {
		fmt.Println("⚠️  Aviso: Base GeoIP ASN não encontrada. Continuando sem dados de provedor.")
	} else {
		fmt.Println("📡 Base GeoIP ASN carregada com sucesso.")
	}

	// Tenta carregar Country
	geoCountryDB, err = geoip2.Open(geoIPPath + "GeoLite2-Country.mmdb")
	if err != nil {
		fmt.Println("⚠️  Aviso: Base GeoIP Country não encontrada. Continuando sem dados de país.")
	} else {
		fmt.Println("🇺🇳 Base GeoIP Country carregada com sucesso.")
	}
}

// Função para analisar banner HTTP e headers
func analyzeHTTPData(banner string, headers map[string]string, ip string, alpnProtocol string) SecurityFindings {
	findings := SecurityFindings{
		SecurityHeaders: make(map[string]string),
		OtherTags:       make(map[string]string),
	}

	// 1. Vazamento de IPs Internos (em headers ou banner)
	ipRegex := regexp.MustCompile(`\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b`)
	matches := ipRegex.FindAllString(banner, -1)
	for _, header := range headers {
		matches = append(matches, ipRegex.FindAllString(header, -1)...)
	}
	findings.InternalIPs = matches

	// 2. Análise de Cookies (flags HttpOnly/Secure)
	if cookie, ok := headers["Set-Cookie"]; ok {
		if !strings.Contains(cookie, "HttpOnly") {
			findings.OtherTags["cookie_insecure"] = "Missing HttpOnly"
		}
		if !strings.Contains(cookie, "Secure") {
			findings.OtherTags["cookie_insecure"] += "; Missing Secure"
		}
	}

	// 3. Descoberta de Framework (headers como X-Powered-By)
	if framework, ok := headers["X-Powered-By"]; ok {
		findings.OtherTags["web_framework"] = framework
	}
	if generator, ok := headers["X-Generator"]; ok {
		findings.OtherTags["web_framework"] = generator
	}

	// 4. Headers de Segurança Ausentes
	requiredHeaders := []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options"}
	for _, h := range requiredHeaders {
		if _, ok := headers[h]; !ok {
			findings.SecurityHeaders[h] = "Missing"
		} else {
			findings.SecurityHeaders[h] = "Present"
		}
	}

	// 5. CORS Misconfiguration
	if cors, ok := headers["Access-Control-Allow-Origin"]; ok && cors == "*" {
		findings.OtherTags["cors_misconfig"] = "Wildcard origin"
	}

	// 6. Exposições em Aplicações (Sensitive Paths - request leve se banner indicar HTTP)
	if strings.Contains(banner, "HTTP") {
		sensitivePaths := []string{"/.git/config", "/env", "/.vscode/", "/phpinfo.php"}
		for _, path := range sensitivePaths {
			url := "http://" + ip + path
			resp, err := http.Get(url)
			if err == nil && resp.StatusCode == 200 {
				findings.DiscoveredPaths = append(findings.DiscoveredPaths, path)
			}
		}
	}

	// 7. Dev/Staging Environments (no título ou banner)
	if strings.Contains(strings.ToLower(banner), "test") || strings.Contains(strings.ToLower(banner), "staging") {
		findings.OtherTags["dev_env"] = "Detected"
	}

	// 8. ALPN Protocols
	if alpnProtocol != "" {
		findings.OtherTags["alpn_protocol"] = alpnProtocol
	}

	return findings
}

func main() {
	initGeoIP()

	conn, err := db.Connect()
	if err != nil {
		panic(fmt.Sprintf("❌ Erro ao conectar no DB: %v", err))
	}
	batcher := db.NewBatcher(conn)

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "raw-hits",
		GroupID: "enricher-group",
		// Ajustes para performance global
		MinBytes: 10e3, // 10KB
		MaxBytes: 10e6, // 10MB
	})

	fmt.Println("🚀 Enricher v3 Global: TCP Probing + TLS Intelligence")

	for {
		m, err := reader.ReadMessage(context.Background())
		if err != nil {
			fmt.Printf("❌ Erro no Kafka: %v\n", err)
			continue
		}

		target := string(m.Value)
		sem <- struct{}{} // Adquire slot
		go func(t string) {
			defer func() { <-sem }() // Libera slot
			processEnrichment(batcher, t)
		}(target)
	}
}

func processEnrichment(batcher *db.Batcher, target string) {
	defer func() {
		if r := recover(); r != nil {
			// Silencioso em prod, ou log de debug
		}
	}()

	parts := strings.Split(target, ":")
	if len(parts) < 2 { return }
	ip, port := parts[0], parts[1]

	var banner, tlsDomain, tlsIssuer, service, cpe, jarm, htmlTitle, headersHash, country, asnOrg, deviceType string
	var asn uint32
	var headers map[string]string
	var findings SecurityFindings
	var alpnProtocol string
	service = "unknown"

	// 1. Handshake TLS (Tenta primeiro, pois dá o Service = HTTPS logo de cara)
	// Adicionamos SNI para extrair domínios reais de CDNs
	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "", // Pode ser populado por Reverse DNS no futuro
	}
	
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	connTLS, err := tls.DialWithDialer(dialer, "tcp", target, conf)
	if err == nil {
		state := connTLS.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			tlsDomain = cert.Subject.CommonName
			if len(cert.Issuer.Organization) > 0 {
				tlsIssuer = cert.Issuer.Organization[0]
			}
			service = "https"
		}
		alpnProtocol = state.NegotiatedProtocol // ALPN
		connTLS.Close()
	}

	// 2. Coleta de Banner via TCP RAW + HTTP Probe
	if banner == "" {
		banner, service = grabBanner(target, port)
	}

	// 3. Fallback de Identificação por Porta
	if service == "unknown" || service == "" {
		service = inferServiceByPort(port)
	}

	// 4. Fingerprinting Avançado
	cpe = extractCPE(banner, service, port)
	htmlTitle, headers = fetchHTTPData(target, port)
	findings = analyzeHTTPData(banner, headers, ip, alpnProtocol)
	headersHash = fmt.Sprintf("%x", len(fmt.Sprintf("%v", headers))) // Simple hash
	// JARM
	jarm = computeJARM(target)
	// GeoIP
	country, asnOrg, asn = enrichLocation(ip)
	jarm = computeJARM(target)

	// 5. Persistência Profissional
	var portInt int
	fmt.Sscanf(port, "%d", &portInt)

	batcher.Add(db.ScanResult{
		IP:              ip,
		Port:            portInt,
		Status:          "enriched",
		Service:         service,
		Banner:          banner,
		TLSDomain:       tlsDomain,
		TLSIssuer:       tlsIssuer,
		CPE:             cpe,
		JARM:            jarm,
		HTMLTitle:       htmlTitle,
		HeadersHash:     headersHash,
		SecurityHeaders: findings.SecurityHeaders,
		DiscoveredPaths: findings.DiscoveredPaths,
		InternalIPs:     findings.InternalIPs,
		OtherTags:       findings.OtherTags,
		Country:         country,
		ASN:             asn,
		ASNOrg:          asnOrg,
		DeviceType:      deviceType,
	})
}

func grabBanner(target, port string) (string, string) {
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		return "", ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(4 * time.Second))

	// Sonda inteligente: Se for porta comum web, manda HTTP. Caso contrário, espera o banner do server.
	if port == "80" || port == "8080" || port == "8888" {
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if n == 0 {
		return "", ""
	}

	raw := string(buf[:n])
	cleanBanner := strings.Map(func(r rune) rune {
		if r < 32 || r > 126 { return -1 }
		return r
	}, raw)

	// Lógica de Identificação por Conteúdo (Fingerprinting)
	detectedService := "unknown"
	lowerBanner := strings.ToLower(cleanBanner)
	if strings.Contains(lowerBanner, "ssh") {
		detectedService = "ssh"
	} else if strings.Contains(lowerBanner, "http") {
		detectedService = "http"
	} else if strings.Contains(lowerBanner, "ftp") {
		detectedService = "ftp"
	}

	return strings.TrimSpace(cleanBanner), detectedService
}

func inferServiceByPort(port string) string {
	mapping := map[string]string{
		"21":   "ftp",
		"22":   "ssh",
		"23":   "telnet",
		"25":   "smtp",
		"53":   "dns",
		"80":   "http",
		"443":  "https",
		"3306": "mysql",
		"3389": "rdp",
		"5432": "postgresql",
		"6379": "redis",
		"8080": "http",
	}
	if s, ok := mapping[port]; ok {
		return s
	}
	return "unknown"
}

func extractCPE(banner, service, port string) string {
	// Carregar fingerprints
	file, err := os.Open("fingerprints.json")
	if err != nil {
		return ""
	}
	defer file.Close()

	var fingerprints []map[string]interface{}
	if err := json.NewDecoder(file).Decode(&fingerprints); err != nil {
		return ""
	}

	for _, fp := range fingerprints {
		if fpPort, ok := fp["port"].(float64); ok && fmt.Sprintf("%.0f", fpPort) == port {
			if contains, ok := fp["banner_contains"].(string); ok && strings.Contains(banner, contains) {
				if cpe, ok := fp["cpe"].(string); ok {
					return cpe
				}
			}
		}
	}

	// Fallback para regex antigo
	if service == "http" || service == "https" {
		if matched, _ := regexp.MatchString(`Apache/([\d.]+)`, banner); matched {
			re := regexp.MustCompile(`Apache/([\d.]+)`)
			matches := re.FindStringSubmatch(banner)
			if len(matches) > 1 {
				return fmt.Sprintf("cpe:2.3:a:apache:http_server:%s", matches[1])
			}
		}
		if matched, _ := regexp.MatchString(`nginx/([\d.]+)`, banner); matched {
			re := regexp.MustCompile(`nginx/([\d.]+)`)
			matches := re.FindStringSubmatch(banner)
			if len(matches) > 1 {
				return fmt.Sprintf("cpe:2.3:a:f5:nginx:%s", matches[1])
			}
		}
	}
	return ""
}

func enrichLocation(ipStr string) (string, string, uint32) {
	if geoCityDB == nil || geoAsnDB == nil {
		return "", "", 0
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", "", 0
	}
	city, err := geoCityDB.City(ip)
	if err != nil {
		return "", "", 0
	}
	asn, err := geoAsnDB.ASN(ip)
	if err != nil {
		return city.Country.IsoCode, "", 0
	}
	return city.Country.IsoCode, asn.AutonomousSystemOrganization, uint32(asn.AutonomousSystemNumber)
}

func fetchHTTPData(target, port string) (string, map[string]string) {
	if port != "80" && port != "443" && port != "8080" {
		return "", nil
	}

	url := fmt.Sprintf("http://%s", target)
	if port == "443" {
		url = fmt.Sprintf("https://%s", target)
	} else if port != "80" {
		url = fmt.Sprintf("http://%s:%s", target, port)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()

	// Extrair title do HTML
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	html := string(buf[:n])
	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	matches := re.FindStringSubmatch(html)
	title := ""
	if len(matches) > 1 {
		title = matches[1]
	}

	// Retornar headers como map
	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}

	return title, headers
}

func computeJARM(target string) string {
	// Placeholder para JARM - implementação completa requer 10 handshakes TLS customizados
	// Para produção, usar https://github.com/salesforce/jarm
	return ""
}