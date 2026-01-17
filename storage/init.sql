-- 1. Cria o banco de dados
CREATE DATABASE IF NOT EXISTS scanning;

-- 2. Cria a tabela com suporte ao novo campo 'service' e status 'enriched'
CREATE TABLE IF NOT EXISTS scanning.results (
    ip IPv4,
    port UInt16,
    status Enum8('open' = 1, 'closed' = 2, 'enriched' = 3),
    service String,
    banner String CODEC(ZSTD(3)), 
    tls_domain String,
    tls_issuer String,
    cpe String,
    jarm String,
    html_title String,
    headers_hash String,
    security_headers Map(String, String),
    discovered_paths Array(String),
    internal_ips Array(String),
    other_tags Map(String, String),
    country String,
    asn UInt32,
    asn_org String,
    device_type String,
    -- asn e latency podem ser mantidos para expansões futuras
    asn_old UInt32 DEFAULT 0,
    latency Float32 DEFAULT 0,
    timestamp DateTime64(3, 'UTC')
) 
ENGINE = ReplacingMergeTree()
ORDER BY (ip, port)
PRIMARY KEY (ip, port);

-- 4. Tabela de mapeamentos CPE -> CVE para correlação de exploits (modelo profissional: 1 CVE por linha)
CREATE TABLE IF NOT EXISTS scanning.cve_mappings (
    cpe String,
    cve String,
    severity String,     -- e.g., 'HIGH', 'MEDIUM', 'LOW'
    cvss_score Float32,  -- Pontuação CVSS (0-10)
    exploit_available UInt8, -- 1 se exploit público disponível, 0 caso contrário
    description String,  -- Descrição breve da vulnerabilidade
    published_date Date  -- Data de publicação da CVE
)
ENGINE = MergeTree()
ORDER BY (cpe, cve);

-- 5. View para estatísticas em tempo real
CREATE OR REPLACE VIEW scanning.view_stats AS
SELECT 
    port, 
    service,
    count() as total
FROM scanning.results
GROUP BY port, service
ORDER BY total DESC;