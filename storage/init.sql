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

-- 3. View para estatísticas em tempo real
CREATE OR REPLACE VIEW scanning.view_stats AS
SELECT 
    port, 
    service,
    count() as total
FROM scanning.results
GROUP BY port, service
ORDER BY total DESC;