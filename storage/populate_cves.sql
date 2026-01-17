-- Exemplo de inserção de dados CPE -> CVE
-- Substitua por dados reais da NVD (National Vulnerability Database)
-- Você pode baixar feeds JSON da NVD e parsear para inserir aqui.

INSERT INTO scanning.cve_mappings (cpe, cves, severity, description) VALUES
('cpe:2.3:a:apache:http_server:2.4.41', ['CVE-2021-41773', 'CVE-2021-42013'], 'HIGH', 'Path traversal and remote code execution in Apache HTTP Server'),
('cpe:2.3:a:nginx:nginx:1.20.1', ['CVE-2021-23017'], 'MEDIUM', 'Off-by-one error in nginx resolver'),
('cpe:2.3:o:microsoft:windows_10:21h1', ['CVE-2021-34527'], 'CRITICAL', 'PrintNightmare vulnerability');

-- Nota: Para produção, automatize a importação de feeds NVD.
-- Exemplo de script Python para baixar e inserir:
-- Use requests para https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz
-- Parse JSON e insira no ClickHouse via clickhouse-client ou API.