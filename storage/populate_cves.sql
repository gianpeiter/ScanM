-- Exemplo de inserção de dados CPE -> CVE (modelo profissional: 1 CVE por linha)
-- Substitua por dados reais da NVD (National Vulnerability Database)
-- Você pode baixar feeds JSON da NVD e parsear para inserir aqui.

INSERT INTO scanning.cve_mappings (cpe, cve, severity, cvss_score, exploit_available, description, published_date) VALUES
('cpe:2.3:a:apache:http_server:2.4.41', 'CVE-2021-41773', 'HIGH', 9.8, 1, 'Path traversal vulnerability in Apache HTTP Server', '2021-09-15'),
('cpe:2.3:a:apache:http_server:2.4.41', 'CVE-2021-42013', 'HIGH', 9.8, 1, 'Remote code execution in Apache HTTP Server', '2021-09-15'),
('cpe:2.3:a:f5:nginx:1.20.1', 'CVE-2021-23017', 'MEDIUM', 6.1, 0, 'Off-by-one error in nginx resolver', '2021-05-25'),
('cpe:2.3:o:microsoft:windows_10:21h1', 'CVE-2021-34527', 'CRITICAL', 8.8, 1, 'PrintNightmare vulnerability', '2021-07-01');

-- Nota: Para produção, automatize a importação de feeds NVD.
-- Exemplo de script Python para baixar e inserir:
-- Use requests para https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz
-- Parse JSON e insira no ClickHouse via clickhouse-client ou API.
-- Use requests para https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz
-- Parse JSON e insira no ClickHouse via clickhouse-client ou API.