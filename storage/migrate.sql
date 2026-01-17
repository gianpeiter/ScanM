-- Migração para adicionar novas colunas de segurança
ALTER TABLE scanning.results ADD COLUMN security_headers Map(String, String) DEFAULT map();
ALTER TABLE scanning.results ADD COLUMN discovered_paths Array(String) DEFAULT [];
ALTER TABLE scanning.results ADD COLUMN internal_ips Array(String) DEFAULT [];
ALTER TABLE scanning.results ADD COLUMN other_tags Map(String, String) DEFAULT map();