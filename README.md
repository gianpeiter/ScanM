# ScanM: Sistema de Scanner de IPs e Serviços com Enriquecimento GeoIP

## Descrição

O **ScanM** é um sistema avançado de scanner de IPs e serviços projetado para mapear portas abertas, coletar banners, analisar certificados TLS, fingerprints JARM, títulos HTML, cabeçalhos HTTP, CPE (Common Platform Enumeration), tipos de dispositivos, latência e muito mais. Além disso, o projeto realiza **enriquecimento GeoIP** em tempo real, adicionando informações de localização geográfica (país), ASN (Autonomous System Number) e organização associada a cada IP escaneado.

Este projeto é ideal para análises de segurança, monitoramento de rede e estudos de magnitude global, garantindo dados precisos e atualizados sobre infraestrutura crítica.

## Funcionalidades Principais

- **Scanner de Portas**: Identifica portas abertas e serviços associados.
- **Coleta de Dados**: Banners, TLS, JARM, HTML, cabeçalhos, CPE, etc.
- **Enriquecimento GeoIP**: Integração com bancos GeoLite2 da MaxMind para país, ASN e organização.
- **Banco de Dados**: Armazenamento eficiente em ClickHouse para consultas rápidas e escaláveis.
- **Estatísticas em Tempo Real**: Views para análise de portas e serviços mais comuns.

## Arquitetura

- **Linguagens**: Go (enricher, scheduler, worker), Rust (scanner principal).
- **Banco de Dados**: ClickHouse para armazenamento e consultas.
- **GeoIP**: Bancos GeoLite2 atualizados automaticamente via geoipupdate.
- **Mensageria**: Kafka para processamento assíncrono.
- **Containerização**: Docker para fácil deployment.

## Pré-requisitos

- **Sistema Operacional**: Linux (recomendado Ubuntu/Debian).
- **Go**: Versão 1.19+ para compilar componentes Go.
- **Rust**: Para o scanner principal.
- **ClickHouse**: Servidor de banco de dados.
- **Docker e Docker Compose**: Para execução containerizada.
- **Kafka**: Para mensageria (pode ser via Docker).
- **geoipupdate**: Para atualizar bancos GeoIP.

## Instalação

### 1. Instalar Dependências Básicas

```bash
# Atualizar o sistema
sudo apt update && sudo apt upgrade -y

# Instalar Go
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc

# Instalar Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Instalar Docker e Docker Compose
sudo apt install docker.io docker-compose -y
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
# Reinicie o terminal ou faça logout/login

# Instalar ClickHouse
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv E0C56BD4
echo "deb https://repo.clickhouse.com/deb/stable/ main/" | sudo tee /etc/apt/sources.list.d/clickhouse.list
sudo apt update
sudo apt install clickhouse-server clickhouse-client -y
sudo systemctl start clickhouse-server
sudo systemctl enable clickhouse-server
```

### 2. Configurar GeoIP com MaxMind

1. **Obter Licença Gratuita da MaxMind**:
   - Acesse [MaxMind GeoLite2](https://www.maxmind.com/en/geolite2/signup) e cadastre-se para uma conta gratuita.
   - Gere uma `LICENSE_KEY` no painel da conta.

2. **Instalar geoipupdate**:
   ```bash
   sudo apt install geoipupdate -y
   ```

3. **Configurar geoipupdate**:
   - Edite o arquivo de configuração:
     ```bash
     sudo nano /etc/GeoIP.conf
     ```
   - Adicione suas credenciais:
     ```
     AccountID YOUR_ACCOUNT_ID
     LicenseKey YOUR_LICENSE_KEY
     EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country
     ```
   - Atualize os bancos:
     ```bash
     sudo geoipupdate
     ```
   - Os arquivos `.mmdb` serão baixados para `/var/lib/GeoIP/`.

4. **Agendar Atualizações Semanais** (opcional, via cron):
   ```bash
   sudo crontab -e
   # Adicione: 0 2 * * 1 sudo geoipupdate  # Toda segunda-feira às 2h
   ```

### 3. Clonar e Configurar o Projeto

```bash
git clone https://github.com/seu-usuario/scan.git
cd scan

# Instalar dependências Go
go mod tidy

# Compilar componentes
go build ./cmd/enricher
go build ./cmd/scheduler
go build ./cmd/worker

# Para o scanner Rust
cd src/scanner
cargo build --release
```

### 4. Configurar Banco de Dados ClickHouse

1. **Executar o Script de Inicialização**:
   ```bash
   clickhouse-client --query="CREATE DATABASE IF NOT EXISTS scanning;"
   clickhouse-client --multiquery < storage/init.sql
   ```

2. **Verificar Tabelas**:
   ```sql
   USE scanning;
   SHOW TABLES;
   DESCRIBE results;
   ```

### 5. Configuração com Docker (Opcional)

Se preferir usar Docker para tudo:

```bash
# Subir serviços via Docker Compose
docker-compose up -d

# Verificar logs
docker-compose logs
```

## Uso

### 1. Executar o Scan

```bash
# Usar o script de inicialização
./start_scan.sh

# Ou executar manualmente
# Iniciar Kafka, ClickHouse, etc., se não estiverem rodando
# Rodar o scheduler, worker e enricher em terminais separados
```

### 2. Monitorar o Banco de Dados

- **Conectar ao ClickHouse**:
  ```bash
  clickhouse-client
  ```

- **Queries de Exemplo**:
  - Ver resultados recentes:
    ```sql
    SELECT * FROM scanning.results ORDER BY timestamp DESC LIMIT 10;
    ```
  - Estatísticas por país:
    ```sql
    SELECT country, COUNT(*) AS total FROM scanning.results GROUP BY country ORDER BY total DESC;
    ```
  - IPs por ASN:
    ```sql
    SELECT asn, asn_org, COUNT(*) AS total FROM scanning.results WHERE asn > 0 GROUP BY asn, asn_org ORDER BY total DESC LIMIT 20;
    ```
  - Usar a view de estatísticas:
    ```sql
    SELECT * FROM scanning.view_stats LIMIT 10;
    ```

### 3. Verificar GeoIP

- Testar enriquecimento:
  ```bash
  # Exemplo: Consultar um IP específico
  SELECT ip, country, asn, asn_org FROM scanning.results WHERE ip = '8.8.8.8';
  ```

## Estrutura do Projeto

```
ScanM/
├── cmd/
│   ├── enricher/      # Enriquecimento GeoIP
│   ├── scheduler/     # Agendamento de scans
│   └── worker/        # Processamento de tarefas
├── internal/
│   ├── db/            # Conexão com ClickHouse
│   ├── fingerprint/   # Matcher de fingerprints
│   └── kafka/         # Cliente Kafka
├── src/
│   └── scanner/       # Scanner principal em Rust
├── storage/
│   └── init.sql       # Schema do banco
├── worker/            # Scripts auxiliares
├── docker-compose.yml # Configuração Docker
├── go.mod             # Dependências Go
└── README.md          # Este arquivo
```

## Licença

Este projeto é distribuído sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

## Contribuição

Contribuições são bem-vindas! Por favor, abra issues para bugs ou sugestões, e pull requests para melhorias. Siga as diretrizes de contribuição no arquivo `CONTRIBUTING.md`.

## Contato

- **Autor**: Gian Peiter
- **Email**: giancpeiter@gmail.com
- **GitHub**: [gianpeiter](https://github.com/gianpeiter)

Para dúvidas ou suporte, entre em contato via issues no repositório.