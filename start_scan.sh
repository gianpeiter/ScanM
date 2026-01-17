#!/bin/bash

echo "🚀 Iniciando Infraestrutura de Magnitude Global..."

# 1. Inicia o Enricher (Banner Grabber) em background
echo "[1/3] Iniciando Enricher..."
go run cmd/enricher/main.go & 

# 2. Inicia o Worker (Enviador de pacotes) em background
# Nota: Precisa de sudo por causa dos Raw Sockets
echo "[2/3] Iniciando Worker de Scan..."
sudo go run cmd/worker/main.go &

# 3. Inicia o Scheduler (Gerador de IPs)
echo "[3/3] Iniciando Scheduler..."
go run cmd/scheduler/main.go