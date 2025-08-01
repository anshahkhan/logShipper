# 🪵 SHA Log Shipper Agent

> ⚡ A lightweight, secure, and modular log shipper written in Go for enterprise-grade telemetry — built for Windows, and ready for Linux/macOS in the future.

![Go](https://img.shields.io/badge/Go-1.22-blue?logo=go)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20(Planned)%20%7C%20macOS%20(Planned)-lightgrey)
![gRPC](https://img.shields.io/badge/Transport-gRPC%20with%20TLS-brightgreen)
![Elastic](https://img.shields.io/badge/Logs-To%20Elasticsearch-orange)
![Security](https://img.shields.io/badge/Security-TLS%20Enabled-important)

---

## ✨ Overview

**SHA Log Shipper** is a high-performance, cross-platform-ready log shipping agent designed to collect, enrich, and securely transmit Windows Event Logs to a central SIEM system via **gRPC over TLS**. It's optimized for scalability, modularity, and future expansion to support Linux (journald/syslog) and macOS (Unified Logs).

---

## 🔥 Features

- ⚙️ **Modular Log Types:** Choose specific Windows channels (Sysmon, DNS, VPN, Defender, etc.)
- 🔍 **Regex-Based Event Filtering:** Precisely control what gets shipped.
- 🔐 **gRPC + TLS Encryption:** Ensures logs are securely transmitted.
- 🧠 **Metadata Enrichment:** Org ID, hostname, timestamp, tags.
- 🧹 **Duplicate Filtering:** Avoids noise and redundant logs.
- 📦 **Elastic & Kibana Ready:** Indexes logs to `log` in Elasticsearch.
- 🚀 **Cross-Platform Vision:** Future support for Linux/macOS.

---

## 📁 Project Structure

logShipper/

├── gRPC/

│ ├── logshipper.proto

│ └── logshipperpb/

│ ├── logshipper.pb.go
│ └── logshipper_grpc.pb.go

├── internal/
│ ├── config.go
│ └── sender.go

├── receiver/
│ └── receiver.go

├── config.yaml

├── main.go

├── go.mod

├── go.sum

└── README.md


---

## ⚙️ config.yaml Example

```yaml
org_id: "ORG123"
log_types:
  - "Security"
  - "Microsoft-Windows-Sysmon/Operational"
  - "Microsoft-Windows-DNS-Client/Operational"
  - "Microsoft-Windows-RasClient/Operational" # VPN
  - "Microsoft-Windows-Windows Defender/Operational" # Malware
interval_sec: 5
server_ip: "127.0.0.1"
port: "50051"
event_id_patterns:
  - "^1$"
  - "^3$"
  - "^22$"
  - "^4688$"
  - "^4624$"
  - "^1102$"

```
## 📡 Setup Instructions

### 1️⃣ Generate TLS Certificates (Self-signed)

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

### 2️⃣ Run gRPC Receiver
```bash
go run receiver/receiver.go
```

### 3️⃣ Start the Agent
```bash
go run main.go
```

## 🛣️ Roadmap
- 🔄 Linux (journald/syslog) support
- 🔄 macOS (unified logging) support
- 🔄 Retry with exponential backoff
- 🔄 Agent control panel (Electron/CLI GUI) 
- 🔄 Remote config updates
- 🔄 MSI / DEB / Homebrew installers

## 🤝 Contributing
Got an idea? Spot a bug? Want to help expand support?

We’d love your help!

- Open a PR
- Suggest an issue
- Fork and hack it however you like 💥

## 🧑‍💻 Authors
- Anshah Khan

## 📄 License
MIT License. Use freely, modify boldly, and give credit kindly.

## 🧵 Stay Tuned
**The Log Shipper is just the beginning.
We're building a complete AI-augmented SIEM for defenders.**

### “Build tools to empower defenders, not overwhelm them.” — Anshah Khan
