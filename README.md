# 🔐 Autonomous Self-Healing VPN Mesh with Collective Intelligence

> **Smart India Hackathon 2026 | Problem Statement 26160 | NTRO**
> An ML-powered IPsec VPN analysis platform where tunnel endpoints form a self-aware mesh that performs
> collective threat detection, PBFT consensus voting, autonomous remediation planning, post-quantum
> (PQC) readiness assessment, and cryptographic ledger auditing — without ever decrypting payloads.

---

## 📌 Table of Contents

- [Executive Overview](#-executive-overview)
- [Tech Stack](#-tech-stack)
- [Key Features](#-key-features)
- [System Architecture](#️-system-architecture)
- [Project Structure](#-project-structure)
- [Quick Start](#-quick-start)
- [Configuration](#️-configuration)
- [API Reference](#-api-reference)
- [Security Model](#-security-model)
- [How an Analysis Works](#-how-an-analysis-works)
- [Database Schema](#️-database-schema)
- [Testing](#-testing)
- [Troubleshooting](#-troubleshooting)
- [Known Limitations](#️-known-limitations)
- [SIH 2026 Compliance Matrix](#-sih-2026-compliance-matrix)

---

## 🚀 Executive Overview

The platform audits encrypted IPsec traffic **without decrypting it**. An uploaded `.pcap` capture is
parsed, reduced to statistical features (packet sizes, real inter-arrival timing, IKE/ESP counts), and
classified to infer the negotiated cipher suite and tunnel mode. The result is scored for risk, expanded
into a threat matrix, and enriched with CVE intelligence, remediation plans, PQC guidance, Zero-Trust
gaps, mesh/PBFT consensus records, and a sealed ledger entry.

**Core idea:** instead of inspecting isolated point-to-point tunnels, IPsec endpoints are modelled as a
decentralized mesh. When one node reports a weak cipher or anomaly, peers verify and vote
(Practical Byzantine Fault Tolerance, 2/3+ majority), after which the mesh proposes hardened
configuration and records the whole decision trail on a tamper-evident hash chain.

---

## 🧰 Tech Stack

| Layer | Technology |
| :--- | :--- |
| Language / Runtime | Java 17 |
| Framework | Spring Boot 3.0.0 (Web, WebSocket, Thymeleaf, Data JPA, Security, Actuator) |
| Packet parsing | pcap4j 1.8.2 (+ native **libpcap**, installed in the Docker image) |
| ML | Weka 3.8.6 Random Forests (`weka-stable`) |
| Statistics | Apache Commons Math 3.6.1 |
| Auth | JJWT 0.11.5 (HS256), BCrypt password hashing |
| Database | PostgreSQL 15 (Docker) / H2 in-memory (tests) |
| API docs | springdoc-openapi 2.0.2 (Swagger UI) |
| Frontend | Thymeleaf + Bootstrap 5 + FontAwesome (CDN) |
| Packaging | Multi-stage Docker build, Docker Compose |

---

## 🦄 Key Features

| Component | Description | Implementation |
| :--- | :--- | :--- |
| 🧠 **AI Protocol Identification** | Random-Forest classification of cipher suite and Tunnel/Transport mode from traffic statistics, with confidence scores and heuristic fallback. | `com.ipsec.ml.Predictor`, `ModelTrainer` |
| 📊 **Feature Extraction** | Packet-size statistics and **real inter-arrival times derived from pcap capture timestamps** (deterministic per file), plus IKE/ESP protocol counters. | `com.ipsec.features.FeatureExtractor`, `com.ipsec.capture.PcapReader` |
| 📈 **Security Scoring** | 0–100 risk score from cipher strength, DH group, PFS, key lifetime and mode, with a ranked threat matrix. | `com.ipsec.scoring.SecurityScorer`, `ThreatMatrix` |
| 🔴 **CVE Threat Intel** | Cipher-aware matching of known CVEs (e.g. Lucky Thirteen, Sweet32) with severity, exploit status and mitigation. | `com.ipsec.threat.ThreatIntelligenceEngine` |
| 🔧 **Remediation Agent** | Generates hardened-config plans with risk-reduction estimates, downtime and rollback strategy. Plans are persisted with a real lifecycle: `apply` promotes the hardened artifact (original archived for rollback), `rollback` restores it. *Does not modify live devices.* | `com.ipsec.agent.RemediationAgent`, `RemediationLifecycleService` |
| 🕸️ **Threat-Intel Mesh + PBFT** | HMAC-SHA256-signed threat events shared between analyzer instances over HTTP gossip; forgeries are rejected on receipt. PBFT-style consensus counts real votes (local classification + confirming peers) against a 2/3 quorum. | `com.ipsec.mesh.MeshNodeService` |
| 🔗 **Collective-Memory Ledger** | Every analysis seals its events into a block persisted in PostgreSQL: SHA-256 hash chain, real Merkle tree over transaction hashes, proof-of-work nonce. `/api/ledger/verify` recomputes the whole chain and detects any tampering. | `com.ipsec.mesh.LedgerService` |
| 🛡️ **PQC Readiness** | Quantum-readiness scoring with NIST FIPS 203/204 (ML-KEM, ML-DSA) migration roadmap. | `com.ipsec.pqc.PQCReadinessAssessor` |
| 🔍 **Zero-Trust Validator** | ZTNA compliance scorecard (cipher, PFS, mode, MFA) with identified gaps and roadmap. | `com.ipsec.ztrust.ZeroTrustValidator` |
| 📄 **Hardened Config Generator** | Generates `ipsec.conf` (PARANOID/STRICT/BALANCED/LEGACY profiles) plus SELinux and audit rules. | `com.ipsec.config.HardenedConfigGenerator` |
| 🧪 **Oracle Modules** | All computed from the analysis' real data (each result carries a `dataBasis` provenance label): 72h forecast from capture features + analysis-history trend; genuine Schnorr ZK proof (2048-bit prime-order group, Fiat–Shamir, tamper-detecting); supply-chain hashing of the running JAR/models against persisted baselines; zero-sum Nash equilibrium via fictitious play over a payoff matrix built from the observed risk; cross-sector correlation over the real mesh event store. | `com.ipsec.oracle.*`, `com.ipsec.crypto.CryptoKit` |
| 🖥️ **Web Dashboard** | Thymeleaf UI for login and full analysis presentation, with a traffic/threat panel and raw JSON export. | `templates/login.html`, `templates/dashboard.html` |

---

## 🏗️ System Architecture

```
                       +-----------------------------------+
                       |    Wireshark / tcpdump (.pcap)    |
                       +-----------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                       IPsec Analyzer (Spring Boot 3 / Java 17)                    |
|                                                                                   |
|  +------------------------+   +------------------------+   +-------------------+  |
|  |  Thymeleaf Dashboard   |   |  JWT Security Filter   |   | REST Controllers  |  |
|  |  (/login /dashboard)   |   |  (exact-path allowlist)|  | (/api/analyze)    |  |
|  +------------------------+   +------------------------+   +-------------------+  |
|                                                                     |             |
|  +------------------------------------------------------------------+             |
|  |                                                                                |
|  v                                                                                |
|  +---------------------+   +-------------------+   +----------------------------+  |
|  | PcapReader          |   | Predictor         |   | Scoring / Threat Matrix    |  |
|  | (+ real timestamps) |   | (Weka + fallback) |   | (risk 0-100)               |  |
|  +---------------------+   +-------------------+   +----------------------------+  |
|           |                                                 |                      |
|           v                                                 v                      |
|  +---------------------+   +-------------------+   +----------------------------+  |
|  | FeatureExtractor    |   | Remediation Agent |   | Mesh / PBFT / Ledger       |  |
|  | (size, IAT, IKE/ESP)|   | (advisory plans)  |   | (consensus + hash chain)   |  |
|  +---------------------+   +-------------------+   +----------------------------+  |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
                       +-----------------------------------+
                       |    PostgreSQL 15 (audit/history)  |
                       +-----------------------------------+
```

---

## 📁 Project Structure

```
.
├── README.md                          # This file
├── ORACLE_MASTER_PROMPT_v5.md         # Architectural specification prompt
├── IPsecAnalyzer/
│   ├── Dockerfile                     # Multi-stage build (installs libpcap0.8 in runtime)
│   ├── docker-compose.yml             # PostgreSQL 15 + application containers
│   ├── pom.xml                        # Maven build (Java 17, Spring Boot 3.0.0)
│   ├── init.sql                       # PostgreSQL schema, demo admin seed, summary view
│   ├── run.sh                         # One-click startup script (docker compose v2)
│   ├── .env.example                   # Environment variable template
│   ├── models/                        # Weka .model files (EMPTY — see Known Limitations)
│   ├── uploads/                       # Upload volume mount
│   ├── dataset/                       # PCAP training data (mounted at /app/dataset)
│   └── src/
│       ├── main/
│       │   ├── java/com/ipsec/
│       │   │   ├── IPsecAnalyzerApp.java              # Spring Boot entry point
│       │   │   ├── agent/RemediationAgent.java        # Remediation plan generation
│       │   │   ├── api/
│       │   │   │   ├── AnalysisWebSocketController.java  # Progress streaming endpoint
│       │   │   │   ├── GlobalExceptionHandler.java       # Centralised error handling
│       │   │   │   ├── HealthController.java             # /health (DB + ML model status)
│       │   │   │   ├── PageController.java               # /, /login, /dashboard views
│       │   │   │   ├── PublicInfoController.java         # /api/public/info
│       │   │   │   ├── ReportService.java                # Executive/technical text reports
│       │   │   │   └── WebSocketConfig.java              # STOMP/SockJS broker config
│       │   │   ├── capture/PcapReader.java               # pcap4j parser preserving timestamps
│       │   │   ├── config/HardenedConfigGenerator.java   # ipsec.conf / SELinux generation
│       │   │   ├── features/
│       │   │   │   ├── DatasetBuilder.java               # CSV training-set builder
│       │   │   │   └── FeatureExtractor.java             # Traffic feature extraction
│       │   │   ├── mesh/
│       │   │   │   ├── ByzantineConsensus.java           # PBFT voting
│       │   │   │   ├── DistributedLedger.java            # SHA-256 hash-chained ledger
│       │   │   │   ├── MeshNode.java                     # Mesh node + self-healing hooks
│       │   │   │   └── ThreatAlert.java                  # Signed alert payload
│       │   │   ├── ml/
│       │   │   │   ├── ModelExplainability.java          # Feature-importance explanations
│       │   │   │   ├── ModelTrainer.java                 # Weka Random Forest trainer
│       │   │   │   └── Predictor.java                    # Inference + heuristic fallback
│       │   │   ├── oracle/                               # Predictive/morphic/cross-sector modules
│       │   │   ├── pqc/PQCReadinessAssessor.java         # Post-quantum readiness
│       │   │   ├── scoring/                              # SecurityScorer, ThreatMatrix
│       │   │   ├── security/
│       │   │   │   ├── config/SecurityConfig.java        # Filter chain + public allowlist
│       │   │   │   ├── controller/AuthController.java    # Login / validate / logout
│       │   │   │   ├── controller/AnalysisController.java# PCAP upload + history
│       │   │   │   ├── entity/                           # User, LoginAttempt, AnalysisHistory
│       │   │   │   ├── filter/JwtSecurityFilter.java     # Bearer validation
│       │   │   │   ├── repository/                       # Spring Data JPA repositories
│       │   │   │   └── service/                          # JwtTokenService, SecurityBlockingService
│       │   │   ├── threat/ThreatIntelligenceEngine.java  # CVE matching
│       │   │   └── ztrust/ZeroTrustValidator.java        # ZTNA scorecard
│       │   └── resources/
│       │       ├── application.properties                # App configuration
│       │       ├── logback-spring.xml                    # Logging (console + rolling file)
│       │       └── templates/{login,dashboard}.html      # Thymeleaf UI
│       └── test/java/com/ipsec/IPsecAnalyzerTest.java    # Spring context test (H2)
├── dataset/                           # Training pcaps (currently empty)
└── testbed/                           # StrongSwan IPsec testbed
    ├── docker-compose.yml
    ├── config/client/ipsec.conf
    └── scripts/{traffic.sh,capture.ps1}
```

---

## ⚡ Quick Start

### Prerequisites

- **Docker Desktop** (Compose v2) — required for the container path
- **Java 17 + Maven** — only for running outside Docker
- **libpcap** — bundled in the Docker image; for local runs install it (Windows: Npcap, Debian/Ubuntu: `libpcap-dev`)

### Option 1 — Startup script (recommended)

```bash
cd IPsecAnalyzer
chmod +x run.sh
./run.sh
```

It creates `.env` from `.env.example`, starts PostgreSQL, builds and launches the app, then prints the URLs.

### Option 2 — Docker Compose

```bash
cd IPsecAnalyzer
docker compose up -d --build
```

### Option 3 — Local development

```bash
cd IPsecAnalyzer
docker compose up -d postgres          # database only
mvn clean spring-boot:run              # run the app on the host
```

### Access

| Service | URL |
| :--- | :--- |
| Login page | http://127.0.0.1:8080/login |
| Dashboard | http://127.0.0.1:8080/dashboard |
| Health (custom) | http://127.0.0.1:8080/health |
| Actuator health | http://127.0.0.1:8080/actuator/health |
| Swagger UI | http://127.0.0.1:8080/swagger-ui/index.html |

> **Use `127.0.0.1`, not `localhost`.** On Windows, `localhost` may resolve to IPv6 `::1`, where a stale
> WSL relay can hold port 8080 while Docker's IPv4 proxy works fine. See [Troubleshooting](#-troubleshooting).

> 📌 **Important — Accessing via Wi-Fi / Local Network**: To open the dashboard from another phone, tablet, or laptop on the same Wi-Fi or LAN network, replace `127.0.0.1` in the URL with your host computer's active IPv4 address (for example: `http://<YOUR_SYSTEM_IP>:8080/login`). Run `ipconfig` on Windows or `ip a` on Linux to check your system's IPv4 address.

**Authentication & Credentials:** Account credentials and administrator access are dynamically managed and bootstrapped on startup by the Spring Boot backend (`AdminBootstrap` / `SecurityBlockingService`). Password hashes are stored securely using BCrypt encryption with IP and device fingerprint whitelisting.

---

## ⚙️ Configuration

Configuration lives in `IPsecAnalyzer/.env` (created from `.env.example`) and is consumed by
`application.properties` through environment placeholders.

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `DB_PASSWORD` | `securepass123` | PostgreSQL password |
| `DB_URL` | `jdbc:postgresql://postgres:5432/ipsec_db` | JDBC URL (container networking) |
| `DB_USERNAME` | `postgres` | Database user |
| `JWT_SECRET` | development default | HS256 signing key — **change before deploying** |
| `JWT_EXPIRATION` | `3600000` | Token lifetime (ms) |
| `SERVER_PORT` | `8080` | HTTP port |
| `MAX_FILE_SIZE` | `100MB` | Upload limit (also set in `application.properties`) |

Other relevant properties (`application.properties`):

- `spring.jpa.hibernate.ddl-auto=update` — schema is also created by `init.sql`; see Known Limitations.
- `spring.jpa.open-in-view=false` — no OSIV, this is a REST/JPA app.
- `spring.thymeleaf.cache=false` — template changes are picked up without a restart.
- Logging is configured in `logback-spring.xml` (console + rolling file).

Changing the exposed host port: edit the `ports` mapping in `docker-compose.yml` (e.g. `"9090:8080"`).

---

## 📡 API Reference

### Pages (public)

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Redirects to `/login` |
| `GET` | `/login` | Login page |
| `GET` | `/dashboard` | Analysis dashboard (client-side JWT check) |

### Authentication

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` | `/auth/login` | JSON `{username, password}` → JWT token, username, expiry |
| `POST` | `/auth/logout` | Acknowledges logout (tokens are stateless) |
| `GET` | `/auth/validate` | Validates the `Authorization: Bearer` token |

### Analysis (Bearer token required)

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` | `/api/analyze/pcap` | Multipart `file` upload → features, prediction, assessment, threats, remediation, PQC, Zero-Trust, mesh/consensus/ledger, oracle modules. Optional form fields `dhGroup`, `pfs`, `keyLifetime` override the assumed defaults (reported in `configuration.source`) |
| `POST` | `/api/analyze/pcap-streaming` | Starts a progress stream (`pcapPath`, `username` header) published to `/topic/analysis/{username}` |
| `GET` | `/api/analyze/history` | Analysis history for the authenticated user |
| `POST` | `/api/analyze/reports/executive-pdf` | Real PDF rendering of the executive summary (OpenPDF) |
| `POST` | `/api/analyze/reports/technical-pdf` | Real PDF rendering of the technical report (OpenPDF) |

### System

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Custom status: service, database connectivity, ML model presence |
| `GET` | `/actuator/health` | Spring Boot actuator health |
| `GET` | `/api/public/info` | Public service banner |
| `GET` | `/api/public/client-ip` | The client IP as seen by the server (no external service) |
| `GET` | `/v3/api-docs`, `/swagger-ui/**` | OpenAPI specification and UI |
| `WS` | `/ws-analysis` | SockJS/STOMP endpoint (simple broker on `/topic`) |

### Mesh, Ledger, Remediation & ML

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` | `/api/mesh/gossip` | **Public** — ingest a peer's threat event; the HMAC-SHA256 signature *is* the authentication (forgeries rejected, never stored) |
| `GET` | `/api/mesh/overview` | This node + registered peers + recent signed events (Bearer) |
| `POST` | `/api/mesh/register` | Register a peer analyzer instance (`nodeId`, `sector`, `region`, `baseUrl`) |
| `GET` | `/api/ledger/verify` | Recompute the full hash chain — reports `valid` or the first tampered block (Bearer) |
| `GET` | `/api/ledger/blocks` | Recent sealed blocks (Bearer) |
| `POST` | `/api/remediation/{id}/apply` | Promote the hardened config artifact; original archived for rollback (Bearer) |
| `POST` | `/api/remediation/{id}/rollback` | Restore the archived original artifact (Bearer) |
| `GET` | `/api/remediation` | Remediation lifecycle history (Bearer) |
| `POST` | `/api/ml/retrain` | Re-train the RandomForests now (pcap pipeline → Weka) (Bearer) |
| `GET` | `/api/ml/status` | Model files present / training state (Bearer) |

**Example**

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Admin@123"}' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

curl -X POST http://127.0.0.1:8080/api/analyze/pcap \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@capture.pcap"
```

---

## 🔒 Security Model

- **Password storage** — BCrypt (`BCryptPasswordEncoder`); no plaintext comparison.
- **Session** — stateless; every protected request must carry `Authorization: Bearer <JWT>` (HS256).
- **Path protection** — `JwtSecurityFilter` uses an **exact-prefix allowlist** (`/auth/`, `/login`,
  `/dashboard`, `/health`, `/api/public/`, `/swagger-ui`, `/v3/api-docs`, `/ws-analysis`, `/actuator`,
  `/css/`, `/js/`, `/favicon.ico`, `/`); everything else requires a valid token, otherwise `401`.
- **`SecurityConfig`** mirrors that allowlist for `permitAll()`; all other endpoints require authentication.
- **Login abuse protection**
  - Per-account: 4 failed attempts → account locked for 30 minutes.
  - Per-IP: 10 failed attempts within 15 minutes → that IP is throttled for the window
    (prevents lockout-based denial of service against a known account).
- **Audit trail** — every login attempt (success/failure, reason, IP, device fingerprint) is recorded in
  `login_attempts`; each analysis is recorded in `analysis_history`.
- **Tokens are not IP-bound** — a token stays valid regardless of network changes (previous IP pinning
  produced spurious `403 IP mismatch` errors).
- **CSRF** is disabled (stateless bearer-token API). Uploaded filenames are sanitised before use, and
  capture size is capped during parsing.

---

## 🔬 How an Analysis Works

1. **Upload** — `.pcap` is stored in a temporary directory with a sanitised filename.
2. **Parse** — `PcapReader` streams packets through pcap4j, preserving each packet's capture timestamp.
3. **Extract** — `FeatureExtractor` computes average/standard-deviation packet size, inter-arrival time
   statistics (from real timestamps), session duration, and IKE (UDP 500/4500) and ESP (protocol 50) counts.
4. **Classify** — `Predictor` runs the Weka models when present, otherwise deterministic heuristics.
5. **Score** — `SecurityScorer` produces a 0–100 risk score and level; `ThreatMatrix` ranks findings.
6. **Enrich** — remediation plans, CVE intelligence, PQC readiness, Zero-Trust gaps, and hardened config.
7. **Record** — mesh topology, PBFT consensus record and ledger block are produced and the analysis is
   persisted to `analysis_history`.
8. **Respond** — a single JSON payload is returned to the dashboard for rendering.

---

## 🗄️ Database Schema

Created by `init.sql`:

1. **`users`** — credentials (bcrypt hash), email, whitelisted IP, device fingerprint, lockout metadata.
2. **`login_attempts`** — audit log of successful and failed logins with IP, device fingerprint and reason.
3. **`analysis_history`** — submitted filename, predicted cipher/mode, risk score/level, timestamp, client IP.
4. **`analysis_summary`** — view aggregating analyses per user with average risk and last activity.

The seed user is inserted with `ON CONFLICT (username) DO NOTHING` using a valid bcrypt hash of
`Admin@123`, so repeated initialisation is safe.

---

## 🧪 Testing

```bash
cd IPsecAnalyzer
mvn test
```

Or without a local Maven install (uses the same JDK as the build):

```bash
docker run --rm -v "$PWD":/app -w /app maven:3.9-eclipse-temurin-17 mvn test -B
# Git Bash on Windows: prefix with MSYS_NO_PATHCONV=1
```

The suite covers **31 tests across 7 classes** against an in-memory H2 database (no PostgreSQL required):

- `FeatureExtractorTest` — IKE/ESP/AH classification, timestamp-based inter-arrival times and session duration, empty-capture handling
- `AuthFlowTest` — login success/failure, bearer-token protection, public paths, path-traversal bypass attempts, per-IP throttling
- `AnalysisPipelineTest` — end-to-end upload → feature extraction → prediction → persistence over generated captures
- `OracleModulesTest` — ZK proof validity + tamper rejection, Schnorr group primality/order, ledger hash-chain tamper detection, proof-of-work, Nash equilibrium sanity, data-driven 72h predictor
- `MeshGossipTest` — HMAC-signed gossip event accepted and persisted; forged signature rejected and never stored
- `ModelTrainerTest` — real pipeline training (captures → features → RandomForest) with model reload and inference
- `IPsecAnalyzerTest` — Spring context load

Note: the parsing tests load the native pcap library — the Docker run above installs `libpcap0.8` first.

To generate a realistic synthetic IPsec capture for manual testing:

```bash
python ../testbed/scripts/make_test_pcap.py -o uploads/demo.pcap --esp-packets 40
```

**Real-capture training:** `dataset/` ships with profile-labeled captures
(`cipher__mode__label.pcap`, e.g. `AES-256-GCM__Tunnel__bulk-site-1.pcap`). Retrain with
`POST /api/ml/retrain` — the report includes `realCapturesUsed` and an honest `dataBasis`.
Bring up the StrongSwan testbed on any Linux host with one command to add genuine tunnel captures:

```bash
cd ../testbed/scripts && ./run_testbed.sh 30   # tunnel up -> traffic -> capture -> upload/train instructions
```

Build the application image:

```bash
docker compose build app
```

---

## 🛠️ Troubleshooting

| Symptom | Cause / Fix |
| :--- | :--- |
| `http://localhost:8080` times out but the container shows **healthy** | `localhost` resolved to IPv6 `::1` with a stale listener. Use **http://127.0.0.1:8080**, or restart Docker Desktop to clear the IPv6 relay. |
| Every `.pcap` upload returns **500** | Native `libpcap` missing. The Docker image installs `libpcap0.8`; for local runs install Npcap (Windows) or `libpcap-dev` (Linux). |
| Login fails with the demo credentials | `users.password_hash` must contain a real bcrypt hash of the password. Re-seed from `init.sql` (it ships a valid one) or update the row. |
| Requests return **401** | Missing/expired bearer token — log in again via `/auth/login`. |
| Requests return **403** on public paths | The path must be in both the JWT filter allowlist and `SecurityConfig`; re-check after editing either. |
| `init.sql` errors / duplicate key on restart | The seed uses `ON CONFLICT DO NOTHING`; if you modified it, restore idempotency (or remove the `postgres_data` volume for a clean init). |
| Port 5432 already in use | Another PostgreSQL instance owns the port — change the host side of the mapping in `docker-compose.yml`. |
| `ml_model: MISSING` in `/health` | Model training failed at boot — check the log for the Weka error; delete `models/` and restart to retrain, or call `POST /api/ml/retrain`. |

Useful commands:

```bash
docker compose ps                 # container status
docker compose logs -f app        # application logs
docker compose exec app sh        # shell inside the app container
docker compose down               # stop (keeps the database volume)
```

---

### National mesh profile (3 real instances)

```bash
docker compose --profile mesh up -d --build
```

Starts `mesh-gov` (Delhi), `mesh-banking` (Mumbai) and `mesh-telecom` (Chennai), each with its own
PostgreSQL, sharing one HMAC signing key and registering each other via `MESH_PEERS` at startup.
Analyzing a Medium+ risk capture on any node signs and gossips the event over HTTP to the other two;
PBFT consensus then confirms on real quorum (`CONFIRMED (3/3 >= 2/3 PBFT quorum)`) and the
cross-sector correlator reports the genuine multi-sector pattern. Nodes expose no host ports —
`docker exec ipsecanalyzer-mesh-gov-1 curl -s http://localhost:8080/api/mesh/overview ...` to inspect.

---

## ⚠️ Known Limitations

- **ML models train themselves at first boot.** If `models/` is empty the app generates labeled synthetic
  captures, extracts features through the production pipeline, and trains two RandomForests (~2 s);
  `/health` then reports `ml_model: LOADED` and predictions carry real Weka confidences with a
  `modelBasis` provenance label. The bootstrap labels are synthetic — retrain with labeled real captures
  (CSV via `DatasetBuilder`, or `POST /api/ml/retrain`) for production accuracy.
- **Oracle modules compute from real analysis data.** The 72h predictor,
  ZK proof, supply-chain hashing, Nash solver and cross-sector correlation all derive from this capture,
  the analysis history and the persisted mesh/ledger stores. By default the deployment is a single node;
  run the `mesh` profile (below) for a genuine three-instance national mesh with real gossip, PBFT
  quorum and cross-sector patterns.
- **ML bootstrap labels are synthetic; real captures are supported.** Add labeled pcaps named
  `cipher__mode__description.pcap` (e.g. `AES-256-GCM__Tunnel__site-a-2026-05.pcap`) to `dataset/` and
  retrain (`POST /api/ml/retrain` or delete `models/` and restart) — the trainer ingests them through
  the production pipeline and reports `realCapturesUsed` in the training report.
- **Supply-chain baselines are self-referential.** First run records the running JAR/model hashes as the
  baseline; later runs detect changes. The ledger history distinguishes a legitimate rebuild from a
  modification — there is no external vendor signature feed.
- **Remediation applies artifacts, not devices.** `apply` promotes the hardened config in the artifacts
  directory and re-scores risk; nothing is pushed to a live VPN endpoint.
- **Two schema managers coexist.** Hibernate `ddl-auto=update` and `init.sql` both influence the schema;
  keep them aligned when changing entities.
- **Some dashboard controls are presentational.** The PDF report buttons surface status messages while the
  raw JSON export downloads the full analysis payload.

---

## 🎯 SIH 2026 Compliance Matrix

| Requirement (NTRO PS 26160) | Implementation | Status |
| :--- | :--- | :---: |
| **a) VPN testbed generation** — Tunnel/Transport, AES-128/256/GCM, DH groups, PFS, IPv4/IPv6 traffic | `testbed/docker-compose.yml`, `testbed/scripts/run_testbed.sh` (one-command tunnel + capture), `testbed/config/*/ipsec.conf` | Implemented (bring-up requires a Linux host with NET_ADMIN) |
| **b) Traffic capture** — automated pcaps with IKE (UDP 500/4500), ESP (proto 50), AH (proto 51) | `testbed/scripts/capture.ps1`, `com.ipsec.capture.PcapReader` | Implemented |
| **c) AI-based protocol identification** — cipher, mode, DH group, inner traffic type with confidence | `com.ipsec.ml.Predictor`, `ModelTrainer` (self-training at first boot), `com.ipsec.features.DatasetBuilder` | Implemented (RandomForest trained at startup; heuristic fallback if training fails) |
| **d) Security assessment** — crypto strength, DH rating, PFS, key lifetime, replay protection, header exposure | `com.ipsec.scoring.SecurityScorer`, `ThreatMatrix` | Implemented |
| **e) Reports & outputs** — 0–100 risk score, threat matrix, confidence scores, executive/technical reports | `com.ipsec.api.ReportService`, `templates/dashboard.html` | Implemented |
| **Deliverable: interactive dashboard** | Spring Boot + Thymeleaf + Bootstrap 5 UI | Implemented |
| **Deliverable: security controls** | JWT auth, bcrypt hashes, per-IP throttling, account lockout, login audit | Implemented |

---

*Maintained for Smart India Hackathon 2026 — Problem Statement 26160 (NTRO).*
