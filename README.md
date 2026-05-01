# NFV Virtual Firewall Simulation
**Team:** Kiran U P | Harsh Sarda | K Mallikarjun  
**Topic:** Network Function Virtualization (NFV) — Virtual Firewall

---

## 📁 Project Structure

```
NFV_Virtual_Firewall/
├── src/
│   ├── main.py              ← Entry point — run this!
│   ├── firewall_engine.py   ← Core firewall logic
│   ├── packet.py            ← Packet data structure
│   ├── rule.py              ← Firewall rule class
│   ├── validator.py         ← Input validation
│   └── logger.py            ← Logging module
├── tests/
│   └── test_firewall.py     ← Automated test suite (10 tests)
├── logs/
│   └── firewall_YYYY-MM-DD.log  ← Auto-generated per session
└── README.md
```

---

## ▶️ How to Run

### Prerequisites
- Python 3.8 or above (no external libraries needed)

### Run Main Demo
```bash
cd src
python main.py
```

### Run Interactive Web UI (HTML + Tailwind + React)
```bash
# From project root (Python built-in static server)
python -m http.server 8000
```

Then open: `http://localhost:8000/ui/`

### Run Automated Tests
```bash
# From project root
python -m unittest tests.test_firewall -v
# OR
python tests/test_firewall.py
```

---

## 🔥 Features

| Feature | Description |
|---|---|
| IP Filtering | Block/Allow by exact IP |
| Subnet Filtering | Block/Allow by CIDR range (e.g., 10.10.0.0/16) |
| Port Filtering | Match specific destination ports |
| Protocol Filtering | TCP, UDP, ICMP, HTTP, HTTPS, SSH, FTP |
| Time-Based Rules | Block traffic during specific hours |
| Priority Ordering | Lower priority number = checked first |
| Default Policy | Default BLOCK (deny all unmatched) |
| Persistent Logging | All decisions saved to daily log file |
| Input Validation | Strict validation of IP, port, protocol |
| Interactive Mode | Test custom packets via terminal |
| Interactive Web UI | Browser dashboard using HTML + Tailwind CSS + React JS |

---

## 🧪 Test Cases Summary

| # | Scenario | Expected |
|---|---|---|
| TC1 | Known malicious IP (10.0.0.99) | BLOCK |
| TC2 | Suspicious subnet (10.10.5.22) | BLOCK |
| TC3 | HTTPS request (port 443) | ALLOW |
| TC4 | HTTP request (port 80) | ALLOW |
| TC5 | Admin SSH from 192.168.1.10 | ALLOW |
| TC6 | External SSH brute-force | BLOCK |
| TC7 | Telnet (port 23) | BLOCK |
| TC8 | DNS query (UDP/53) | ALLOW |

---

## 👥 Team Contribution

| Member | Role |
|---|---|
| Kiran U P | Rule Engine + Packet Simulation |
| Harsh Sarda | Validator + Logger + Testing |
| K Mallikarjun | Main Runner + Documentation + Report |
