
# Firewall V2 — Stateful Zone-Aware Firewall in C++

A stateful, zone-based packet firewall built in C++ using WinDivert. Evolved from Firewall V1 — adds connection tracking, IP blacklisting, zone classification, and CSV logging.

---

## Overview
V2 moves beyond stateless port filtering by introducing zone-based rules and connection state tracking. It aims to operate closer to enterprise firewalls like pfSense and Windows Firewall. 

---

## How it works
```
   Incoming/Outgoing Packet
        ↓
   WinDivert Hook (kernel-level intercept)
        ↓
   Parse IP / TCP / UDP headers
        ↓
   Classify SrcIP and DstIP → Zones (LOCAL / LOOPBACK / PUBLIC / BLOCKED)
        ↓
   Check Blacklist → BLOCKED zone? → Drop + Log
        ↓
   Check ConnectionTable → Established session? → Pass + Log
        ↓
   Evaluate Zone-based Rules (top-to-bottom, first match wins)
        ↓
   PASS → TrackConnection → Forward    |    BLOCK → Drop + Log
        ↓
   Every 100 packets: evict idle connections (60s timeout)
```
---

## Features
- Zone-based filtering — classifies IPs into LOCAL, LOOPBACK, PUBLIC, or BLOCKED zones and applies directional rules between them

- Stateful connection tracking — established sessions are cached in a hash map; reply packets bypass rule evaluation

- IP & subnet blacklisting — block individual IPs or entire CIDR ranges via configurable vectors

- TCP FIN/RST handling — detects connection teardown and removes closed sessions from the table

- Connection timeout — idle connections evicted after 60 seconds, preventing unbounded memory growth

- CSV logging — every packet decision written to a timestamped .csv on the desktop

---

## Security conscepts demonstrated

- Stateful packet inspection — tracks TCP session state across packets

- Zone-based access control — analogous to security zones in enterprise firewalls (pfSense, Cisco ASA)

- Default allow / default deny — configurable per zone pair via the Rules vector

- Subnet masking — CIDR-range blacklisting using bitwise mask comparison

- Connection table management — timeout-based eviction to prevent resource exhaustion

- Audit logging — structured CSV output for post-incident review

---

## Zone classification

| Zone | Range |
|---|---|
| LOOPBACK | 127.x.x.x |
| LOCAL | 192.168.x.x, 10.x.x.x, 172.16-31.x.x |
| BLOCKED | Manually configured IPs / subnets |
| PUBLIC | Everything else |

---

## Rule configuration

Rules are evaluated top-to-bottom; first match wins. Each rule specifies source zone, destination zone, port, protocol, and action.

```cpp
vector<Rule> Rules = {
    {Zone::LOOPBACK, Zone::LOOPBACK, 0, 0, Action::PASS, "Allow Loopbacks"},
	{Zone::BLOCKED, Zone::LOCAL, 0, 0, Action::BLOCK, "Block Blacklisted IP"},
	{Zone::BLOCKED, Zone::LOCAL, 0, 0, Action::BLOCK, "Block Blacklisted IP"},
	{Zone::LOCAL, Zone::BLOCKED, 0, 0, Action::BLOCK, "Block to Blacklisted IP"},
	{Zone::PUBLIC, Zone::BLOCKED, 0, 0, Action::BLOCK, "Block to Blacklisted IP"},
	{Zone::LOCAL, Zone::PUBLIC, 80, 6, Action::BLOCK, "Block sending HTTP"},
	{Zone::LOCAL, Zone::PUBLIC, 0, 0, Action::PASS, "Allow sending everything out"},
	{Zone::PUBLIC, Zone::LOCAL, 80, 6, Action::BLOCK, "Block HTTP"},
	{Zone::PUBLIC, Zone::LOCAL, 22, 6, Action::BLOCK, "Block SSH"},
	{Zone::PUBLIC, Zone::LOCAL, 3389, 6, Action::BLOCK, "Block RDP"},
	{Zone::PUBLIC, Zone::LOCAL, 80, 6, Action::BLOCK, "Block HTTP"},
	{Zone::LOCAL, Zone::LOCAL, 0, 0, Action::PASS, "Allow sending everything out"}
};
```
--- 

## Blacklist configuration

Add IPs and subnet ranges directly in the vectors at the top of the file:

```
vector <UINT32> BlackListedIPs = {
	//inet_addr ("")
};

vector <UINT32> BlackListedRanges = {
	//inet_addr ("185.220.101.0")
};

vector <UINT32> Mask = {
	//inet_addr("255.255.255.0")
};
```
---

## CSV log output
A timestamped log file is created on the desktop each run:

Gets the desktop path 
```
string GetDesktopPath() {
	char Path[MAX_PATH];
	SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, Path);


	return string(Path) + "\\" + GetTimeStamp() + "_FirewallLog.csv";

}
```
Initialize the log 
```
void InitializeLog() {

	LogFileName = GetDesktopPath();

	LogFile.open(LogFileName, ios::trunc);

	LogFile << "Timestamp," << "Action," << "Protocol," << "Source IP," << "Source Zone," << "Source Port," << "Destination IP," << "Destination Zone, " << "Destination Port," << "Rule Matched," << "Packet Size" << "\n";
	LogFile.flush();
	cout << "Log file created at: " << LogFileName << endl;
}
```
Create the log
```
void LogPacket(const string& Action, UINT8 Protocol, UINT16 SrcIp, Zone SrcZone, UINT16 SrcPort, UINT16 DstIp, Zone DstZone, UINT16 DstPort, const string& RuleMatched, UINT PacketSize) {

	if (!LogFile.is_open()) {
		cerr << "Log file is not open!" << endl;
		return;
	}

	string ProtocolName;
	if (Protocol == 6) {
		ProtocolName = "TCP";
	}
	else if (Protocol == 17) {
		ProtocolName = "UDP";
	}
	else {
		ProtocolName = "Other";
	}

	char SrcStr[46], DstStr[46];
	inet_ntop(AF_INET, &SrcIp, SrcStr, sizeof(SrcStr));
	inet_ntop(AF_INET, &DstIp, DstStr, sizeof(DstStr));

	LogFile << GetTimeStamp() << "," << Action << "," << ProtocolName << "," << SrcStr << "," << ZoneStr(SrcZone) << "," << SrcPort << "," << DstStr << "," << ZoneStr(DstZone) << "," << DstPort << "," << RuleMatched << "," << PacketSize << "\n";

	LogFile.flush();
}

void CloseLog() {
	if (LogFile.is_open()) {
		LogFile.close();
	}
}
```
---

## Requirements
 
- Windows 10 / 11 (64-bit)
- Visual Studio 2019 or 2022 with Desktop development with C++ workload
- [WinDivert 2.x](https://github.com/basil00/WinDivert/releases)
- Administrator privileges

---

## Setup & build
 
- Download WinDivert and extract to e.g. `C:\WinDivert\`
- In Visual Studio project properties, set:
   - Include directory → `C:\WinDivert\include`
   - Library directory → `C:\WinDivert\x64`
   - Additional dependencies → `WinDivert.lib`
   - Platform → `x64`
- Copy `WinDivert.dll` and `WinDivert64.sys` into your build output folder
- Build with `Ctrl+Shift+B`
- Run the executable as Administrator

---
 
## Known limitations
 
- Windows-only (WinDivert dependency)
- Rules are hardcoded at compile time — no live config reload
- Single-threaded — high-throughput networks may see packet drops
- No IPv6 support
- Code is currently uncommented 

---

## Compared to V1
 
| Feature | V1 | V2 |
|---|---|---|
| Rule basis | Port + Protocol | Zone + Port + Protocol |
| Connection tracking |  Stateless |  Stateful |
| IP blacklisting | ❌ | ✅ |
| Logging | Console only |  CSV file |
| TCP FIN/RST handling | ❌ | ✅ |
| Connection timeout | ❌ | ✅ |
 
See [Firewall_V1](https://github.com/Lazymelly-z/Firewall_V1) for the original implementation.

---

## Project structure
 
```
Firewall_V2/
├── Firewall_V2.cpp     # Core firewall logic
├── README.md
└── x64/
    └── Debug/
        ├── Firewall_V2.exe
        ├── WinDivert.dll        ← copy from WinDivert release
        └── WinDivert64.sys      ← copy from WinDivert release
```
 
---

## Built with
 
- C++ (C++17)
- [WinDivert](https://github.com/basil00/WinDivert) — Windows packet interception library
- Shell32 — desktop path resolution for log output

---

## Author 
**Matthew Belvian** · [GitHub](https://github.com/Lazymelly-z)

**Matt Belvian** · [LinkedIn](https://www.linkedin.com/in/matt-belvian-18b27b354/)







