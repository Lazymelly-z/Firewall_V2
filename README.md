# Firewall_V2

### What it does
* **Packet Interception:** Captures all incoming and outgoing network traffic.
* **Header Analysis:** Inspects IP, TCP, and UDP headers for every packet.
* **Rule Engine:** Evaluates traffic against a customizable list of security rules.
* **Traffic Control:** Instantly allows or blocks packets based on defined logic.
* **Live Monitoring:** Logs every decision to the console, including Source/Dest IPs and Ports.

### Advanced Capabilities
* **Stateful Inspection:** Automatically remembers active sessions to allow reply traffic without re-checking rules.
* **Zone Segmentation:** Categorizes traffic into **Loopback**, **Local**, **Public**, and **Blocked** zones.
* **Automatic Cleanup:** Prunes closed connections (FIN/RST) and expires idle sessions after 60 seconds.
* **Data Logging:** Generates timestamped CSV files on the Desktop.

## Requirements

- Windows 10 or 11 (64-bit)
- Visual Studio 2019 or 2022 with the **Desktop development with C++** workload
- [WinDivert 2.x](https://github.com/basil00/WinDivert/releases)
- Administrator rights

---

## Setup

### 1. Download WinDivert

Go to https://github.com/basil00/WinDivert/releases and download the latest ZIP.
Extract it somewhere easy to find, for example: `C:\WinDivert\`

### 2. Configure Visual Studio

In your project Properties:

| Setting | Where to find it | Value |
|---|---|---|
| Include directory | C/C++ → General → Additional Include Directories | `C:\WinDivert\include` |
| Library directory | Linker → General → Additional Library Directories | `C:\WinDivert\x64` |
| Library file | Linker → Input → Additional Dependencies | `WinDivert.lib` |
| Platform | Top toolbar | `x64` |

### 3. Copy runtime files

Copy these two files from `C:\WinDivert\x64\` into your build output folder (e.g. `x64\Debug\`):

- `WinDivert.dll`
- `WinDivert64.sys`

### 4. Build the project

Press `Ctrl+Shift+B` in Visual Studio.

---

## Running

> **You must run as Administrator or the firewall will fail to open.**

**Option A** — Right-click Visual Studio → Run as administrator, then press F5.

**Option B** — Build the project, then right-click `Firewall_V1.exe` in `x64\Debug\` and choose Run as administrator.
