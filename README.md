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
