#include <iostream>
#include <vector>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windivert.h>
#include <chrono>
#include <unordered_map>
#include <fstream>
#include <ctime>
#include <shlobj.h>


#pragma	comment(lib, "Ws2_32.lib")
#pragma	comment(lib, "WinDivert.lib")
#pragma comment(lib, "Shell32.lib")

using namespace std;

// Global variables //
//---------------------------------------------//

UINT8 Packet[65535];
UINT PacketLen = 0;
PWINDIVERT_IPHDR IpHeader = NULL;
PWINDIVERT_TCPHDR TcpHeader = NULL;
PWINDIVERT_UDPHDR UdpHeader = NULL;
PVOID Payload = NULL;
UINT PayloadLen = 0;
WINDIVERT_ADDRESS Addr;
ofstream LogFile;
string LogFileName;
string RuleMatched;

//---------------------------------------------//

enum class Zone {
	LOCAL, LOOPBACK, PUBLIC, BLOCKED
};

vector <UINT32> BlackListedIPs = {
	//inet_addr ("")
};

vector <UINT32> BlackListedRanges = {
	//inet_addr ("185.220.101.0")
};

vector <UINT32> Mask = {
	//inet_addr("255.255.255.0")
};

Zone GetZone(UINT32 Ip) {
	for (UINT32 Blocked : BlackListedIPs) {
		if (Ip == Blocked) {
			return Zone::BLOCKED;
		}
	}
	for (size_t i = 0; i < BlackListedRanges.size(); ++i) {
		if ((Ip & Mask[i]) == (BlackListedRanges[i] & Mask[i])) {
			return Zone::BLOCKED;
		}
	}

	UINT8 FirstOctet = Ip & 0xFF;
	UINT8 SecondOctet = (Ip >> 8) & 0xFF;

	if (FirstOctet == 127) {
		return Zone::LOOPBACK;
	}
	else if (FirstOctet == 192 && SecondOctet == 168) {
		return Zone::LOCAL;
	}
	else if (FirstOctet == 10 || (FirstOctet == 172 && (SecondOctet >= 16 && SecondOctet <= 31))) {
		return Zone::LOCAL;
	}
	else {
		return Zone::PUBLIC;
	}
}

string ZoneStr(Zone z) {
	switch (z) {
	case Zone::LOCAL: return "LOCAL";
	case Zone::LOOPBACK: return "LOOPBACK";
	case Zone::PUBLIC: return "PUBLIC";
	case Zone::BLOCKED: return "BLOCKED";
	default: return "Unknown";
	}
}

//---------------------------------------------//

struct ConnectionKey {
	UINT32 SrcIp;
	UINT32 DstIp;
	UINT16 SrcPort;
	UINT16 DstPort;
	UINT8 Protocol;

	bool operator==(const ConnectionKey& other) const {
		return SrcIp == other.SrcIp &&
			DstIp == other.DstIp &&
			SrcPort == other.SrcPort &&
			DstPort == other.DstPort &&
			Protocol == other.Protocol;
	}
};

struct ConnectionKeyHash {
	size_t operator()(const ConnectionKey& k) const {
		size_t h = k.SrcIp;
		h ^= k.DstIp + 0x9e3779b9 + (h << 6) + (h >> 2);
		h ^= k.SrcPort + 0x9e3779b9 + (h << 6) + (h >> 2);
		h ^= k.DstPort + 0x9e3779b9 + (h << 6) + (h >> 2);
		h ^= k.Protocol + 0x9e3779b9 + (h << 6) + (h >> 2);

		return h;
	}
};

enum class ConnectionState {
	ACTIVE, CLOSED
};

struct ConnectionEntry {
	ConnectionState State;
	chrono::steady_clock::time_point LastSeen;
};

unordered_map<ConnectionKey, ConnectionEntry, ConnectionKeyHash> ConnectionTable;

// Logging //
//---------------------------------------------// 

string GetTimeStamp() {
	time_t now = time(0);
	struct tm TimeInfo;
	localtime_s(&TimeInfo, &now);

	char TimeBuf[32];
	strftime(TimeBuf, sizeof(TimeBuf), "%Y-%m-%d_%H-%M-%S", &TimeInfo);

	return string(TimeBuf);
}

string GetDesktopPath() {
	char Path[MAX_PATH];
	SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, Path);


	return string(Path) + "\\" + GetTimeStamp() + "_FirewallLog.csv";

}

void InitializeLog() {

	LogFileName = GetDesktopPath();

	LogFile.open(LogFileName, ios::trunc);

	LogFile << "Timestamp," << "Action," << "Protocol," << "Source IP," << "Source Zone," << "Source Port," << "Destination IP," << "Destination Zone, " << "Destination Port," << "Rule Matched," << "Packet Size" << "\n";
	LogFile.flush();
	cout << "Log file created at: " << LogFileName << endl;
}

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


// Firewall rules // 
//---------------------------------------------// 
enum class Action {
	PASS, BLOCK
};

struct Rule {
	Zone SrcZone;
	Zone DstZone;
	UINT16 DstPort;
	UINT8 Protocol;
	Action Action;
	string Description;
};

vector <Rule> Rules = {
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

Action RuleChecker(Zone SrcZone, Zone DstZone, UINT16 DstPort, UINT8 Protocol, string& RuleMatched) {
	for (const Rule& r : Rules) {
		bool SrcMatch = (r.SrcZone == SrcZone);
		bool DstMatch = (r.DstZone == DstZone);
		bool PortMatch = (r.DstPort == 0 || r.DstPort == DstPort);
		bool ProtocolMatch = (r.Protocol == 0 || r.Protocol == Protocol);

		if (SrcMatch && DstMatch && PortMatch && ProtocolMatch) {
			RuleMatched = r.Description;
			cout << "{Zone " << ZoneStr(SrcZone) << "-->" << ZoneStr(DstZone) << "}" << r.Description << "Port = " << DstPort << endl;
			return r.Action;
		}
	}
	RuleMatched = "No Match";
	return Action::PASS; // Default action 
}

//---------------------------------------------//


void TrackConnection(UINT32 SrcIp, UINT32 DstIp, UINT16 SrcPort, UINT16 DstPort, UINT8 Protocol) {
	ConnectionKey key = { SrcIp, DstIp, SrcPort, DstPort,Protocol };
	ConnectionTable[key] = { ConnectionState::ACTIVE, chrono::steady_clock::now() };

	ConnectionKey reverse = { DstIp, SrcIp, DstPort, SrcPort, Protocol };
	ConnectionTable[reverse] = { ConnectionState::ACTIVE, chrono::steady_clock::now() };

	cout << "{Track} New Connection:" << SrcPort << "-->" << DstPort << endl;

}

bool EstablishedConnection(UINT32 SrcIp, UINT32 DstIp, UINT16 SrcPort, UINT16 DstPort, UINT8 Protocol) {
	ConnectionKey key = { SrcIp, DstIp, SrcPort, DstPort,Protocol };
	auto It = ConnectionTable.find(key);

	if (It != ConnectionTable.end() && It->second.State == ConnectionState::ACTIVE) {
		It->second.LastSeen = chrono::steady_clock::now();
		return true;
	}
	return false;
}

void OldConnection() {
	auto Now = chrono::steady_clock::now();
	for (auto It = ConnectionTable.begin(); It != ConnectionTable.end();) {
		auto age = chrono::duration_cast <chrono::seconds>(Now - It->second.LastSeen).count();
		if (age > 60) {
			It = ConnectionTable.erase(It);
		}
		else {
			++It;
		}
	}
}

void CloseConnection(UINT32 SrcIp, UINT32 DstIp, UINT16 SrcPort, UINT16 DstPort, UINT8 Protocol) {

	char SrcStr[46], DstStr[46];
	inet_ntop(AF_INET, &SrcIp, SrcStr, sizeof(SrcStr));
	inet_ntop(AF_INET, &DstIp, DstStr, sizeof(DstStr));

	ConnectionKey key = { SrcIp, DstIp, SrcPort, DstPort,Protocol };
	ConnectionKey reverse = { DstIp, SrcIp, DstPort, SrcPort, Protocol };
	ConnectionTable.erase(key);
	ConnectionTable.erase(reverse);
	cout << "{Closed} Connection Close :" << SrcStr << "-->" << DstStr << endl;
}

void PacketLogger(PWINDIVERT_IPHDR IpHeader, PWINDIVERT_TCPHDR TcpHeader, PWINDIVERT_UDPHDR UdpHeader) {

	if (IpHeader == NULL) return;

	if (IpHeader != NULL) {
		char SrcStr[46], DstStr[46];
		UINT32 SrcIp = IpHeader->SrcAddr;
		UINT32 DstIp = IpHeader->DstAddr;
		inet_ntop(AF_INET, &SrcIp, SrcStr, sizeof(SrcStr));
		inet_ntop(AF_INET, &DstIp, DstStr, sizeof(DstStr));
		cout << "From: " << SrcStr << " To: " << DstStr << endl;
	}

	if (TcpHeader != NULL) {
		cout << "TCP Packet:" << ntohs(TcpHeader->SrcPort) << ", DstPort=" << ntohs(TcpHeader->DstPort) << endl;
	}
	else if (UdpHeader != NULL) {
		cout << "UDP Packet: SrcPort=" << ntohs(UdpHeader->SrcPort) << ", DstPort=" << ntohs(UdpHeader->DstPort) << endl;
	}

}

void HandlePacket(HANDLE WdHandle, UINT8* Packet, UINT PacketLen, WINDIVERT_ADDRESS Addr) {

	PWINDIVERT_IPHDR IpHeader = NULL;
	PWINDIVERT_TCPHDR TcpHeader = NULL;
	PWINDIVERT_UDPHDR UdpHeader = NULL;
	PVOID Payload = NULL;
	UINT PayloadLen = 0;

	WinDivertHelperParsePacket(Packet, PacketLen, &IpHeader, NULL, NULL, NULL, NULL, &TcpHeader, &UdpHeader, &Payload, &PayloadLen, NULL, NULL);

	if (IpHeader == NULL) {
		WinDivertSend(WdHandle, Packet, PacketLen, NULL, &Addr);
		return;
	}

	PacketLogger(IpHeader, TcpHeader, UdpHeader);

	UINT32 SrcIp = IpHeader->SrcAddr;
	UINT32 DstIp = IpHeader->DstAddr;
	UINT16 SrcPort = 0;
	UINT16 DstPort = 0;
	UINT8 Protocol = IpHeader->Protocol;
	Zone SrcZone = GetZone(SrcIp);
	Zone DstZone = GetZone(DstIp);
	string RuleMatched;

	char SrcStr[46], DstStr[46];
	inet_ntop(AF_INET, &SrcIp, SrcStr, sizeof(SrcStr));
	inet_ntop(AF_INET, &DstIp, DstStr, sizeof(DstStr));

	if (TcpHeader) {
		SrcPort = ntohs(TcpHeader->SrcPort);
		DstPort = ntohs(TcpHeader->DstPort);
	}

	else if (UdpHeader) {
		SrcPort = ntohs(UdpHeader->SrcPort);
		DstPort = ntohs(UdpHeader->DstPort);
	}

	if (SrcZone == Zone::BLOCKED || DstZone == Zone::BLOCKED) {
		cout << "{Blocked} Packet from " << SrcStr << " --> " << DstStr << endl;
		LogPacket("BLOCK", Protocol, SrcIp, SrcZone, SrcPort, DstIp, DstZone, DstPort, "Blocked Zone", PacketLen);
		return;
	}

	if (EstablishedConnection(SrcIp, DstIp, SrcPort, DstPort, Protocol)) {

		cout << "{Established} Allowing Reply : " << SrcStr << "-->" << DstStr << endl;

		LogPacket("ESTABLISHED", Protocol, SrcIp, SrcZone, SrcPort, DstIp, DstZone, DstPort, "Existing Connection", PacketLen);

		if (TcpHeader && (TcpHeader->Fin || TcpHeader->Rst)) {
			CloseConnection(SrcIp, DstIp, SrcPort, DstPort, Protocol);
		}

		WinDivertSend(WdHandle, Packet, PacketLen, NULL, &Addr);
		return;
	}

	Action Decision = RuleChecker(SrcZone, DstZone, DstPort, Protocol, RuleMatched);

	if (Decision == Action::PASS) {
		TrackConnection(SrcIp, DstIp, SrcPort, DstPort, Protocol);
		WinDivertSend(WdHandle, Packet, PacketLen, NULL, &Addr);

		LogPacket("PASS", Protocol, SrcIp, SrcZone, SrcPort, DstIp, DstZone, DstPort, RuleMatched, PacketLen);
	}

	else {
		LogPacket("BLOCK", Protocol, SrcIp, SrcZone, SrcPort, DstIp, DstZone, DstPort, RuleMatched, PacketLen);
	}

	static int PacketCount = 0;
	if (++PacketCount % 100 == 0) {
		OldConnection();
	}
}

int main() {
	HANDLE Handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);

	if (Handle == INVALID_HANDLE_VALUE) {
		cerr << "Failed to open WinDivert handle: " << GetLastError() << endl; // Prints the error code if the handle fails to open
	}

	InitializeLog();
	while (true) {
		if (!WinDivertRecv(Handle, Packet, sizeof(Packet), &PacketLen, &Addr)) break;

		HandlePacket(Handle, Packet, PacketLen, Addr);
	}

	CloseLog();
	WinDivertClose(Handle);
	return 0;
}
