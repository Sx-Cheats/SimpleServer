#pragma once

#define HAVE_REMOTE
#define _WINSOCK_DEPRECATED_NO_WARNINGS


#include <Ws2tcpip.h>
#include<iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <WinDNS.h>
#include <stdio.h>
#include <functional>

#include <process.h>
#include <mutex>
#include "NTapi.h"

#include <stdio.h>
#include "Regex.h"

#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"psapi.lib")
#pragma comment(lib,"dnsapi.lib")

#define bof_max(a,b) ((a) < (b) ? (a) : (b)) 
#define bof_min(a,b) ((a) > (b) ? (a) : (b)) 



#define DEBUG_CLIENT_SERVER_CONNECT(clientServer) { debug_client_server(clientServer); };


typedef struct IpHostInfo_t {

	PVOID address;
	INT family;

	IpHostInfo_t(PVOID _address=nullptr, INT _family=0) : address(_address), family(_family) {};

} IpHostInfo, * PIpHostInfo;

typedef struct EthernetHeader {
	uint8_t  dest[6];			 
	uint8_t  src[6];
	uint16_t type;
};

typedef struct ARPHeader
{
	uint16_t htype;
	uint16_t ptype;
	uint8_t  hlen;
	uint8_t  plen;
	uint16_t op;
	uint8_t  sender_mac[6];
	uint8_t  sender_ip[4];
	uint8_t  target_mac[6];
	uint8_t  target_ip[4];
};

typedef struct ARPTrame
{
	EthernetHeader eth;
	ARPHeader arp;																									 
};

typedef struct DHCPRelease
{
	uint8_t  MType;
	uint8_t  Htype;
	uint8_t  Hlen;
	uint8_t  Hops;
	uint32_t TansitionId;
	uint16_t Secs;
	uint16_t Flags;
	uint32_t ClientIPAddr;
	uint32_t YourIPAddr;
	uint32_t ServerIpAddress;
	uint32_t GatewayIPAddr;
	uint8_t  ClientMACAddr[16];
	uint8_t  Padding[2];
	uint8_t  ServerName[64];
	uint8_t  File[128];
	uint32_t MagicCookie;
	uint8_t  Options[12];
};


struct IPv4Header
{
	uint8_t  Version;
	uint8_t  TypeOfService;
	uint16_t TotalLength;
	uint16_t Identification;
	uint16_t Flag;
	uint8_t  TimeToLive;
	uint8_t  Protocol;
	uint16_t HeaderCheckSum;
	uint8_t  Src[4];
	uint8_t  Dst[4];
};

struct IPv6Header
{
	uint8_t  Version;
	uint8_t  TrafficClass;
	uint8_t  FlowLabel;
	uint16_t PayloadLength;
	uint8_t  NextHeader;
	uint8_t  HopLimit;
	uint8_t  Src[16];
	uint8_t  Dst[16];
};


struct TcpHeader
{
	uint16_t SrcPort;
	uint16_t DstPort;
	uint32_t SequenceNumber;
	uint32_t AckNowLedgement;
	uint16_t HeaderLentgh;
	uint16_t Window;
	uint16_t CheckSum;
	uint16_t Urgent;

};

struct UdpHeader
{
	uint16_t SrcPort;
	uint16_t DstPort;
	uint16_t UdpLength;
	uint16_t UdpChecksum;
};





class MAC_t
{
public:

	BYTE mac[6]{};

	MAC_t(BYTE * oct)
	{
		SetAddress(oct[0], oct[1], oct[2], oct[3], oct[4], oct[5]);
	}

	MAC_t(const char * oct)
	{
		SetAddress(oct);
	}

	MAC_t() {};

	MAC_t(BYTE oct1, BYTE oct2, BYTE oct3, BYTE oct4, BYTE oct5, BYTE oct6)
	{
		SetAddress(oct1, oct2, oct3, oct4, oct5, oct6);
	}

	MAC_t * SetAddress(const char * _mac)
	{
		if (strlen((char*)_mac) > 17 || !Regex::StringMatch(_mac, "([0-9a-fA-F]{1,2}[-]*){1,6}"))
		{
			memset(mac, 0, sizeof(BYTE) * 6);

			return this;
		}

		std::vector<std::string> byte = Regex::StringSearch(_mac, "([0-9a-fA-F]{1,2}){1,6}");

		for (BYTE x = 0; x < 6; x++) {
			if (x < byte.size()) 
				mac[x] = (BYTE)std::strtol(byte[x].c_str(), nullptr, 16);
			else
				mac[x] = 0;
		}

		return this;		
	}

	MAC_t * SetAddress(BYTE oct1, BYTE oct2, BYTE oct3, BYTE oct4, BYTE oct5, BYTE oct6)
	{
		mac[0] = oct1;
		mac[1] = oct2;
		mac[2] = oct3;
		mac[3] = oct4;
		mac[4] = oct5;
		mac[5] = oct6;
										
		return this;
	}

	std::string ToString()
	{
		char mac_str[18]{};

		sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

		return 	 std::string(mac_str);
	}

	BYTE GetSegment(BYTE segment) {
		if (segment >= 0 && segment < 6)
			return mac[segment];
		else
			return -1;
	}

	std::string GetSegmentString(BYTE segment) {
		if (segment >= 0 && segment < 6) {
			char mac_segment_str[3]{};
			sprintf(mac_segment_str, "%x", mac[segment]);
			return std::string(mac_segment_str);
		}
		else
			return std::string();
	}

	DWORD Sum()
	{
		DWORD _sum = 0;

		for (BYTE s = 0; s < 6; s++) {
			if (mac[s] > 0)
				_sum += mac[s];
		}

		return _sum;
	}

	static bool IsSame(MAC_t mac1, MAC_t mac2)
	{
		return memcmp(mac1.mac, mac2.mac, sizeof(BYTE) * 6) == 0;
	}
};

class IPV4_t
{
public:

	BYTE ip[4]{};

	IPV4_t(const char * ip)
	{
		SetAddress(ip);
	}

	IPV4_t() {};

	IPV4_t(BYTE oct1, BYTE oct2, BYTE oct3, BYTE oct4)
	{
		SetAddress(oct1, oct2, oct3, oct4);
	}

	IPV4_t * SetAddress(const char * address)
	{
		if (strlen(address) > INET_ADDRSTRLEN)
		{
			memset(ip, 0, sizeof(BYTE) * 4);

			return this;
		}

		std::vector<std::string> byte = Regex::StringSearch(address, "([0-9]{1,3}){1,4}");

		for (BYTE x = 0; x < 4; x++) {
			if (x < byte.size()) 
				ip[x] = (BYTE)std::stoi(byte[x]);
			else
				ip[x] = 0;
		}

		return this;
	}

	IPV4_t * SetAddress(BYTE oct1, BYTE oct2, BYTE oct3, BYTE oct4)
	{
		ip[0] = oct1;
		ip[1] = oct2;
		ip[2] = oct3;
		ip[3] = oct4;

		return this;
	}

	BYTE GetSegment(BYTE segment) {
		if (segment >= 0 && segment < 4)
			return ip[segment];
		else 
		return -1;
	}

	std::string GetSegmentString(BYTE segment) {
		if (segment >= 0 && segment < 4) {
			char ip_segment_str[4]{};
			sprintf(ip_segment_str, "%d", ip[segment]);
			return std::string(ip_segment_str);
		}
		else
			return std::string();
	}

	IPAddr ToInternet()
	{
		struct in_addr ipv4addr {};
		inet_pton(AF_INET, ToString().c_str(), &ipv4addr);
		return (IPAddr)ipv4addr.s_addr;
	}

	std::string ToString()
	{
		char ip_str[16]{};
		sprintf(ip_str, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
		return 	 std::string(ip_str);

	}

	DWORD Sum()
	{
		DWORD _sum = 0;

		for (BYTE s = 0; s < 4; s++) {
			if (ip[s] > 0)
				_sum += ip[s];
		}

		return _sum;
	}

	static bool IsSame(IPV4_t ip1, IPV4_t ip2)
	{
		return memcmp(ip1.ip, ip2.ip, sizeof(BYTE) * 4) == 0;
	}

};


class IPV6_t
{
public:

	WORD ip[8]{};

	IPV6_t(const char* ip)
	{
		SetAddress(ip);
	}

	IPV6_t() {};

	IPV6_t(WORD oct1, WORD oct2, WORD oct3, WORD oct4,WORD oct5, WORD oct6, WORD oct7, WORD oct8)
	{
		SetAddress(oct1, oct2, oct3, oct4, oct5, oct6, oct7, oct8);
	}

	IPV6_t* SetAddress(const char* address)
	{
		if (strlen(address) > INET6_ADDRSTRLEN) {
			memset(ip, 0, sizeof(WORD)*8);
			return this;
		}

		std::vector<std::string> byte = Regex::StringSearch(address, "([0-9a-fA-F]{1,4}){1,8}");

		for (BYTE x = 0; x < 8; x++) {
			if (x < byte.size()) {
				ip[x] = (WORD)std::strtol(byte[x].c_str(), nullptr, 16);
			}
			else
				ip[x] = 0;
		}

		return this;
	}

	IPV6_t* SetAddress(WORD oct1, WORD oct2, WORD oct3, WORD oct4, WORD oct5, WORD oct6, WORD oct7, WORD oct8)
	{
		ip[0] = oct1;
		ip[1] = oct2;
		ip[2] = oct3;
		ip[3] = oct4;
		ip[4] = oct5;
		ip[5] = oct6;
		ip[6] = oct7;
		ip[7] = oct8;

		return this;
	}

	std::string Concact()
	{
		if (Sum() == 1)
			return "::1";

		std::string _concact = Regex::StringReplace(ToString(), "(:0{2,4}(?=:))", "");

		return _concact;
	}

	PBYTE ToInternet()
	{
		struct in6_addr ipv6addr {};
		inet_pton(AF_INET6, ToString().c_str(), &ipv6addr);
		return ipv6addr.s6_addr;
	}

	std::string ToString()
	{
		char ip_str[39]{};
		sprintf(ip_str, "%x:%x:%x:%x:%x:%x:%x:%x", ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]);
		return std::string(ip_str);
	}

	WORD GetSegment(BYTE segment) {
		if (segment >= 0 && segment < 8)
			return ip[segment];
		else
			return -1;
	}

	std::string GetSegmentString(BYTE segment) {
		if (segment >= 0 && segment < 8) {
			char ip_segment_str[5]{};
			sprintf(ip_segment_str, "%x", ip[segment]);
			return std::string(ip_segment_str);
		}
		else
			return std::string();
	}

	DWORD Sum()
	{
		DWORD _sum = 0;

		for (BYTE s = 0; s < 8; s++) {
			if (ip[s] > 0)
			_sum += ip[s];
		}
		
		return _sum;
	}

	static bool IsSame(IPV6_t ip1, IPV6_t ip2)
	{
		return memcmp(ip1.ip, ip2.ip, sizeof(WORD) * 8) == 0;
	}

};

typedef struct ADDRESS_INFO_t {

	IPV4_t      IpAddress;
	IPV4_t      IpMask;
	DWORD       Context;

} ADDRESS_INFO, * PADDRESS_INFO_t;


typedef struct NetworkInterface_t
{
	MAC_t   Mac;

	NetworkInterface_t();

	NetworkInterface_t(BYTE * mac,UINT maclen, DWORD index, BYTE type, bool dhcpisenabled, bool havewins, time_t lo, time_t le, char* adaptername, char* description) : Mac(mac), Index(index), Type(type), DHCPIsEnabled(dhcpisenabled), HaveWins(havewins), LeaseObtained(lo), LeaseExpires(le)
	{
		strcpy(AdapterName, adaptername);
		strcpy(Description, description);
	};

	std::vector<ADDRESS_INFO>  Ip;
	std::vector<ADDRESS_INFO>  Gateway;

	DWORD	Index;
	BYTE	Type;	

	bool	DHCPIsEnabled;
	bool	HaveWins;

	time_t  LeaseObtained;
	time_t  LeaseExpires;

	char  AdapterName[MAX_ADAPTER_NAME_LENGTH + 4];
	char  Description[MAX_ADAPTER_NAME_LENGTH + 4];


} NetworkInterface, * PNetworkInterface;


typedef struct NServerClient_t
{
	IpHostInfo  Ip{};
	IpHostInfo  IpToServer{}; // Ip used from client to connect on the server
	WORD   Port=0;
	SOCKET client_socket = NULL;
	HANDLE client_thread = NULL;
	bool   is_listen_recv = true;
	PVOID  server = nullptr;
	DWORD  TimeoutRcv = 0;

} NServerClient, * PNServerClient;



void debug_client_server(PNServerClient clientServer);


typedef struct NServer_t
{
	std::function<bool(PNServerClient)> ConnectSuccess_Event_CallBack = NULL;
	std::function<void(int)> ConnectFailed_Event_CallBack = NULL;

	std::function<std::string(PNServerClient,char *,int byteRead)> ServerRecv_Event_CallBack = NULL;
	std::function<void (PNServerClient)> DisconnectClient_Event_CallBack = NULL;

	HANDLE ListenHandle = NULL;

	DWORD  RecvSize = 1024;

public: 

	IpHostInfo Ip{};
	std::mutex server_mutex;
	WORD     Port = 0;
	SOCKET   Socket = NULL;
	DWORD    Timeout = 0;
	DWORD    MaxConnection = 0;
	std::vector<PNServerClient>  * Clients = nullptr;
	HANDLE   ServerEvent = NULL;
	
	bool IsListen = true;

	NServer_t(DWORD recv_size,SOCKET socket, IpHostInfo ip,WORD port,DWORD timeout,DWORD max_connection) : Socket(socket), Ip(ip), Port(port), Timeout(timeout), MaxConnection(max_connection)
	{
		if (recv_size < 1048576)
			RecvSize = recv_size;
		else
			RecvSize = 1047552;

		this->Clients = new std::vector<PNServerClient>();

		OBJECT_ATTRIBUTES objectAttributes = {};
		objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

		NtCreateEvent(&ServerEvent, EVENT_ALL_ACCESS, &objectAttributes,NotificationEvent,FALSE);

		BOOL act = TRUE;

		setsockopt(Socket, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, (char*) & act, sizeof(BOOL));

		setsockopt(Socket, SOL_SOCKET, SO_SNDBUF, (char*)&RecvSize, sizeof(RecvSize));
		setsockopt(Socket, SOL_SOCKET, SO_RCVBUF, (char*)&RecvSize, sizeof(RecvSize));

		HANDLE t = (HANDLE)_beginthreadex( NULL,0,(_beginthreadex_proc_type)NServer_t::_server_listen_,this, CREATE_SUSPENDED,0);

		if (t != INVALID_HANDLE_VALUE)
		{
			ListenHandle = t;
			NtAlertResumeThread(t, 0);
		}
	}

	DWORD SetTimeout(DWORD NewTimeout);

	DWORD SetMaxConnection(DWORD NewMaxConnection);

	DWORD SetTimeoutForClient(PNServerClient Client, DWORD NewTimeout);

	void _new_client_(PNServerClient new_client);

	void DiscClient(PNServerClient client);

	void DiscAllClient();

	static void _server_listen_(NServer_t * server);
	static void _new_client_recv_(NServerClient * client);

	bool _connect_success_(NServer_t* server, PNServerClient user_sokcet);

	void _connect_failed_(int error_code);

	void StartListen();

	void StopListen();

	void CloseServer();

	char* GetNextRecvClient(PNServerClient _client);

	int Send(PNServerClient client_server_side, const char* buffer_data);

	int Send(PNServerClient client_server_side, std::string buffer_data);

	void WaitForDisconnect();

	char* _recv_server_client_callback_(PNServerClient client, char* buffer_data,int byteReaded);

	void _client_disconnect_callback_(PNServerClient client);


	void Event_ServerRecv(std::function<std::string(PNServerClient, char*, int byteRead)> CallBack);

	void Event_ConnectSuccess(std::function<bool(PNServerClient)> CallBack);

	void Event_ConnectFailed(std::function<void(int)> CallBack);

	void Event_ClientDisconnect(std::function<void(PNServerClient)> CallBack);

} NServer,* PNServer;





typedef class NClient_t
{

private :

	std::function<void(char*,int)> RecvData_Event_CallBack = NULL;

	static std::function<void(NClient_t*)> Disconnect_Event_CallBack;

	std::mutex client_mutex;

	HANDLE client_thread = NULL;

	char ClientName[24] = {"\0"};

	IpHostInfo Ip{};
	WORD   Port = 0;

public:

	SOCKET Socket = NULL;

	const DWORD ServerRecvSize = 0;

	static void _client_recv_from_server_event_(NClient_t * current_client);

	char* GetClientName();

	void WaitForDisconnect();

	NClient_t(DWORD server_recv, SOCKET socket, IpHostInfo ip, WORD port,const char client_name[24]) : ServerRecvSize(bof_min(server_recv, 1024)), Socket(socket), Ip(ip), Port(port)
	{
		if (client_name != nullptr)
			strncpy(ClientName, client_name, 24);

		Sleep(1500);

		setsockopt(socket, SOL_SOCKET, SO_SNDBUF, (char*)&ServerRecvSize, sizeof(DWORD));
		setsockopt(socket, SOL_SOCKET, SO_RCVBUF, (char*)&ServerRecvSize, sizeof(DWORD));

		BOOL act = TRUE;

	    setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, (char*)&act, sizeof(BOOL));

		HANDLE t = (HANDLE)_beginthreadex(NULL, 0, (_beginthreadex_proc_type)NClient_t::_client_recv_from_server_event_, this, CREATE_SUSPENDED, 0);

		if (t != INVALID_HANDLE_VALUE)
		{
			this->client_thread = t;
			NtAlertResumeThread(this->client_thread,0);
		}
	};

	void _recv_data_from_server_(char* buffer_data, int bytesRead);

	void Event_RecvData(std::function<void(char*,int)> CallBack);

	void _event_disconnect_client_();

	static void Event_Disconnect(std::function<void(NClient_t*)> CallBack);

	int Send(const char* buffer_data, int size);

	int Send(const char* buffer_data);

	int Send(std::string buffer_data);

	void Disconnect();

} NClient, * PNClient;


class NetworkAPI
{
public:

	static std::vector<PNServer> Servers;

	static std::vector<NetworkInterface*> GetInterfaces();
	static bool Init(DWORD v=2,DWORD v1=2);
	static bool CleanUp();
	static NetworkInterface* GetDefaultInterface();
	static MAC_t GetMACByIp(const IPV4_t ip);
	static MAC_t GetMACByIp(const char ip[16]);
	static IpHostInfo GetHostIPByName(const char* HostName);
	static INT GetIpFamily(const char* Ip);

	static PNServer CreateServer(const char * Ip, WORD Port = INADDR_ANY,DWORD RecvSize = 1024, DWORD timeout = 0, DWORD MaxConnection = 0);
	static PNClient	ConnectServer(const char* _Ip, WORD Port=443, DWORD RcvSendSize = 1024, const char ClientName[24] = "client");
};


