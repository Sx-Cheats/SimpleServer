#include "./NetworkAPI.h"

//Server defs

void debug_client_server(PNServerClient clientServer) {

	std::cout << "----------------NEW CLIENT CONNECTION----------------" << std::endl;

	if (clientServer->IpToServer.family == AF_INET) {
		std::cout << "\tClient IP (used to connect): " << ((IPV4_t*)(clientServer)->IpToServer.address)->ToString() << std::endl;
	}


	if (clientServer->Ip.family == AF_INET) {
		std::cout << "\tClient IP: " << ((IPV4_t*)(clientServer)->Ip.address)->ToString() << std::endl;
	}

	if (clientServer->IpToServer.family == AF_INET6) {
		std::cout << "\tClient IP (used to connect): " << ((IPV6_t*)(clientServer)->IpToServer.address)->ToString() << std::endl;
	}


	if (clientServer->Ip.family == AF_INET6) {
		std::cout << "\tClient IP: " << ((IPV6_t*)(clientServer)->Ip.address)->ToString() << std::endl;
	}






	std::cout << "\tClient port: " << (clientServer)->Port << std::endl;
	std::cout << "\tClient timeout receive: " << (clientServer)->TimeoutRcv << std::endl;
	std::cout << "-----------------------------------------------------" << std::endl;


}

DWORD NServer_t::SetTimeout(DWORD NewTimeout) 
{
	if (NewTimeout < 0) return this->Timeout;

	DWORD bcTimeout = this->Timeout;

	this->Timeout = NewTimeout;

	for(std::vector<PNServerClient>::iterator client = this->Clients->begin(); client != this->Clients->end(); client++)
		setsockopt((*client)->client_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&this->Timeout, sizeof(DWORD));

	return bcTimeout;
}

DWORD NServer_t::SetMaxConnection(DWORD NewMaxConnection)
{
	if (NewMaxConnection < 0) return this->MaxConnection;

	DWORD bcMaxConnection = this->MaxConnection;

	this->MaxConnection = NewMaxConnection;

	size_t nClient = this->Clients->size();

	if (nClient > this->MaxConnection)
	{
		for (DWORD c = nClient; c > this->MaxConnection; c--)
		{
			PNServerClient Client = this->Clients->at(c-1);

			if (Client)
			{
				this->DiscClient(Client);
				NtTerminateThread(Client->client_thread,0);
			}
		}
	}
	return bcMaxConnection;
}

DWORD NServer_t::SetTimeoutForClient(PNServerClient Client, DWORD NewTimeout)
{
	if (NewTimeout < 0 || !Client) return this->Timeout;

	DWORD bcTimeout = Client->TimeoutRcv;

	Client->TimeoutRcv = NewTimeout;

     setsockopt(Client->client_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&Client->TimeoutRcv, sizeof(DWORD));

	return bcTimeout;
}

void NServer_t::_new_client_(PNServerClient new_client)
{
	bool b = server_mutex.try_lock();

	this->Clients->push_back(new_client);

	if (b)
		server_mutex.unlock();
}


void NServer_t::DiscClient(PNServerClient client)
{
	if (client->client_socket == NULL)
		return;

	bool b = server_mutex.try_lock();

	this->_client_disconnect_callback_(client);

	closesocket(client->client_socket);

	std::vector<PNServerClient>::iterator fclient = std::find(this->Clients->begin(), this->Clients->end(), client);

	if (fclient != this->Clients->end())
		this->Clients->erase(fclient);

	client->client_socket = NULL;

	if (b)
		server_mutex.unlock();
}



bool NServer_t::_connect_success_(NServer_t* server, PNServerClient client)	 
{
	bool br = true;

	if ((this->Clients->size() >= this->MaxConnection) && this->MaxConnection > 0)
	{
		this->DiscClient(client);

		return false;
	}

	if (this->ConnectSuccess_Event_CallBack)
		br = this->ConnectSuccess_Event_CallBack(client);

	return br;
}

void NServer_t::_connect_failed_(int error_code)
{
	bool b = server_mutex.try_lock();

	if (this->ConnectFailed_Event_CallBack)
		this->ConnectFailed_Event_CallBack(error_code);

	if (b)
		server_mutex.unlock();
}


void NServer_t::StartListen()
{
	this->IsListen = true;

	HANDLE t = (HANDLE)_beginthreadex(NULL, 0, (_beginthreadex_proc_type)NServer_t::_server_listen_, this, CREATE_SUSPENDED, 0);

	if (t != INVALID_HANDLE_VALUE)
	{
		ListenHandle = t;
		NtAlertResumeThread(t, 0);
	}
}

void NServer_t::StopListen()
{
	this->IsListen = false;

	shutdown(this->Socket, SD_RECEIVE);

	HANDLE t = this->ListenHandle;

	this->ListenHandle = NULL;

	NtTerminateThread(t, 0);
	NtClose(t);

}

void NServer_t::CloseServer()
{
	if (this->Socket == NULL || this->ListenHandle == NULL)
		return;

	this->StopListen();

	this->DiscAllClient();

	closesocket(this->Socket);

	this->Socket = NULL;

	NtPulseEvent(ServerEvent, 0);

	NtClose(ServerEvent);

	this->ServerEvent = NULL;
}



void NServer_t::_new_client_recv_(NServerClient* client)
{
	PNServer hserver = (PNServer)client->server;

	char* buffer_data = (char*)std::calloc(1, hserver->RecvSize);

	while (client->client_socket && hserver->Socket)
	{
		if (client->is_listen_recv)
		{
			int bytesRead = recv(client->client_socket, buffer_data, hserver->RecvSize, 0);

			if (!client->client_socket || !hserver->Socket || bytesRead <= 0)
				break;

			if (!client->is_listen_recv)
			{
				memset(buffer_data, 0, hserver->RecvSize);
				continue;
			}

			hserver->_recv_server_client_callback_(client, buffer_data, bytesRead);

			send(client->client_socket, buffer_data, bof_max(strlen(buffer_data), hserver->RecvSize), 0);

			memset(buffer_data, 0, hserver->RecvSize);
		}
		else
			Sleep(5000);
	}

	if (buffer_data)
		free(buffer_data);

	hserver->DiscClient(client);

	HANDLE tct = client->client_thread;
	client->client_thread = NULL;

	NtTerminateThread(tct, 0);

	NtClose(tct);
}

char* NServer_t::GetNextRecvClient(PNServerClient _client)
{
	char* buffer_data = new char[this->RecvSize];
	int bytesRead = recv(_client->client_socket, buffer_data, this->RecvSize, 0);

	if (bytesRead > 0)
		return buffer_data;
	else
		return nullptr;
}

int NServer_t::Send(PNServerClient client_server_side, const char* buffer_data)
{
	if (!this->Socket || !client_server_side->client_socket)
		return -1;

	return send(client_server_side->client_socket, buffer_data, bof_max(strlen(buffer_data), ((PNServer)client_server_side->server)->RecvSize), 0);
}

int NServer_t::Send(PNServerClient client_server_side, std::string buffer_data)
{
	if (!this->Socket || !client_server_side->client_socket)
		return -1;

	return send(client_server_side->client_socket, buffer_data.c_str(), bof_max(buffer_data.size(), ((PNServer)client_server_side->server)->RecvSize), 0);

}

void NServer_t::WaitForDisconnect()
{
	if (this->ServerEvent != NULL)
		WaitForSingleObject(this->ServerEvent, INFINITE);

}


char* NServer_t::_recv_server_client_callback_(PNServerClient client, char* buffer_data,int byteReaded)
{
	bool b = this->server_mutex.try_lock();

	if (this->ServerRecv_Event_CallBack)
		strncpy(buffer_data, this->ServerRecv_Event_CallBack(client, buffer_data, byteReaded).c_str(), this->RecvSize);
	else
		strncpy(buffer_data, (char*)"\0", this->RecvSize);

	if (b)
		this->server_mutex.unlock();

	return buffer_data;
}

void NServer_t::_client_disconnect_callback_(PNServerClient client)
{
	bool b = this->server_mutex.try_lock();

	if (this->DisconnectClient_Event_CallBack)
		this->DisconnectClient_Event_CallBack(client);

	if (b)
		this->server_mutex.unlock();
}


void NServer_t::Event_ServerRecv(std::function<std::string(PNServerClient, char*,int byteRead)> CallBack)
{
	bool b = this->server_mutex.try_lock();

	this->ServerRecv_Event_CallBack = CallBack;

	if (b)
		this->server_mutex.unlock();
}

void NServer_t::Event_ConnectSuccess(std::function<bool(PNServerClient)> CallBack)
{
	bool b = this->server_mutex.try_lock();

	this->ConnectSuccess_Event_CallBack = CallBack;

	if (b)
		this->server_mutex.unlock();
}

void NServer_t::Event_ConnectFailed(std::function<void(int)> CallBack)
{
	bool b = server_mutex.try_lock();

	this->ConnectFailed_Event_CallBack = CallBack;

	if (b)
		server_mutex.unlock();
}

void NServer_t::Event_ClientDisconnect(std::function<void(PNServerClient)> CallBack)
{
	bool b = server_mutex.try_lock();

	this->DisconnectClient_Event_CallBack = CallBack;

	if (b)
		server_mutex.unlock();
}



void NServer_t::DiscAllClient()
{
	for (auto it = this->Clients->begin(); it != this->Clients->end(); it++)
	{
		this->_client_disconnect_callback_(*it);

		closesocket((*it)->client_socket);

		(*it)->client_socket = NULL;
	}

	this->Clients->clear();
}

void NServer_t::_server_listen_(NServer_t* server)
{
	sockaddr_storage  clientAddress{};
	int clientAddressSize = sizeof(clientAddress);

	listen(server->Socket, server->MaxConnection);

	while (server->Socket && server->IsListen)
	{
		if (server->IsListen)
		{
			SOCKET clientSocket = accept(server->Socket, (sockaddr*)&clientAddress, &clientAddressSize);

			if (!server->Socket)
			{
				closesocket(clientSocket);

				server->DiscAllClient();

				server->StopListen();

				break;
			}

			if (!server->IsListen)
				break;

			if (clientSocket != INVALID_SOCKET)
			{
				PNServerClient  nclient = new NServerClient;

				nclient->server = (PVOID)server;
				nclient->client_socket = clientSocket;

				if (clientAddress.ss_family == AF_INET) {

					char clientIPAddress[INET_ADDRSTRLEN];
					struct sockaddr_in* ipv4 = (struct sockaddr_in*)&clientAddress;
					inet_ntop(AF_INET, &(ipv4->sin_addr), clientIPAddress, sizeof(clientIPAddress));

					nclient->Ip = IpHostInfo(new IPV4_t(clientIPAddress), AF_INET);
					nclient->Port = ntohs(ipv4->sin_port);

					sockaddr_in socktest;
					int connectedAddressSize = sizeof(socktest);
					getsockname(clientSocket, (sockaddr*)&socktest, &connectedAddressSize);

					inet_ntop(AF_INET, &(socktest.sin_addr), clientIPAddress, sizeof(socktest));

					nclient->IpToServer = new IpHostInfo(clientIPAddress, AF_INET);
				}
				else if (clientAddress.ss_family == AF_INET6) {
					char clientIPAddress[INET6_ADDRSTRLEN];
					struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)&clientAddress;
					inet_ntop(AF_INET6, &(ipv6->sin6_addr), clientIPAddress, sizeof(clientIPAddress));

					nclient->Ip = IpHostInfo(new IPV4_t(clientIPAddress), AF_INET6);
					nclient->Port = ntohs(ipv6->sin6_port);

					sockaddr_in6 socktest;
					int connectedAddressSize = sizeof(socktest);
					getsockname(clientSocket, (sockaddr*)&socktest, &connectedAddressSize);

					inet_ntop(AF_INET6, &(socktest.sin6_addr), clientIPAddress, sizeof(socktest));

					nclient->IpToServer = new IpHostInfo(clientIPAddress, AF_INET6);
				}

				if (server->_connect_success_(server, nclient))
				{
					HANDLE new_client_thread = (HANDLE)_beginthreadex(NULL, 0, (_beginthreadex_proc_type)NServer_t::_new_client_recv_, nclient, CREATE_SUSPENDED, 0);

					if (new_client_thread != INVALID_HANDLE_VALUE)
					{
						nclient->client_thread = new_client_thread;

						setsockopt(clientSocket, SOL_SOCKET, SO_SNDBUF, (char*)&server->RecvSize, sizeof(DWORD));
						setsockopt(clientSocket, SOL_SOCKET, SO_RCVBUF, (char*)&server->RecvSize, sizeof(DWORD));

						server->_new_client_(nclient);

						NtAlertResumeThread(new_client_thread, 0);

						if (server->Timeout != 0)
						{
							setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&server->Timeout, sizeof(DWORD));
							nclient->TimeoutRcv = server->Timeout;
						}
					}
					else
					{
						closesocket(clientSocket);

						if(nclient->Ip.address)
						    delete nclient->Ip.address;

						if(nclient->IpToServer.address)
						    delete nclient->IpToServer.address;

						if(nclient)
						   delete 	nclient;

						NtTerminateThread(new_client_thread, 0);

						NtClose(new_client_thread);

						server->_connect_failed_(GetLastError());

						continue;
					}
				}
				else
				{
					closesocket(clientSocket);

					delete 	nclient;

					continue;
				}
			}
			else
				server->_connect_failed_(WSAGetLastError());
		}
		else if (!server->IsListen)
			break;
	}

	if (server->Socket && server->IsListen)
		server->CloseServer();

	else if (!server->IsListen)
		server->StopListen();
}




//Client defs


std::function<void(NClient_t*)> NClient_t::Disconnect_Event_CallBack = NULL;

char* NClient_t::GetClientName()
{
	return ClientName;
}

void NClient_t::WaitForDisconnect()
{
	if (this->client_thread != NULL)
		WaitForSingleObject(this->client_thread, INFINITE);
}


void NClient_t::_client_recv_from_server_event_(NClient_t* current_client)
{
	char* buffer_data = (char*)std::calloc(1, current_client->ServerRecvSize);

	while (current_client->Socket)
	{
		int bytesRead = recv(current_client->Socket, buffer_data, current_client->ServerRecvSize, 0);

		if (!current_client->Socket)
		{
			free(buffer_data);

			current_client->Disconnect();

			return;
		}

		if (bytesRead > 0)
		{
			current_client->_recv_data_from_server_(buffer_data, bytesRead);

			memset(buffer_data, 0, current_client->ServerRecvSize);

		}
		else
		{
			free(buffer_data);

			current_client->Disconnect();

			return;
		}
	}

	free(buffer_data);
	current_client->Disconnect();

	return;
}

void NClient_t::_recv_data_from_server_(char* buffer_data,int bytesRead)
{
	bool b = this->client_mutex.try_lock();

	if (this->RecvData_Event_CallBack)
		this->RecvData_Event_CallBack(buffer_data, bytesRead);

	if (b)
		this->client_mutex.unlock();
}

void NClient_t::Event_RecvData(std::function<void(char*,int)> CallBack)
{
	bool b = this->client_mutex.try_lock();

	this->RecvData_Event_CallBack = CallBack;

	if (b)
		this->client_mutex.unlock();
}

void NClient_t::_event_disconnect_client_()
{
	bool b = client_mutex.try_lock();

	if (NClient_t::Disconnect_Event_CallBack)
		NClient_t::Disconnect_Event_CallBack(this);

	if (b)
		client_mutex.unlock();
}

void NClient_t::Event_Disconnect(std::function<void(NClient_t*)> CallBack)
{
	NClient_t::Disconnect_Event_CallBack = CallBack;
}

int NClient_t::Send(const char* buffer_data, int size)
{
	if (!this->Socket || !this->client_thread)
		return -1;	

	return send(this->Socket, buffer_data, size, 0);
}

int NClient_t::Send(const char* buffer_data)
{
	if (!Socket || !client_thread)
		return -1;

	return send(this->Socket, buffer_data, bof_max(strlen(buffer_data), this->ServerRecvSize), 0);
}

int NClient_t::Send(std::string buffer_data)
{
	if (!this->Socket || !this->client_thread)
		return -1;

	return send(this->Socket, buffer_data.c_str(), bof_max(buffer_data.size(), this->ServerRecvSize), 0);
}

void NClient_t::Disconnect()
{
	if (this->Socket == NULL || !this->client_thread)
		return;

	this->_event_disconnect_client_();

	closesocket(this->Socket);

	this->Socket = NULL;

	if (this->client_thread && this->client_thread != INVALID_HANDLE_VALUE)
	{
		NtTerminateThread(this->client_thread, 0);

		NtClose(this->client_thread);

		this->client_thread = NULL;
	}
}



// NetworkAPI def

std::vector<PNServer>  NetworkAPI::Servers{};


bool NetworkAPI::Init(DWORD v, DWORD v1)
{
	WSADATA wsaData;

	NTapi::Init();

	return (WSAStartup(MAKEWORD(v, v1), &wsaData) == 0);
}

bool NetworkAPI::CleanUp()
{
	for (auto server = NetworkAPI::Servers.begin(); server != NetworkAPI::Servers.end(); server++)
		(*server)->CloseServer();

	return (WSACleanup() == 0);
}

IpHostInfo NetworkAPI::GetHostIPByName(const char* HostName)
{
	struct addrinfo* result = NULL;
	struct addrinfo hints;
																				   
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if (getaddrinfo(HostName, NULL, &hints, &result) != 0)
		return IpHostInfo(new IPV4_t(HostName), 0);

	struct addrinfo* addr = result;

	char ip[INET6_ADDRSTRLEN];
	PVOID address = nullptr;

	if (addr->ai_family == AF_INET) { // IPv4
		struct sockaddr_in* ipv4 = (struct sockaddr_in*)addr->ai_addr;
		address = &(ipv4->sin_addr);
	}
	else if (addr->ai_family == AF_INET6) {
		struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)addr->ai_addr;
		address = &(ipv6->sin6_addr);
	}

	inet_ntop(addr->ai_family, address, ip, INET6_ADDRSTRLEN);
	freeaddrinfo(result);

	if (addr->ai_family == AF_INET) 
		return IpHostInfo(new IPV4_t(ip), addr->ai_family);
	else if (addr->ai_family == AF_INET6)
	    return IpHostInfo(new IPV6_t(ip), addr->ai_family);
}

INT NetworkAPI::GetIpFamily(const char* Ip)
{
	if(Regex::StringMatch(Ip,"^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"))
	 return AF_INET;
	else 
	return AF_INET6;
}

PNClient NetworkAPI::ConnectServer(const char* _Ip, WORD Port, DWORD RcvSendSize, const char ClientName[24])
{
	IpHostInfo Ip = NetworkAPI::GetHostIPByName(_Ip);

	SOCKET _socket = socket(Ip.family, SOCK_STREAM, IPPROTO_TCP);

	BOOL act = TRUE;

	setsockopt(_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&act, sizeof(BOOL));

	//DWORD connect_timeout = 500;

	// setsockopt(_socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&connect_timeout, sizeof(connect_timeout));
	// setsockopt(_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&connect_timeout, sizeof(connect_timeout));

	 if(Ip.family == AF_INET)
	 {
		 sockaddr_in serverAddress{};
		 serverAddress.sin_family = AF_INET;
		 serverAddress.sin_port = htons(Port);

		 std::string IP = ((IPV4_t*)Ip.address)->ToString();
		 inet_pton(AF_INET, IP.c_str(), &serverAddress.sin_addr);

		 if (connect(_socket, (sockaddr*)&serverAddress, sizeof(serverAddress)) != 0)
		 {
			 closesocket(_socket);
			 return nullptr;
		 }
	 }
	 else if (Ip.family == AF_INET6)
	 {
		 sockaddr_in6 serverAddress{};
		 serverAddress.sin6_family = AF_INET6;
		 serverAddress.sin6_port = htons(Port);

		 std::string IP = ((IPV6_t*)Ip.address)->Concact();

		 inet_pton(AF_INET6, IP.c_str(), &serverAddress.sin6_addr);

		 if (connect(_socket, (sockaddr*)&serverAddress, sizeof(serverAddress)) != 0)
		 {
			 closesocket(_socket);
			 return nullptr;
		 }
	 }

//	connect_timeout = 0;
 //  setsockopt(_socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&connect_timeout, sizeof(connect_timeout));
  // setsockopt(_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&connect_timeout, sizeof(connect_timeout));

	PNClient client = new NClient(RcvSendSize, _socket, Ip, Port, ClientName);

	return client;
}

PNServer NetworkAPI::CreateServer(const char * Ip, WORD Port, DWORD RecvSize, DWORD timeout, DWORD MaxConnection)
{
	INT family = NetworkAPI::GetIpFamily(Ip);

	SOCKET _socket = socket(family, SOCK_STREAM, IPPROTO_TCP);

	BOOL act = TRUE;

	PNServer  _server = nullptr;

	setsockopt(_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&act, sizeof(BOOL));
	setsockopt(_socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&act, sizeof(BOOL));

	if (family == AF_INET)
	{
		sockaddr_in serverAddress;
		serverAddress.sin_family = AF_INET;
		serverAddress.sin_port = htons(Port);

		IPV4_t * IP = new IPV4_t(Ip);

		if (IP->Sum() != 0)
			inet_pton(family, IP->ToString().c_str(), &serverAddress.sin_addr);
		else
			serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);

		if (bind(_socket, (sockaddr*)&serverAddress, sizeof(serverAddress)) != 0)
			return  nullptr;

		_server = new NServer(RecvSize, _socket, IpHostInfo(IP, AF_INET), Port, timeout, MaxConnection);
	}
	else if (family == AF_INET6)
	{
		sockaddr_in6  serverAddress{};
		memset(&serverAddress, 0, sizeof(serverAddress));
		serverAddress.sin6_family = AF_INET6;
		serverAddress.sin6_port = htons(Port);

		IPV6_t* IP = new IPV6_t(Ip);						    

		if (IP->Sum() != 0)
			inet_pton(AF_INET6, IP->Concact().c_str(), &serverAddress.sin6_addr);
		else
			serverAddress.sin6_addr = in6addr_any;

		if (bind(_socket, (sockaddr*)&serverAddress, sizeof(serverAddress)) != 0)
			return  nullptr;

		_server = new NServer(RecvSize, _socket, IpHostInfo(IP, AF_INET6), Port, timeout, MaxConnection);
	}

	NetworkAPI::Servers.push_back(_server);

	return	_server;

}

std::vector<NetworkInterface*> NetworkAPI::GetInterfaces()
{
	DWORD size;
	std::vector<NetworkInterface*> Interfaces;

	GetAdaptersInfo(NULL, &size);
	IP_ADAPTER_INFO* info = (IP_ADAPTER_INFO*)calloc(1, size);
	GetAdaptersInfo(info, &size);

	PVOID binfo = info;

	for (; info->Next; info = info->Next)
	{
		PNetworkInterface ni = new NetworkInterface(info->Address, info->AddressLength, info->Index, info->Type, info->DhcpEnabled, info->HaveWins, info->LeaseObtained, info->LeaseExpires, info->AdapterName, info->Description);

		for (IP_ADDR_STRING* ias = &info->IpAddressList; ias; ias = ias->Next)
			ni->Ip.push_back({ IPV4_t(ias->IpAddress.String),IPV4_t(ias->IpMask.String),ias->Context });


		for (IP_ADDR_STRING* ias = &info->GatewayList; ias; ias = ias->Next)
			ni->Gateway.push_back({ IPV4_t(ias->IpAddress.String),IPV4_t(ias->IpMask.String),ias->Context });

		Interfaces.push_back(ni);
	}

	free(binfo);

	return Interfaces;
}


NetworkInterface* NetworkAPI::GetDefaultInterface()
{
	std::vector<NetworkInterface*> Interfaces = GetInterfaces();

	NetworkInterface* _default;

	for (std::vector<NetworkInterface*>::iterator i = Interfaces.begin(); i != Interfaces.end(); i++)
	{
		if ((*i)->Ip[0].IpAddress.Sum() != 0 && (*i)->Ip[0].IpMask.Sum() != 0 && (*i)->DHCPIsEnabled)
			return *i;
	}

	return nullptr;
}


MAC_t NetworkAPI::GetMACByIp(IPV4_t _ip)
{
	ULONG macAddr[2];
	ULONG macAddrLen = 6;

	if (SendARP(_ip.ToInternet(), 0, macAddr, &macAddrLen) == NO_ERROR)
		return   MAC_t((BYTE*)macAddr);
	else
		return MAC_t();
}

MAC_t NetworkAPI::GetMACByIp(const char ip[INET_ADDRSTRLEN])
{
	ULONG macAddr[2];
	ULONG macAddrLen = 6;

	if (SendARP(inet_addr(ip), 0, macAddr, &macAddrLen) == NO_ERROR)
		return   MAC_t((BYTE*)macAddr);
	else
		return MAC_t();
}