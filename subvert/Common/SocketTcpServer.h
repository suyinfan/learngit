#pragma once
#include "network.h"
#include <functional>
#include <vector>
#include <algorithm>

class CSocketTcpServer
{
#define SOCKET_TIMEOUT 10
public:
	CSocketTcpServer();
	~CSocketTcpServer();
	bool init_server(int nPort, std::function<VOID(SOCKET, sockaddr_in)> callback);
	void wait_for_clients();
private:
	SOCKET sock;
	std::function<VOID(SOCKET, sockaddr_in)> callback;
	std::vector<SOCKET> client_socks;
	void listen_thread();
};

