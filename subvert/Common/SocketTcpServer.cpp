#include "stdafx.h"
#include "SocketTcpServer.h"
#include <thread>

CSocketTcpServer::CSocketTcpServer()
{
	callback = nullptr;
	client_socks.clear();
	if (!is_socket_inited())
	{
		init_winsock();
	}
}


CSocketTcpServer::~CSocketTcpServer()
{
	if (!client_socks.empty())
	{
		std::for_each(client_socks.cbegin(), client_socks.cend(), [&](auto sk) {shutdown(sk, SD_BOTH); closesocket(sk); });
	}
	if (sock != INVALID_SOCKET && sock != 0)
	{
		shutdown(sock, SD_BOTH);
		closesocket(sock);
	}
	client_socks.clear();
}


bool CSocketTcpServer::init_server(int nPort, std::function<VOID(SOCKET, sockaddr_in)> callback)
{
	sock = socket(AF_INET, SOCK_STREAM, 0);

	if (this->sock == INVALID_SOCKET)
	{
		return false;
	}

	int opt = 1;
	if (setsockopt(this->sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&opt), sizeof(opt)) == SOCKET_ERROR)
	{
		return false;
	}

	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(nPort);
	addr.sin_addr.s_addr = INADDR_ANY;
	std::fill(addr.sin_zero, addr.sin_zero + sizeof(addr.sin_zero), 0);

	if (bind(this->sock, reinterpret_cast<const sockaddr*>(&addr), sizeof(sockaddr_in)) == SOCKET_ERROR)
	{
		return false;
	}

	if (listen(this->sock, SOMAXCONN) == SOCKET_ERROR)
	{
		return false;
	}
	this->callback = callback;
	return true;
}


void CSocketTcpServer::wait_for_clients()
{
	auto thr = std::thread(std::bind(&CSocketTcpServer::listen_thread, this));
	thr.join();
}


void CSocketTcpServer::listen_thread()
{
	for (;;)
	{
		sockaddr_in sender;
		int len = sizeof(sockaddr_in);

		SOCKET desc = accept(this->sock, reinterpret_cast<sockaddr*>(&sender), &len);

		if (desc == INVALID_SOCKET)
		{
			continue;
		}

		client_socks.push_back(desc);

		timeval timeout = { SOCKET_TIMEOUT, 0 };

		if (setsockopt(desc, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout)) != SOCKET_ERROR &&
			setsockopt(desc, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout)) != SOCKET_ERROR)
		{
			auto client_handler = std::thread(std::bind(callback, desc,sender));
			client_handler.detach();	
		}
	}
}
