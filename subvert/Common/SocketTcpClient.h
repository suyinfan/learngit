#pragma once
#include "network.h"
#include "../Common/TcpSendRecv.h"
#include "../Common/SocketTcpClient.h"
class CSocketTcpClient
{
public:
	CSocketTcpClient();
	~CSocketTcpClient();
private:
	SOCKET m_sock;
	bool m_init;
public:
	bool Connect(LPCWSTR lpszHostName, int nPort);
	SOCKET get();
	void Close();
};

