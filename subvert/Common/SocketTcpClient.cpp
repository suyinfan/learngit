#include "stdafx.h"
#include "SocketTcpClient.h"
#include "TcpSendRecv.h"

CSocketTcpClient::CSocketTcpClient()
	: m_init(false), m_sock(INVALID_SOCKET)
{
	if(!is_socket_inited())
		init_winsock();
	m_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}


CSocketTcpClient::~CSocketTcpClient()
{
	if (m_sock != INVALID_SOCKET && m_sock != 0)
	{
		if(m_init)
			shutdown(m_sock, SD_BOTH);
		closesocket(m_sock);
	}
}


bool CSocketTcpClient::Connect(LPCWSTR lpszHostName, int nPort)
{
	if (m_sock==INVALID_SOCKET)
	{
		return false;
	}
	if (m_init)
	{
		return false;
	}
	//IPV4
	//gethostbyname是一个被抛弃的函数！
	/*auto host = gethostbyname(lpszHostName);
	sockaddr_in clientService = { 0 };
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr*)(host->h_addr_list[0])));
	clientService.sin_port = htons(nPort);
	*/
	//IPV6 IPV4
	//GetAddrInfo
	ADDRINFOW hints = {0};
	hints.ai_flags = AI_ALL;
	hints.ai_family = PF_INET;
	hints.ai_protocol = IPPROTO_IPV4;
	ADDRINFOW* pResult = NULL;
	auto ret = GetAddrInfoW(lpszHostName, NULL, &hints, &pResult);
	if (ret!=0)
	{
		return false;
	}
	sockaddr_in clientService = { 0 };
	clientService.sin_family = AF_INET;
	clientService.sin_addr.S_un.S_addr = *(reinterpret_cast<ULONG*>(&(reinterpret_cast<sockaddr_in*>(pResult->ai_addr)->sin_addr)));
	clientService.sin_port = htons(nPort);

	ret = connect(m_sock, reinterpret_cast<struct sockaddr*>(&clientService), sizeof(clientService));
	if (ret<0)
	{
		return false;
	}
	m_init = true;
	return true;
}

SOCKET CSocketTcpClient::get()
{
	return m_sock;
}

void CSocketTcpClient::Close()
{
	if (m_init)
	{
		shutdown(m_sock, SD_BOTH);
		m_init = false;
	}
}
