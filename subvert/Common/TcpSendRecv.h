#pragma once
#include "network.h"
class CTcpSendRecv
{
public:
	CTcpSendRecv(SOCKET sock);
	~CTcpSendRecv();
private:
	SOCKET m_sock;
public:
	bool write(LPCVOID Buffer, SIZE_T nSize);
	bool read(LPVOID *lpBuffer, PSIZE_T lpInOutSize);
private:
	int raw_read(LPVOID lpBuffer, SIZE_T nSize);
	bool raw_write(LPCVOID Buffer, SIZE_T nSize);
public:
	bool just_read(LPVOID lpBuffer, PSIZE_T lpSize);
	bool just_write(LPCVOID Buffer, SIZE_T nSize);
};

