#pragma once
#include "../Common/common.h"
#include "../Common/network.h"
#include "../Common/SocketTcpClient.h"
#include "../Common/TcpSendRecv.h"
namespace helper
{
	bool send_cmd_read(DWORD64 ProcessId, PVOID Address, PVOID outBuffer, SIZE_T toReadSize, PSIZE_T pRetReadSize);
	void init();
}