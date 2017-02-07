#include "stdafx.h"
#include "network.h"
#include "SocketTcpServer.h"
#include "TcpSendRecv.h"
#include "PatternSearch.h"
#include <string>
#include <chrono>
#include <thread>

//初始化socket
bool init_winsock()
{
	WSADATA wsadata;
	auto wVersionRequested = MAKEWORD(2, 2);
	auto err = WSAStartup(wVersionRequested, &wsadata);
	if (err != 0)
	{
		return false;
	}
	return true;
}
//测试socket
bool  is_socket_inited()
{
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET && WSAGetLastError() == WSANOTINITIALISED)
	{
		return false;
	}
	closesocket(s);
	return true;
}
#if defined(_WIN64)
namespace network
{
	std::map<PACKET_CMD_TYPE, packet_handler> m_handler_packet;
	bool on_cmd_nothing(SOCKET _socket, PVOID _packet, SIZE_T _packet_size)
	{
		return false;
	}
	bool on_cmd_read(SOCKET _socket, PVOID _packet, SIZE_T _packet_size)
	{
		auto pCmdRead = reinterpret_cast<PCMD_READ>(_packet);
		auto ProcessId = pCmdRead->ProcessId;
		auto _ReadAddress = (PVOID)pCmdRead->Address;
		auto _ReadSize = pCmdRead->Size;
		DBG_PRINTA("Read Pid=%d\r\n", ProcessId);
		auto Process = std::experimental::make_unique_resource(
			OpenProcess(PROCESS_ALL_ACCESS, false, (DWORD)ProcessId), &CloseHandle);

		auto client = CTcpSendRecv(_socket);

		HANDLE ProcessHandle = Process.get();
		if (ProcessHandle == INVALID_HANDLE_VALUE)
		{
			DBG_PRINTA("OpenFailed\r\n");
			return false;
		}

		auto new_size = sizeof(PACKET_CMD) + sizeof(RET_READ) + pCmdRead->Size;
		auto p_buffer = malloc(new_size);
		auto exit1 = std::experimental::make_scope_exit([&]() {
			if (p_buffer)free(p_buffer);
		});
		if (!p_buffer)
		{
			return false;
		}
		RtlZeroMemory(p_buffer, new_size);
		auto packet = reinterpret_cast<PPACKET_CMD>(p_buffer);
		packet->dwCmd = RetRead;
		auto ret_read_packet = reinterpret_cast<PRET_READ>(packet->Cmd);
		auto readbuffer = (PVOID)ret_read_packet->data;
		SIZE_T stRead = 0;
		ret_read_packet->ReadRet = 1;
		if (!ReadProcessMemory(ProcessHandle,
			(LPCVOID)_ReadAddress,
			readbuffer,
			_ReadSize,
			&stRead))
		{
			ret_read_packet->ReadRet = 0;
		}
		ret_read_packet->Size = stRead;
		auto b_send = client.write((LPCVOID)p_buffer, new_size);
		return b_send;
	}
	bool on_cmd_write(SOCKET _socket, PVOID _packet, SIZE_T _packet_size)
	{
		auto pCmdWrite = reinterpret_cast<PCMD_WRITE>(_packet);
		auto ProcessId = pCmdWrite->ProcessId;
		auto _WriteAddress = (PVOID)pCmdWrite->Address;
		auto _WriteSize = pCmdWrite->Size;
		auto _WriteBuffer = (PVOID)pCmdWrite->WriteBuf;

		DBG_PRINTA("Write %p %d\r\n", _WriteAddress, _WriteSize);

		auto Process = std::experimental::make_unique_resource(
			OpenProcess(PROCESS_ALL_ACCESS, false, (DWORD)ProcessId), &CloseHandle);

		auto client = CTcpSendRecv(_socket);

		HANDLE ProcessHandle = Process.get();
		if (ProcessHandle == INVALID_HANDLE_VALUE)
		{
			return false;
		}

		auto new_size = sizeof(PACKET_CMD) + sizeof(RET_WRITE);
		auto p_buffer = malloc(new_size);
		auto exit1 = std::experimental::make_scope_exit([&]() {
			if (p_buffer)free(p_buffer);
		});
		if (!p_buffer)
		{
			return false;
		}
		RtlZeroMemory(p_buffer, new_size);
		auto packet = reinterpret_cast<PPACKET_CMD>(p_buffer);
		packet->dwCmd = RetWrite;
		auto ret_write_packet = reinterpret_cast<PRET_WRITE>(packet->Cmd);
		SIZE_T stWrite = 0;
		ret_write_packet->WriteRetStatus = 1;
		DWORD old = 0;
		VirtualProtectEx(ProcessHandle, _WriteAddress, _WriteSize, PAGE_EXECUTE_READWRITE, &old);
		if (!WriteProcessMemory(ProcessHandle,
			(LPVOID)_WriteAddress,
			(LPCVOID)_WriteBuffer,
			_WriteSize,
			&stWrite))
		{
			DBG_PRINTA("Write 失败\r\n");
			ret_write_packet->WriteRetStatus = 0;
		}
		VirtualProtectEx(ProcessHandle, _WriteAddress, _WriteSize, old, &old);

		ret_write_packet->WriteSize = stWrite;
		auto b_send = client.write((LPCVOID)p_buffer, new_size);
		return b_send;
	}
	bool on_cmd_create_thread(SOCKET _socket, PVOID _packet, SIZE_T _packet_size)
	{
		DWORD dwTid = 0;
		DWORD dwExitCode = 0;
		auto pCmdCreateThread = reinterpret_cast<PCMD_THREAD>(_packet);
		auto pid = pCmdCreateThread->ProcessId;
		auto thread_address = PVOID(pCmdCreateThread->RoutineAddress);
		auto thread_param = PVOID(pCmdCreateThread->RoutineParam);
		DBG_PRINTA("秘密通信 CreateThread %p %p\r\n", thread_address, thread_param);
		auto Process = std::experimental::make_unique_resource(
			OpenProcess(PROCESS_ALL_ACCESS, false, pid), &CloseHandle);
		auto process_handle = Process.get();
		if (process_handle&&process_handle!=INVALID_HANDLE_VALUE)
		{		
			auto thread = std::experimental::make_unique_resource(
				CreateRemoteThread(process_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)thread_address,
				thread_param, 0, &dwTid), &CloseHandle);
			auto hThread = thread.get();
			if (hThread&&hThread!=INVALID_HANDLE_VALUE)
			{
			//	NtWaitForSingleObject(hThread, FALSE, NULL);
			//	GetExitCodeThread(hThread, &dwExitCode);
				DBG_PRINTA("秘密通信线程ID = %d\r\n", dwTid);
			}
		}

		auto new_size = sizeof(PACKET_CMD) + sizeof(RET_THREAD);
		auto pBuffer = malloc(new_size);
		auto exit1 = std::experimental::make_scope_exit([&]() {
			if (pBuffer)
			{
				free(pBuffer);
			}
		});
		if (!pBuffer)
		{
			return false;
		}
		RtlZeroMemory(pBuffer, new_size);
		auto ret_packet = reinterpret_cast<PPACKET_CMD>(pBuffer);
		auto ret_ = reinterpret_cast<PRET_THREAD>(ret_packet->Cmd);
		ret_packet->dwCmd = RetCreateThread;
		ret_->ExitCode = dwExitCode;
		ret_->ThreadId = dwTid;
		auto client = CTcpSendRecv(_socket);
		auto b_send = client.write((LPCVOID)pBuffer, new_size);
		return b_send;
	}
	bool on_cmd_alloc(SOCKET _socket, PVOID _packet, SIZE_T _packet_size)
	{
		auto cmd_packet = reinterpret_cast<PCMD_ALLOC>(_packet);
		auto processid = cmd_packet->ProcessId;
		auto flAllocationType = cmd_packet->flAllocationType;
		auto flProtectType = cmd_packet->ProtectType;
		auto BaseAddress = PVOID(cmd_packet->BaseAddress);
		
		auto Process = std::experimental::make_unique_resource(
			OpenProcess(PROCESS_ALL_ACCESS, false, processid), &CloseHandle);
		
		auto process_handle = Process.get();
		if (process_handle&&process_handle != INVALID_HANDLE_VALUE)
		{
			auto pbase = VirtualAllocEx(process_handle, BaseAddress, cmd_packet->Size,
				flAllocationType, flProtectType);
			auto new_size = sizeof(PACKET_CMD) + sizeof(RET_ALLOC);
			auto p_buffer = malloc(new_size);
			auto exit1 = std::experimental::make_scope_exit([&]() {
				if (p_buffer)free(p_buffer);
			});
			if (!p_buffer)
			{
				return false;
			}
			RtlZeroMemory(p_buffer, new_size);
			auto ret_packet = reinterpret_cast<PPACKET_CMD>(p_buffer);
			auto ret_ = reinterpret_cast<PRET_ALLOC>(ret_packet->Cmd);
			ret_packet->dwCmd = RetAlloc;
			ret_->Address = DWORD64(pbase);
			auto client = CTcpSendRecv(_socket);
			auto b_send = client.write((LPCVOID)p_buffer, new_size);
			return b_send;
		}
		return false;
	}
	bool on_cmd_protect(SOCKET _socket, PVOID _packet, SIZE_T _packet_size)
	{
		auto pcmd = reinterpret_cast<PCMD_PROTECT>(_packet);
		auto processid = pcmd->ProcessId;
		auto address = PVOID(pcmd->Address);
		auto size = pcmd->Size;
		auto protect = pcmd->ProtectType;

		auto Process = std::experimental::make_unique_resource(
			OpenProcess(PROCESS_ALL_ACCESS, false, processid), &CloseHandle);

		auto process_handle = Process.get();
		if (process_handle&&process_handle != INVALID_HANDLE_VALUE)
		{
			DWORD old = 0;
			auto bRet = VirtualProtectEx(process_handle, address, size, protect, &old);
			if (!bRet)
			{
				old = 0;
			}
			auto new_size = sizeof(PACKET_CMD) + sizeof(RET_PROTECT);
			auto p_buffer = malloc(new_size);
			auto exit1 = std::experimental::make_scope_exit([&]() {
				if (p_buffer)free(p_buffer);
			});
			if (!p_buffer)
			{
				return false;
			}
			RtlZeroMemory(p_buffer, new_size);
			auto ret_packet = reinterpret_cast<PPACKET_CMD>(p_buffer);
			auto ret_ = reinterpret_cast<PRET_PROTECT>(ret_packet->Cmd);
			ret_packet->dwCmd = RetProtect;
			ret_->OldProtect = old;
			ret_->bRet = bRet;
			auto client = CTcpSendRecv(_socket);
			auto b_send = client.write((LPCVOID)p_buffer, new_size);
			return b_send;
		}
		return false;
	}

	decltype(&NtQuerySystemInformation) NewwhNt32QuerySystemInformation = NULL;
	//wow64!whNT32ThunkProcessInformationEx:pvoid 64info boolean bExtendInfo pvoid 32info pulong maxinfosize
	NTSTATUS __fastcall whNT32ThunkProcessInformationEx(PVOID InSystemInformation, char a2, PVOID OutSystemInformation, PULONG ReturnLength);
	decltype(&whNT32ThunkProcessInformationEx) NewwhNT32ThunkProcessInformationEx = NULL;
	bool On_Cmd_NtQuerySystemInformation(SOCKET _socket, PVOID _packet, SIZE_T _packet_size)
	{
	
		auto pCmd = reinterpret_cast<_CMD_QUERY_SYSINFO_*>(_packet);
		ULONG ReturnLength = 0;
		unsigned long cbBuffer = pCmd->QuerySize+0x100;  //Initial Buffer Size	
		auto Buffer = malloc(cbBuffer);
		auto exit1 = std::experimental::make_scope_exit([&]() {
			if(Buffer)
				free(Buffer);
		});
		auto class_info = (NTDLL::SYSTEM_INFORMATION_CLASS)pCmd->InfoClass;
		if (Buffer == 0) return false;
		if (NewwhNt32QuerySystemInformation == NULL)
		{
			std::vector<magic::ptr_t> pOut;
			HMODULE wow64base = LoadLibrary(L"wow64.dll");
			::magic::PatternSearch pese({ 0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x20,0x41,0x8B,0x19 });
			pese.Search(wow64base, 0x20000, pOut, 0);
			NewwhNT32ThunkProcessInformationEx = (decltype(&whNT32ThunkProcessInformationEx))(pOut.front() - 15);
			DBG_PRINTA("NewwhNT32ThunkProcessInformationEx=%p\n", NewwhNT32ThunkProcessInformationEx);
		}
		bool x = false;
		bool error = false;
		auto ret = NTDLL::NtQuerySystemInformation((NTDLL::SYSTEM_INFORMATION_CLASS)pCmd->InfoClass, 
			Buffer,
			cbBuffer,
			&ReturnLength);
		DBG_PRINTA("ret==%lx cbBuffer==0x%lx ReturnLength==0x%lx 0x%p\n", ret, cbBuffer, ReturnLength, *(DWORD64*)Buffer);

		if (ret < 0)
		{
			//if (ret == STATUS_INFO_LENGTH_MISMATCH || ret==STATUS_BUFFER_TOO_SMALL)
			{
				auto packet = reinterpret_cast<PPACKET_CMD>(malloc(cbBuffer + sizeof(PACKET_CMD) + sizeof(RET_QUERY_SYSINFO)));
				auto exit2 = std::experimental::make_scope_exit([&]() {if (packet)free(packet);
				});
				if (!packet)
				{
					return false;
				}
				PRET_QUERY_SYSINFO pBuffer = (PRET_QUERY_SYSINFO)packet->Cmd;
				pBuffer->InfoSize = ReturnLength+0x10000;
				pBuffer->Status = ret;
				packet->dwCmd = RetQuerySysInfo;
				auto ret_read_packet = reinterpret_cast<PRET_READ>(packet->Cmd);
				auto client = CTcpSendRecv(_socket);
				auto b_send = client.write(packet, cbBuffer + sizeof(RET_QUERY_SYSINFO) + sizeof(PACKET_CMD));
				//(packet);
				return b_send;
			}
			//error = true;
		}

		if (error == false)
		{
			NTDLL::SYSTEM_PROCESSES_INFORMATION* p = (NTDLL::SYSTEM_PROCESSES_INFORMATION*)Buffer;
			SIZE_T i = 0, addpacketsize = 0x1000;
			while (i++)
			{
				addpacketsize = addpacketsize + (p->ImageName.Length * 2 + 4);
				if (p->NextEntryDelta == 0) break;
				p = (NTDLL::SYSTEM_PROCESSES_INFORMATION*)((unsigned char*)p + (p->NextEntryDelta));
			}
			p = (NTDLL::SYSTEM_PROCESSES_INFORMATION*)Buffer;
			auto packet = reinterpret_cast<PPACKET_CMD>(malloc(
				ReturnLength + sizeof(PACKET_CMD) + sizeof(RET_QUERY_SYSINFO) + addpacketsize));
			if (!packet) { DBG_PRINTA("内存分配失败");	return false; }
			auto pBuffer = (PRET_QUERY_SYSINFO)packet->Cmd;
			PVOID pB = pBuffer->Info;
			ULONG Length = cbBuffer;
			while (1)
			{
				CMD_UNICODE_STRING* pUtr = (CMD_UNICODE_STRING*)((unsigned char*)pB);//
				pUtr->Length = p->ImageName.Length;
				pUtr->MaximumLength = p->ImageName.MaximumLength;
				RtlCopyMemory(pUtr->Buffer, p->ImageName.Buffer, p->ImageName.Length);
				DBG_PRINTA(" %lx len=%lx %lx %ws\n", p->NextEntryDelta, pUtr->Length, pUtr->MaximumLength, pUtr->Buffer);
				PVOID pBinfo = pB = (PVOID)((unsigned char*)pB + p->ImageName.Length + 4);
				int ret = NewwhNT32ThunkProcessInformationEx((PVOID)p, 
					class_info == NTDLL::SystemExtendedProcessInformation ? 1 : 0
					, 
					&pBinfo,
					&Length);
				if (ret < 0 || *(DWORD *)pB == 0)
				{
					break;
				}
				pB = (PVOID)((unsigned char*)pB + *(DWORD*)pB);
				if (p->NextEntryDelta == 0)  break;
				p = (NTDLL::SYSTEM_PROCESSES_INFORMATION*)((unsigned char*)p + (p->NextEntryDelta));

			}
			pBuffer = (PRET_QUERY_SYSINFO)packet->Cmd;
			pBuffer->InfoSize = ReturnLength + addpacketsize;
			pBuffer->Status = ret;
			packet->dwCmd = RetQuerySysInfo;
			auto ret_read_packet = reinterpret_cast<PRET_READ>(packet->Cmd);
			auto client = CTcpSendRecv(_socket);
			auto b_send = client.write(packet, ReturnLength + addpacketsize + sizeof(RET_QUERY_SYSINFO) + sizeof(PACKET_CMD));
			free(packet);
			return b_send;
		}
		
		return false;
	}
	//////////////////////////////////////////////////////////////////////////
	NTSTATUS __fastcall whNtQueryInformationProcess(whNtQueryInformationProcessStruct * mystrcut);
	decltype(&whNtQueryInformationProcess)  pfnwhNtQueryInformationProcess = NULL;
	bool On_Cmd_QueryProcessInfo(SOCKET _socket, PVOID _packet, SIZE_T _packet_size)
	{
		auto pCmd = reinterpret_cast<_CMD_QUERY_PROCESSINFO_*>(_packet);
		unsigned long cbBuffer = pCmd->ProcessInformationLength;
		//void* Buffer = (void*)malloc(cbBuffer);
		auto packet = reinterpret_cast<PPACKET_CMD>(malloc(cbBuffer + sizeof(PACKET_CMD) + sizeof(_RET_QUERY_PROCESSINFO_)));
		auto exit1 = std::experimental::make_scope_exit([&]() {
			if (packet)
			{
				free(packet);
			}
		});
		if (!packet) return true;
		auto pRetBuffer = (PRET_QUERY_PROCESSINFO)packet->Cmd;

		if (pfnwhNtQueryInformationProcess == NULL)
		{
			PROCESS_BASIC_INFORMATION ProcessBasicInfo = { 0 };
			std::vector<magic::ptr_t> pOut;
			HMODULE wow64base = (HMODULE)LoadLibraryW(L"wow64.dll");// 0x74F60000; ////
																   //44 8B 49 0C 4C 63 11 44 8B 59 08 8B 59 10 BA 1C 00 00 00 44 3B C2
			::magic::PatternSearch pese({ 0x44,0x8B,0x49,0x0C,0x4C,0x63,0x11,0x44,0x8B,0x59,0x08,0x8B,0x59,0x10,0xBA,0x1C,0x00,0x00,0x00,0x44,0x3B,0xC2 });
			pese.Search(wow64base, 0x20000, pOut, 0);
			pfnwhNtQueryInformationProcess = (decltype(&whNtQueryInformationProcess))(pOut.front() - 15);
			DBG_PRINTA("pfnwhNtQueryInformationProcess=%p\n", pfnwhNtQueryInformationProcess);
		}

		auto Process = std::experimental::make_unique_resource(
			OpenProcess(PROCESS_ALL_ACCESS, false, pCmd->ProcessId), &CloseHandle);

		auto process_handle = Process.get();

		if (process_handle == INVALID_HANDLE_VALUE) { DBG_PRINTA("打开进程失败\n"); }
		ULONG ReturnLength = 0;
		//这里如果分配的内存超过32位，可能会GG
		PVOID ProcessInfo = new BYTE[pCmd->ProcessInformationLength];
		auto exit2 = std::experimental::make_scope_exit([&]() {
			if (ProcessInfo) { delete[] ProcessInfo; ProcessInfo = NULL; }
		});
		whNtQueryInformationProcessStruct mystrcut{ (DWORD32)process_handle,
			pCmd->ProcessInformationClass,
			(DWORD32)ProcessInfo,
			pCmd->ProcessInformationLength,
			(DWORD32)&ReturnLength };
		DBG_PRINTA("ProcessInfo=%p =%lx\n", ProcessInfo, process_handle);
		NTSTATUS Status = pfnwhNtQueryInformationProcess(&mystrcut);

		pRetBuffer->InfoSize = ReturnLength;
		pRetBuffer->Status = Status;
		packet->dwCmd = RetQueryProcessInfo;
		if (STATUS_SUCCESS == Status)
		{
			DBG_PRINTA("ProcessBasicInfo=%p\n", ProcessInfo);
			RtlCopyMemory(pRetBuffer->Info, ProcessInfo, ReturnLength);
			auto ret_read_packet = reinterpret_cast<PRET_READ>(packet->Cmd);
			auto client = CTcpSendRecv(_socket);
			auto b_send = client.write(packet, ReturnLength + sizeof(PRET_QUERY_SYSINFO) + sizeof(PACKET_CMD));
			//if (ProcessInfo) { delete[] ProcessInfo; ProcessInfo = NULL; }
			return b_send;
		}
		else
		{
			DBG_PRINTA("NtQueryFail:%lX,PEB:%p\n", Status, ProcessInfo);
		}
		//if (ProcessInfo) { delete[] ProcessInfo; ProcessInfo = NULL; }
		return true;
	}
	//////////////////////////////////////////////////////////////////////////
	/*bool on_cmd_query_sysinfo(SOCKET _socket, PVOID _packet, SIZE_T _packet_size)
	{
		auto pcmd = reinterpret_cast<PCMD_QUERY_SYSINFO>(_packet);
		auto alloc_size = pcmd->QuerySize;
		auto pInfoBuff = malloc(alloc_size);
		auto exit0 = std::experimental::make_scope_exit([&]() {
			if (pInfoBuff)free(pInfoBuff);
		});
		if(!pInfoBuff)
		{
			return false;
		}
		RtlZeroMemory(pInfoBuff, alloc_size);
		ULONG retLength = 0;
		auto ns = NTDLL::NtQuerySystemInformation(
			(NTDLL::SYSTEM_INFORMATION_CLASS)(pcmd->InfoClass),
			pInfoBuff, alloc_size, &retLength);
		
		auto new_size = sizeof(PACKET_CMD) + sizeof(RET_QUERY_SYSINFO) + alloc_size;
		auto p_buffer = malloc(new_size);
		auto exit1 = std::experimental::make_scope_exit([&]() {
			if (p_buffer)free(p_buffer);
		});
		if (!p_buffer)
		{
			return false;
		}
		RtlZeroMemory(p_buffer, new_size);
		auto ret_packet = reinterpret_cast<PPACKET_CMD>(p_buffer);
		auto ret_ = reinterpret_cast<PRET_QUERY_SYSINFO>(ret_packet->Cmd);
		ret_packet->dwCmd = RetQuerySysInfo;
		ret_->Status = ns;
		ret_->InfoSize = retLength;
		if (retLength)
		{
			RtlCopyMemory(ret_->Info, pInfoBuff, retLength);
		}
		auto client = CTcpSendRecv(_socket);
		auto b_send = client.write((LPCVOID)p_buffer, new_size);
		return b_send;
	}*/
//////////////////////////////////////////////////////////////////////////
	bool pfn_dop(SOCKET s)
	{
		auto client = CTcpSendRecv(s);
		auto pfn_do = [&]()
		{
			PVOID packet_buffer = nullptr;
			SIZE_T packet_size = 0;
			bool b_ret = false;
			do
			{
				auto packet_readed = client.read(&packet_buffer, &packet_size);
				if (!packet_readed)
				{
					//有问题退出
					break;
				}
				auto packet_test = reinterpret_cast<PPACKET_CMD>(packet_buffer);
				auto cmd_type = packet_test->dwCmd;
				if (cmd_type <= (DWORD)MinCmd
					|| cmd_type >= (DWORD)MaxCmd)
				{
					break;
				}
				auto _pfn = m_handler_packet[(PACKET_CMD_TYPE)cmd_type];
				auto p_ret = _pfn(s, PVOID(packet_test->Cmd), packet_size);
				if (!p_ret)
				{
					break;
				}
				b_ret = true;
			} while (false);
			if (packet_buffer)
			{
				delete[] packet_buffer;
			}
			return b_ret;
		};
		return pfn_do();
	}
	VOID client_handler(SOCKET s, sockaddr_in addr)
	{
		
		DBG_PRINTA("client %s:%d\r\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		do
		{
			__try
			{
				if (!pfn_dop(s))
				{
					break;
				}
			}
			__except (1)
			{
				DBG_PRINTA("Exception in DoFnc\r\n");
				break;
			}

		} while (1);

		shutdown(s, SD_BOTH);
		closesocket(s);
	}
	void init_srv()
	{
		for (int Type = MinCmd + 1; Type < MaxCmd; Type++)
		{
			m_handler_packet[(PACKET_CMD_TYPE)Type] = on_cmd_nothing;
		}

		m_handler_packet[CmdRead] = on_cmd_read;
		m_handler_packet[CmdWrite] = on_cmd_write;
		m_handler_packet[CmdCreateThread] = on_cmd_create_thread;
		m_handler_packet[CmdAlloc] = on_cmd_alloc;
		m_handler_packet[CmdProtect] = on_cmd_protect;
		m_handler_packet[CmdQuerySysInfo] = On_Cmd_NtQuerySystemInformation;
		m_handler_packet[CmdQueryProcessInfo] = On_Cmd_QueryProcessInfo;

		if (!is_socket_inited())
		{
			init_winsock();
		}
		//MessageBox(nullptr, _T("jjj"), _T("jjj2"), MB_OK);
		CSocketTcpServer srv;
		if (srv.init_server(2345, network::client_handler))
			srv.wait_for_clients();
	}
}
#endif