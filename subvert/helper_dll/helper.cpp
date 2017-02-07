#include "stdafx.h"
#include "helper.h"
#include "../Common/HookEngine.h"
#include "../Common/native_class.h"

BOOL WINAPI OnWriteProcessMemory(
	_In_ HANDLE ProcessHandle,
	_In_ LPVOID BaseAddress,
	_In_reads_bytes_(nSize) LPCVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ SIZE_T * NumberOfBytesWritten
	);
using _WriteProcessMemory = BOOL(WINAPI*)(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpBaseAddress,
	_In_reads_bytes_(nSize) LPCVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T * lpNumberOfBytesWritten
	);
_WriteProcessMemory OldWriteProcessMemory = NULL;


BOOL
WINAPI
OnReadProcessMemory(
	_In_ HANDLE hProcess,
	_In_ LPCVOID lpBaseAddress,
	_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T * lpNumberOfBytesRead
	);
using _ReadProcessMemory = BOOL(WINAPI*)(
	_In_ HANDLE hProcess,
	_In_ LPCVOID lpBaseAddress,
	_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T * lpNumberOfBytesRead
	);
_ReadProcessMemory OldReadProcessMemory = nullptr;

HANDLE
WINAPI
OnOpenProcess(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwProcessId
	);
using _OpenProcess = HANDLE(WINAPI*)(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwProcessId
	);
_OpenProcess OldOpenProcess = nullptr;


HANDLE
WINAPI
OnCreateRemoteThread(
	_In_ HANDLE hProcess,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId
	);
using _CreateRemoteThread = HANDLE(WINAPI*)(
	_In_ HANDLE hProcess,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId
	);

_CreateRemoteThread OldCreateRemoteThread = nullptr;


LPVOID
WINAPI
OnVirtualAllocEx(
	_In_ HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
	);
using _VirtualAllocEx = LPVOID(WINAPI*)(
	_In_ HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
	);
_VirtualAllocEx OldVirtualAllocEx = nullptr;


BOOL
WINAPI
OnVirtualProtectEx(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect
	);
using _VirtualProtectEx = BOOL(WINAPI*)(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect
	);
_VirtualProtectEx OldVirtualProtectEx = nullptr;


NTSTATUS
NTAPI
OnNtQuerySystemInformation(
	IN NTDLL::SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);
using _NtQuerySystemInformation = NTSTATUS(NTAPI*)(
	IN NTDLL::_SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);
_NtQuerySystemInformation OldNtQuerySystemInformation = nullptr;


decltype(&NTDLL::NtOpenProcess) OldNtOpenProcess = nullptr;

NTSTATUS NTAPI OnNtOpenProcess(
	_Out_		PHANDLE ProcessHandle,
	_In_		ACCESS_MASK DesiredAccess,
	_In_		NTDLL::POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_	NTDLL::PCLIENT_ID ClientId
	);

decltype(&NTDLL::NtQueryInformationProcess) OldNtQueryInformationProcess = nullptr;

NTSTATUS NTAPI OnNtQueryInformationProcess(
	_In_		HANDLE ProcessHandle,
	_In_		NTDLL::PROCESSINFOCLASS ProcessInformationClass,
	_Out_		PVOID ProcessInformation,
	_In_		ULONG ProcessInformationLength,
	_Out_opt_	PULONG ReturnLength
	);


decltype(&NTDLL::NtReadVirtualMemory) OldNtReadVirtualMemory = nullptr;


NTSTATUS NTAPI OnNtReadVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_ PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead
	);


decltype(&ZwWriteVirtualMemory) OldZwWriteVirtualMemory = nullptr;

NTSTATUS
NTAPI
OnZwWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN ULONG BufferLength,
	OUT PULONG ReturnLength OPTIONAL);


decltype(&ZwProtectVirtualMemory) OldZwProtectVirtualMemory = nullptr;
NTSTATUS
NTAPI
OnZwProtectVirtualMemory(
	__in HANDLE ProcessHandle,
	__inout PVOID *BaseAddress,
	__inout PSIZE_T RegionSize,
	__in ULONG NewProtect,
	__out PULONG OldProtect
	);

typedef LONG(NTAPI *T_DbgUiIssueRemoteBreakin)(IN HANDLE ProcessHandle);
T_DbgUiIssueRemoteBreakin OldDbgUiIssueRemoteBreakin = nullptr;
LONG NTAPI OnDbgUiIssueRemoteBreakin(IN HANDLE ProcessHandle)
{
	DBG_PRINTA("INTO CREATE XXX %p\r\n",ProcessHandle);
#if 0
	auto ptr = VirtualAllocEx(ProcessHandle, nullptr, PAGE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (ptr)
	{
		DBG_PRINTA("alloc remote thread code = %p\r\n", ptr);
		UCHAR code[] = { 0xCC,0xC3 };
		SIZE_T dwSize = 0;
		WriteProcessMemory(ProcessHandle, ptr, code, sizeof(code), &dwSize);
		DWORD dwTid = 0;
		CreateRemoteThread(ProcessHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)ptr, nullptr, 0, &dwTid);
		if (dwTid)
		{
			DBG_PRINTA("find it\r\n");
		}
	}
#endif
	return 0;
	//return OldDbgUiIssueRemoteBreakin(ProcessHandle);
}

namespace helper
{
	const auto HANDLE_MASK = 0x08000000;

	const auto HOST_NAME = L"127.0.0.1";//服务器的地址，远程模式，局域网爽翻了
	const auto HOST_PORT = 2345;


	//QueryXXX的
	const auto HOST_PORT2 = 3456;//32位端口
	const auto HOST_NAME2 = L"127.0.0.1";//32位服务器

	HookEngine hook;

	typedef struct _HOOK_API_
	{
		TCHAR szModule[MAX_PATH];
		CHAR szApiName[MAX_PATH];
		PVOID NewFunction;
		PVOID *OldFunction;
	}HOOK_API, *PHOOK_API;


	std::map<HANDLE, DWORD64> m_processHandleToProcessId;
	bool is_handle_our(HANDLE _handle)
	{
		if ((DWORD32(_handle)&HANDLE_MASK))
			return true;
		if (m_processHandleToProcessId.find(_handle)!=m_processHandleToProcessId.end())
		{
			return true;
		}
		return false;
	}
	DWORD64 get_process_id(HANDLE _handle)
	{
		if (_handle == GetCurrentProcess())
		{
			return 0;
		}
		if (is_handle_our(_handle))
		{
			return m_processHandleToProcessId[_handle];
		}
		return 0;
	}
	bool map_pid_handle(DWORD64 ProcessId, PHANDLE _handle)
	{
		auto handleV = HANDLE(ProcessId | HANDLE_MASK);
		m_processHandleToProcessId[handleV] = ProcessId;
		*_handle = handleV;
		return true;
	}
	HANDLE send_cmd_createthead(DWORD64 ProcessId, PVOID ThreadRoutine, PVOID _param)
	{
		auto packet_size = sizeof(PACKET_CMD) + sizeof(CMD_THREAD);
		auto packet_buffer = malloc(packet_size);
		auto exit1 = std::experimental::make_scope_exit([&]() {
			if (packet_buffer)
			{
				free(packet_buffer);
			}
		});
		if (!packet_buffer)
		{
			return INVALID_HANDLE_VALUE;
		}
		RtlZeroMemory(packet_buffer, packet_size);

		auto packet = reinterpret_cast<PPACKET_CMD>(packet_buffer);
		auto cmdpkt = reinterpret_cast<PCMD_THREAD>(packet->Cmd);
		packet->dwCmd = CmdCreateThread;
		cmdpkt->ProcessId = ProcessId;
		cmdpkt->RoutineAddress = DWORD64(PtrToPtr64(ThreadRoutine));
		cmdpkt->RoutineParam = DWORD64(PtrToPtr64(_param));

		CSocketTcpClient tcp_clinet;
		if (tcp_clinet.Connect(HOST_NAME, HOST_PORT))
		{
			auto client = CTcpSendRecv(tcp_clinet.get());
			auto b_ret = client.write(packet_buffer, packet_size);
			if (b_ret)
			{
				PVOID ret_buffer = nullptr;
				SIZE_T ret_buffer_size = 0;
				b_ret = client.read(&ret_buffer, &ret_buffer_size);
				auto exit2 = std::experimental::make_scope_exit([&]() {
					if (ret_buffer)
					{
						delete[] ret_buffer;
					}
				});
				if (b_ret)
				{
					auto ret_packet = reinterpret_cast<PPACKET_CMD>(ret_buffer);
					auto ret_cmd = reinterpret_cast<PRET_THREAD>(ret_packet->Cmd);
					if (ret_packet->dwCmd == RetCreateThread)
					{
						return HANDLE(ret_cmd->ThreadId);
					}
				}
			}
		}
		return INVALID_HANDLE_VALUE;
	}
	bool send_cmd_write(DWORD64 ProcessId,
		PVOID Address,
		PVOID inBuffer,
		SIZE_T toWriteSize,
		PSIZE_T pRetWriteSize)
	{
		if (pRetWriteSize)
		{
			*pRetWriteSize = 0;
		}
		auto packet_size = sizeof(PACKET_CMD) + sizeof(CMD_WRITE) + toWriteSize;
		auto packet_buffer = malloc(packet_size);
		auto exit1 = std::experimental::make_scope_exit([&]() {
			if (packet_buffer)
			{
				free(packet_buffer);
			}
		});
		if (!packet_buffer)
		{
			return false;
		}
		RtlZeroMemory(packet_buffer, packet_size);
		auto packet = reinterpret_cast<PPACKET_CMD>(packet_buffer);
		auto cmdpkt = reinterpret_cast<PCMD_WRITE>(packet->Cmd);
		packet->dwCmd = CmdWrite;
		cmdpkt->Address = DWORD64(PtrToPtr64(Address));
		cmdpkt->ProcessId = ProcessId;
		cmdpkt->Size = toWriteSize;
		RtlCopyMemory(cmdpkt->WriteBuf, inBuffer, toWriteSize);
		CSocketTcpClient tcp_clinet;
		if (tcp_clinet.Connect(HOST_NAME, HOST_PORT))
		{
			auto client = CTcpSendRecv(tcp_clinet.get());
			auto b_ret = client.write(packet_buffer, packet_size);
			if (b_ret)
			{
				DBG_PRINTA("Send CmdWrite OK\r\n");
				PVOID ret_buffer = nullptr;
				SIZE_T ret_buffer_size = 0;
				b_ret = client.read(&ret_buffer, &ret_buffer_size);
				auto exit2 = std::experimental::make_scope_exit([&]() {
					if (ret_buffer)
					{
						delete[] ret_buffer;
					}
				});
				if (b_ret)
				{
					auto ret_packet = reinterpret_cast<PPACKET_CMD>(ret_buffer);
					auto ret_cmd = reinterpret_cast<PRET_WRITE>(ret_packet->Cmd);
					DBG_PRINTA("Recv RetPacket OK\r\n");
					if (ret_packet->dwCmd == RetWrite)
					{
						if (ret_cmd->WriteRetStatus == 1
							&& ret_cmd->WriteSize != 0)
						{
							//RtlCopyMemory(outBuffer, ret_cmd->data, ret_cmd->Size);
							if (pRetWriteSize)
								*pRetWriteSize = ret_cmd->WriteSize;
							return true;
						}
					}
				}
			}
		}
		return false;
	}
	bool send_cmd_read(DWORD64 ProcessId, PVOID Address, PVOID outBuffer, SIZE_T toReadSize, PSIZE_T pRetReadSize)
	{
		if (pRetReadSize)
			*pRetReadSize = 0;

		auto packet_size = sizeof(PACKET_CMD) + sizeof(CMD_READ);
		auto packet_buffer = malloc(packet_size);
		auto exit1 = std::experimental::make_scope_exit([&]() {
			if (packet_buffer)
			{
				free(packet_buffer);
			}
		});
		if (!packet_buffer)
		{
			return false;
		}
		RtlZeroMemory(packet_buffer, packet_size);
		auto packet = reinterpret_cast<PPACKET_CMD>(packet_buffer);
		auto cmdpkt = reinterpret_cast<PCMD_READ>(packet->Cmd);
		packet->dwCmd = CmdRead;
		cmdpkt->Address = DWORD64(PtrToPtr64(Address));
		cmdpkt->ProcessId = ProcessId;
		cmdpkt->Size = toReadSize;

		CSocketTcpClient tcp_clinet;
		if (tcp_clinet.Connect(HOST_NAME, HOST_PORT))
		{
			auto client = CTcpSendRecv(tcp_clinet.get());
			auto b_ret = client.write(packet_buffer, packet_size);
			if (b_ret)
			{
				PVOID ret_buffer = nullptr;
				SIZE_T ret_buffer_size = 0;
				b_ret = client.read(&ret_buffer, &ret_buffer_size);
				auto exit2 = std::experimental::make_scope_exit([&]() {
					if (ret_buffer)
					{
						delete[] ret_buffer;
					}
				});
				if (b_ret)
				{
					auto ret_packet = reinterpret_cast<PPACKET_CMD>(ret_buffer);
					auto ret_cmd = reinterpret_cast<PRET_READ>(ret_packet->Cmd);
					if (ret_packet->dwCmd == RetRead)
					{
						if (ret_cmd->ReadRet == 1
							&& ret_cmd->Size != 0)
						{
							RtlCopyMemory(outBuffer, ret_cmd->data, ret_cmd->Size);
							if (pRetReadSize)
								*pRetReadSize = ret_cmd->Size;
							return true;
						}
					}
				}
			}
		}
		return false;
	}
	LPVOID send_cmd_allocate(DWORD64 ProcessId,
		PVOID BaseAddress,
		SIZE_T Size,
		DWORD flAllocationType,
		DWORD flProtectType)
	{
		auto packet_size = sizeof(PACKET_CMD) + sizeof(CMD_ALLOC);
		auto packet_buffer = malloc(packet_size);
		auto exit1 = std::experimental::make_scope_exit([&]() {
			if (packet_buffer)
			{
				free(packet_buffer);
			}
		});
		if (!packet_buffer)
		{
			return nullptr;
		}
		RtlZeroMemory(packet_buffer, packet_size);
		auto packet = reinterpret_cast<PPACKET_CMD>(packet_buffer);
		auto cmdpkt = reinterpret_cast<PCMD_ALLOC>(packet->Cmd);

		packet->dwCmd = CmdAlloc;
		cmdpkt->BaseAddress = DWORD64(PtrToPtr64(BaseAddress));
		cmdpkt->flAllocationType = flAllocationType;
		cmdpkt->ProtectType = flProtectType;
		cmdpkt->Size = Size;
		cmdpkt->ProcessId = ProcessId;

		CSocketTcpClient tcp_clinet;
		if (tcp_clinet.Connect(HOST_NAME, HOST_PORT))
		{
			auto client = CTcpSendRecv(tcp_clinet.get());
			auto b_ret = client.write(packet_buffer, packet_size);
			if (b_ret)
			{

				PVOID ret_buffer = nullptr;
				SIZE_T ret_buffer_size = 0;
				b_ret = client.read(&ret_buffer, &ret_buffer_size);
				auto exit2 = std::experimental::make_scope_exit([&]() {
					if (ret_buffer)
					{
						delete[] ret_buffer;
					}
				});
				if (b_ret)
				{
					auto ret_packet = reinterpret_cast<PPACKET_CMD>(ret_buffer);
					auto ret_cmd = reinterpret_cast<PRET_ALLOC>(ret_packet->Cmd);
					if (ret_packet->dwCmd == RetAlloc)
					{
						return PVOID(ret_cmd->Address);
					}
				}
			}
		}
		return nullptr;
	}
	BOOL send_cmd_protect(DWORD64 ProcessId, PVOID Address, SIZE_T Size, DWORD flNewProtect, PDWORD lpOldProtect)
	{
		if (lpOldProtect)
		{
			*lpOldProtect = 0;
		}
		auto packet_size = sizeof(PACKET_CMD) + sizeof(CMD_PROTECT);
		auto packet_buffer = malloc(packet_size);
		auto exit1 = std::experimental::make_scope_exit([&]() {
			if (packet_buffer)
			{
				free(packet_buffer);
			}
		});
		if (!packet_buffer)
		{
			return FALSE;
		}
		RtlZeroMemory(packet_buffer, packet_size);
		auto packet = reinterpret_cast<PPACKET_CMD>(packet_buffer);
		auto cmdpkt = reinterpret_cast<PCMD_PROTECT>(packet->Cmd);
		packet->dwCmd = CmdProtect;
		cmdpkt->Address = DWORD64(PtrToPtr64(Address));
		cmdpkt->ProcessId = ProcessId;
		cmdpkt->ProtectType = flNewProtect;
		cmdpkt->Size = Size;

		CSocketTcpClient tcp_clinet;
		if (tcp_clinet.Connect(HOST_NAME, HOST_PORT))
		{
			auto client = CTcpSendRecv(tcp_clinet.get());
			auto b_ret = client.write(packet_buffer, packet_size);
			if (b_ret)
			{
				PVOID ret_buffer = nullptr;
				SIZE_T ret_buffer_size = 0;
				b_ret = client.read(&ret_buffer, &ret_buffer_size);
				auto exit2 = std::experimental::make_scope_exit([&]() {
					if (ret_buffer)
					{
						delete[] ret_buffer;
					}
				});
				if (b_ret)
				{
					auto ret_packet = reinterpret_cast<PPACKET_CMD>(ret_buffer);
					auto ret_cmd = reinterpret_cast<PRET_PROTECT>(ret_packet->Cmd);
					if (ret_packet->dwCmd == RetProtect)
					{
						if (lpOldProtect)
						{
							*lpOldProtect = ret_cmd->OldProtect;
						}
						return ret_cmd->bRet;
					}
				}
			}
		}
		return FALSE;
	}
	bool send_cmd_CmdQuerySysInfo(DWORD InfoClass, DWORD &QuerySize, PVOID outBuffer, NTSTATUS &Status)
	{
		auto packet_size = sizeof(PACKET_CMD) + sizeof(CMD_READ);
		auto packet_buffer = malloc(packet_size);
		auto exit1 = std::experimental::make_scope_exit([&]() {
			if (packet_buffer)
			{
				free(packet_buffer);
			}
		});
		if (!packet_buffer)
		{
			return false;
		}
		RtlZeroMemory(packet_buffer, packet_size);
		auto packet = reinterpret_cast<PPACKET_CMD>(packet_buffer);
		auto cmdpkt = reinterpret_cast<PCMD_QUERY_SYSINFO>(packet->Cmd);
		packet->dwCmd = CmdQuerySysInfo;
		cmdpkt->QuerySize = QuerySize;
		cmdpkt->InfoClass = InfoClass;

		CSocketTcpClient tcp_clinet;
		if (tcp_clinet.Connect(HOST_NAME, HOST_PORT))
		{
			auto client = CTcpSendRecv(tcp_clinet.get());
			auto b_ret = client.write(packet_buffer, packet_size);
			if (b_ret)
			{
				PVOID ret_buffer = nullptr;
				SIZE_T ret_buffer_size = 0;
				b_ret = client.read(&ret_buffer, &ret_buffer_size);
				auto exit2 = std::experimental::make_scope_exit([&]() {
					if (ret_buffer)
					{
						delete[] ret_buffer;
					}
				});
				if (b_ret)
				{
					auto ret_packet = reinterpret_cast<PPACKET_CMD>(ret_buffer);
					auto retinfo = reinterpret_cast<PRET_QUERY_SYSINFO>(ret_packet->Cmd);
					if (ret_packet->dwCmd == RetQuerySysInfo)
					{
						Status = retinfo->Status;
						if (Status >= 0 && QuerySize >= retinfo->InfoSize)
						{
							NTDLL::SYSTEM_PROCESSES_INFORMATION* p = (NTDLL::SYSTEM_PROCESSES_INFORMATION*)retinfo->Info;
							NTDLL::SYSTEM_PROCESSES_INFORMATION* pOut = (NTDLL::SYSTEM_PROCESSES_INFORMATION*)outBuffer;
							auto total_cpy = 0;
							while (1)
							{
								auto pUstr = (CMD_UNICODE_STRING*)((unsigned char*)p);
								auto pinfo = (NTDLL::SYSTEM_PROCESSES_INFORMATION*)((unsigned char*)p + pUstr->Length + 4);
								DBG_PRINTA("Next=%d\r\n", pinfo->NextEntryDelta);
								RtlInitUnicodeString((PUNICODE_STRING)&pinfo->ImageName, (PCWSTR)pUstr->Buffer);
								DBG_PRINTA("IMAGE1 len=%lx %lx %ws\n", pUstr->Length, pUstr->MaximumLength, pUstr->Buffer);

								auto copysize = pinfo->NextEntryDelta == 0 ? retinfo->InfoSize - total_cpy - pUstr->Length - 4 : pinfo->NextEntryDelta;
								RtlCopyMemory(pOut, pinfo, copysize);

								auto pusrbuffer = (PUCHAR)pOut + copysize;
								RtlCopyMemory(pusrbuffer, pUstr, pUstr->Length + 4);
								auto pUstr2 = (CMD_UNICODE_STRING*)(pusrbuffer);
								RtlInitUnicodeString((PUNICODE_STRING)&pOut->ImageName, (PCWSTR)pUstr2->Buffer);
								pOut->NextEntryDelta += pUstr->Length + 4;
								DBG_PRINTA("IMAGE2 len=%lx %lx %ws\n", pUstr2->Length, pUstr2->MaximumLength, pUstr2->Buffer);


								if (pinfo->NextEntryDelta == 0)
								{
									pOut->NextEntryDelta = 0;
									break;
								}
								total_cpy += pOut->NextEntryDelta;

								p = (NTDLL::SYSTEM_PROCESSES_INFORMATION*)((PUCHAR)pinfo + pinfo->NextEntryDelta);
								pOut = (NTDLL::SYSTEM_PROCESSES_INFORMATION*)((unsigned char*)pOut + pOut->NextEntryDelta);
							}
						}
						QuerySize = retinfo->InfoSize;
						return true;
					}
				}
			}
		}
		return false;
	}

	NTSTATUS send_cmd_query_process_info(DWORD64 processId,
		NTDLL::PROCESSINFOCLASS InfoClass,
		PVOID InfoBuffer,
		ULONG InfoSize,
		PULONG RetSize)
	{
		auto packet_size = sizeof(PACKET_CMD) + sizeof(CMD_QUERY_PROCESSINFO);
		auto packet_buffer = malloc(packet_size);
		auto exit1 = std::experimental::make_scope_exit([&]() {if (packet_buffer)free(packet_buffer); });
		if (!packet_buffer)
			return false;

		RtlZeroMemory(packet_buffer, packet_size);
		auto packet = reinterpret_cast<PPACKET_CMD>(packet_buffer);
		auto cmdpkt = reinterpret_cast<PCMD_QUERY_PROCESSINFO>(packet->Cmd);

		packet->dwCmd = CmdQueryProcessInfo;
		cmdpkt->ProcessInformationLength = InfoSize;
		cmdpkt->ProcessInformationClass = InfoClass;
		cmdpkt->ProcessId = processId;
		CSocketTcpClient tcp_clinet;
		if (tcp_clinet.Connect(HOST_NAME, HOST_PORT))
		{
			auto client = CTcpSendRecv(tcp_clinet.get());
			auto b_ret = client.write(packet_buffer, packet_size);
			if (b_ret)
			{
				PVOID ret_buffer = nullptr;
				SIZE_T ret_buffer_size = 0;
				b_ret = client.read(&ret_buffer, &ret_buffer_size);
				auto exit2 = std::experimental::make_scope_exit([&]() {
					if (ret_buffer)delete[] ret_buffer;
				});
				if (b_ret)
				{
					auto ret_packet = reinterpret_cast<PPACKET_CMD>(ret_buffer);
					auto retinfo = reinterpret_cast<PRET_QUERY_PROCESSINFO>(ret_packet->Cmd);
					if (ret_packet->dwCmd == RetQueryProcessInfo)
					{
						NTSTATUS Status = (NTSTATUS)retinfo->Status;
						if (Status == STATUS_SUCCESS)
						{
							auto pBasicInfo = (PROCESS_BASIC_INFORMATION*)(retinfo->Info);
							if (InfoClass == NTDLL::ProcessBasicInformation)
								DBG_PRINTA("Status=%lx retinfoInfoSize=%lx id=%ld peb=%p\r\n", Status, retinfo->InfoSize, pBasicInfo->UniqueProcessId, pBasicInfo->PebBaseAddress);
							RtlCopyMemory(InfoBuffer, retinfo->Info, retinfo->InfoSize);

						}
						if (RetSize) *RetSize = retinfo->InfoSize;
						return Status;
					}
				}
			}
		}
		return STATUS_UNSUCCESSFUL;
	}

	//NTSTATUS send_cmd_query_sysinfo(
	//	IN NTDLL::SYSTEM_INFORMATION_CLASS SystemInformationClass,
	//	OUT PVOID SystemInformation,
	//	IN ULONG SystemInformationLength,
	//	OUT PULONG ReturnLength OPTIONAL)
	//{
	//	if (ReturnLength)
	//	{
	//		*ReturnLength = 0;
	//	}
	//	auto packet_size = sizeof(PACKET_CMD) + sizeof(CMD_QUERY_SYSINFO);
	//	auto packet_buffer = malloc(packet_size);
	//	auto exit1 = std::experimental::make_scope_exit([&]() {
	//		if (packet_buffer)
	//		{
	//			free(packet_buffer);
	//		}
	//	});
	//	if (!packet_buffer)
	//	{
	//		return STATUS_MEMORY_NOT_ALLOCATED;
	//	}
	//	RtlZeroMemory(packet_buffer, packet_size);
	//	auto packet = reinterpret_cast<PPACKET_CMD>(packet_buffer);
	//	auto cmdpkt = reinterpret_cast<PCMD_QUERY_SYSINFO>(packet->Cmd);
	//	packet->dwCmd = CmdQuerySysInfo;
	//	cmdpkt->InfoClass = SystemInformationClass;
	//	cmdpkt->QuerySize = SystemInformationLength;
	//	DBG_PRINTA("packet OK\r\n");
	//	CSocketTcpClient tcp_clinet;
	//	if (tcp_clinet.Connect(HOST_NAME, HOST_PORT))
	//	{
	//		auto client = CTcpSendRecv(tcp_clinet.get());
	//		auto b_ret = client.write(packet_buffer, packet_size);
	//		if (b_ret)
	//		{
	//			DBG_PRINTA("Send OK\r\n");
	//			PVOID ret_buffer = nullptr;
	//			SIZE_T ret_buffer_size = 0;
	//			b_ret = client.read(&ret_buffer, &ret_buffer_size);
	//			auto exit2 = std::experimental::make_scope_exit([&]() {
	//				if (ret_buffer)
	//				{
	//					delete[] ret_buffer;
	//				}
	//			});
	//			if (b_ret)
	//			{
	//				DBG_PRINTA("Recv OK\r\n");
	//				auto ret_packet = reinterpret_cast<PPACKET_CMD>(ret_buffer);
	//				auto ret_cmd = reinterpret_cast<PRET_QUERY_SYSINFO>(ret_packet->Cmd);
	//				if (ret_packet->dwCmd == RetQuerySysInfo)
	//				{
	//					//枚举进程这里有个问题32位进程的数据和64位进程的数据结构不同
	//					//此时需要人工转

	//					auto ns = (NTSTATUS)ret_cmd->Status;
	//					if (NT_SUCCESS(ns))
	//					{
	//						RtlCopyMemory(SystemInformation, ret_cmd->Info, ret_cmd->InfoSize);
	//					}
	//					if (ReturnLength)
	//					{
	//						*ReturnLength = ret_cmd->InfoSize;
	//					}
	//					return ns;
	//				}
	//			}
	//		}
	//	}
	//	return STATUS_UNSUCCESSFUL;
	//}
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	VOID installHook(
		PHOOK_API mHook,
		UINT32 nCount)
	{
		UINT32 idx = 0;
		for (idx = 0; idx < nCount; idx++)
		{
			DBG_PRINTA("%s %ws\r\n", mHook[idx].szApiName, mHook[idx].szModule);
			HMODULE hm = GetModuleHandle(mHook[idx].szModule);
			if (hm)
			{
				void *pfunc = (void *)GetProcAddress(hm, mHook[idx].szApiName);
				if (pfunc)
				{

					hook.hook_function(pfunc,
						mHook[idx].NewFunction,
						mHook[idx].OldFunction, IsX64() ? HookEngine::INT3_HOOK : HookEngine::JMP_HOOK);
				}
			}
		}
	}

	HOOK_API m_hook[] = {
		{
			TEXT("kernelbase.dll"),
			"WriteProcessMemory",
			(void*)OnWriteProcessMemory,
			(void**)&OldWriteProcessMemory
		},
		{
			TEXT("kernelbase.dll"),
			"ReadProcessMemory",
			(void*)OnReadProcessMemory,
			(void**)&OldReadProcessMemory
		},
		{
			TEXT("kernelbase.dll"),
			"OpenProcess",
			(void*)OnOpenProcess,
			(void**)&OldOpenProcess
		},
		{
			TEXT("kernel32.dll"),
			"CreateRemoteThread",
			(void*)OnCreateRemoteThread,
			(void**)&OldCreateRemoteThread
		},
		{
			TEXT("kernelbase.dll"),
			"VirtualAllocEx",
			(void*)OnVirtualAllocEx,
			(void**)&OldVirtualAllocEx
		},
		{
			TEXT("kernelbase.dll"),
			"VirtualProtectEx",
			(void*)OnVirtualProtectEx,
			(void**)&OldVirtualProtectEx
		},
		{
			TEXT("ntdll.dll"),
			"NtQuerySystemInformation",
			(void*)OnNtQuerySystemInformation,
			(void**)&OldNtQuerySystemInformation
		},
		{
			TEXT("ntdll.dll"),
			"NtOpenProcess",
			(void*)OnNtOpenProcess,
			(void**)&OldNtOpenProcess
		},
		{
			TEXT("ntdll.dll"),
			"NtQueryInformationProcess",
			(void*)OnNtQueryInformationProcess,
			(void**)&OldNtQueryInformationProcess
		},
		{
			TEXT("ntdll.dll"),
			"NtReadVirtualMemory",
			(void*)OnNtReadVirtualMemory,
			(void**)&OldNtReadVirtualMemory
		},
		{
			TEXT("ntdll.dll"),
			"ZwWriteVirtualMemory",
			(void*)OnZwWriteVirtualMemory,
			(void**)&OldZwWriteVirtualMemory
		},
		{
			TEXT("ntdll.dll"),
			"ZwProtectVirtualMemory",
			(void*)OnZwProtectVirtualMemory,
			(void**)&OldZwProtectVirtualMemory
		},
		{
			TEXT("ntdll.dll"),
			"DbgUiIssueRemoteBreakin",
			(void *)OnDbgUiIssueRemoteBreakin,
			(void **)&OldDbgUiIssueRemoteBreakin
		},
	};

	void init()
	{
		//ReadProcessMemory()
		//OpenProcess
		//CreateRemoteThread
		//VirtualAllocEx()
		//VirtualProtectEx()
		//第一个版本就这么简单的
		//hook OpenProcess
		//hook ReadProcessMemory
		//hook WriteProcessMemory
		//hook CreateRemoteThread
		//hook VirtualAllocEx
		//hook VirtualProtectEx
		//TODO:
		//hook NtQuerySystemInformation -->进程枚举使用的
		//NtQuerySystemInformation
		//hook NtOpenProcess
		//hook 
		native::get_all_privilege();
		DBG_PRINTA("HelperBegin\r\n");
		installHook(m_hook, ARRAYSIZE(m_hook));
		DBG_PRINTA("HelperEnd\r\n");
	}
};

BOOL WINAPI OnWriteProcessMemory(
	_In_ HANDLE ProcessHandle,
	_In_ LPVOID BaseAddress,
	_In_reads_bytes_(nSize) LPCVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ SIZE_T * NumberOfBytesWritten
	)
{
	DBG_PRINTA("OnWriteProcessMemory\r\n");
	auto pid = helper::get_process_id(ProcessHandle);
	if (pid == 0)
	{
		return OldWriteProcessMemory(ProcessHandle,
			BaseAddress,
			Buffer,
			BufferSize,
			NumberOfBytesWritten);
	}
	DBG_PRINTA("WriteToRemoteServer\r\n");
	return helper::send_cmd_write(pid,
		BaseAddress,
		(PVOID)Buffer,
		BufferSize,
		NumberOfBytesWritten);

}

BOOL
WINAPI
OnReadProcessMemory(
	_In_ HANDLE hProcess,
	_In_ LPCVOID lpBaseAddress,
	_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T * lpNumberOfBytesRead
	)
{
	DBG_PRINTA("OnReadProcessMemory\r\n");
	auto pid = helper::get_process_id(hProcess);
	if (pid == 0)
	{
		return OldReadProcessMemory(hProcess,
			lpBaseAddress,
			lpBuffer,
			nSize,
			lpNumberOfBytesRead);
	}
	DBG_PRINTA("ReadFromRemoteServer\r\n");
	return helper::send_cmd_read(pid,
		(PVOID)lpBaseAddress,
		lpBuffer,
		nSize,
		lpNumberOfBytesRead);
}

HANDLE
WINAPI
OnOpenProcess(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwProcessId
	)
{
	//在非本机上只有样和谐
	HANDLE _handle = 0;
	{
		if (helper::map_pid_handle(DWORD64(dwProcessId), &_handle))
		{
			return _handle;
		}
	}
	return INVALID_HANDLE_VALUE;
}

HANDLE
WINAPI
OnCreateRemoteThread(
	_In_ HANDLE hProcess,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId
	)
{
	auto pid = helper::get_process_id(hProcess);
	if (pid != 0)
	{
//TODO:Fix Bug At RetTID!!
		return helper::send_cmd_createthead(pid,
			lpStartAddress,
			lpParameter);
	}
	return OldCreateRemoteThread(hProcess,
		lpThreadAttributes,
		dwStackSize,
		lpStartAddress,
		lpParameter,
		dwCreationFlags,
		lpThreadId);
}

LPVOID
WINAPI
OnVirtualAllocEx(
	_In_ HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
	)
{
	DBG_PRINTA("Alloc\r\n");
	auto pid = helper::get_process_id(hProcess);
	if (pid != 0)
	{
		return helper::send_cmd_allocate(pid, lpAddress, dwSize, flAllocationType, flProtect);
	}
	return OldVirtualAllocEx(hProcess,
		lpAddress,
		dwSize,
		flAllocationType,
		flProtect);
}

BOOL
WINAPI
OnVirtualProtectEx(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect
	)
{
	auto pid = helper::get_process_id(hProcess);
	if (pid != 0)
	{
		return helper::send_cmd_protect(pid, lpAddress, dwSize, flNewProtect, lpflOldProtect);
	}
	return OldVirtualProtectEx(hProcess,
		lpAddress,
		dwSize,
		flNewProtect,
		lpflOldProtect);
}

NTSTATUS
NTAPI
OnNtQuerySystemInformation(
	IN NTDLL::SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	)
{
	DBG_PRINTA("Query = %d\r\n", SystemInformationClass);
	if (SystemInformationClass != NTDLL::SystemProcessInformation
		&&SystemInformationClass !=
		NTDLL::SystemExtendedProcessInformation)
	{
		goto END;
	}
	DBG_PRINTA("Begin\r\n");
	NTSTATUS  Status = 0;
	DWORD QuerySize = SystemInformationLength;
	auto iret = helper::send_cmd_CmdQuerySysInfo(SystemInformationClass, QuerySize, SystemInformation, Status);
	DBG_PRINTA("iret=%lx %lx  %lx %p\n", iret, QuerySize, Status, SystemInformation);
	DBG_PRINTA("END QUERY\r\n");
	if (iret) {
		if (ReturnLength)
			*ReturnLength = QuerySize;
		return Status;
	}
END:
	auto ns = OldNtQuerySystemInformation(SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength);
	return ns;
}


NTSTATUS NTAPI OnNtOpenProcess(
	_Out_		PHANDLE ProcessHandle,
	_In_		ACCESS_MASK DesiredAccess,
	_In_		NTDLL::POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_	NTDLL::PCLIENT_ID ClientId
	)
{

	__try
	{
		if (ClientId)
		{
#if defined(PLUGINS)
			auto dd = DWORD64(ClientId->UniqueProcess);
			auto ns = OldNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
			if (ns == STATUS_SUCCESS)
			{
				DBG_PRINTA("Open Ok\r\n");
				helper::m_processHandleToProcessId[*ProcessHandle] = dd;
				return ns;
			}
#else
			auto processid = ClientId->UniqueProcess;
			HANDLE _handle = nullptr;
			if (helper::map_pid_handle(DWORD64(processid), &_handle))
			{
				*ProcessHandle = _handle;
				DBG_PRINTA("NtOpenProcess OK\r\n");
				return STATUS_SUCCESS;
			}
#endif
		}
	}
	__except (1)
	{

	}

	return OldNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS NTAPI OnNtQueryInformationProcess(
	_In_		HANDLE ProcessHandle,
	_In_		NTDLL::PROCESSINFOCLASS ProcessInformationClass,
	_Out_		PVOID ProcessInformation,
	_In_		ULONG ProcessInformationLength,
	_Out_opt_	PULONG ReturnLength
	)
{
	NTSTATUS ns = STATUS_UNSUCCESSFUL;
	//DBG_PRINTA("QueryProcessInfo\r\n");
	auto pid = helper::get_process_id(ProcessHandle);
	if (pid)
	{
		DBG_PRINTA("QueryProcessInfo\r\n");
		ns = helper::send_cmd_query_process_info(pid, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
		if (NT_SUCCESS(ns))
		{
			DBG_PRINTA("QueryProcessInfo OK\r\n");
			return ns;
		}
	}
	ns = OldNtQueryInformationProcess(
		ProcessHandle,
		ProcessInformationClass,
		ProcessInformation,
		ProcessInformationLength,
		ReturnLength);
	return ns;
}

NTSTATUS NTAPI OnNtReadVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_ PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead
	)
{
	NTSTATUS ns = STATUS_UNSUCCESSFUL;
	auto pid = helper::get_process_id(ProcessHandle);
	if (pid)
	{
		DBG_PRINTA("ToRead Pid=%llu Base = %p Size = %x\r\n", pid, BaseAddress, BufferSize);
		auto b = helper::send_cmd_read(pid, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
		if (b)
		{
			return STATUS_SUCCESS;
		}
	}
	ns = OldNtReadVirtualMemory(ProcessHandle,
		BaseAddress,
		Buffer,
		BufferSize,
		NumberOfBytesRead);
	return ns;
}

NTSTATUS
NTAPI
OnZwWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN ULONG BufferLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	auto pid = helper::get_process_id(ProcessHandle);
	if (pid)
	{
		auto b = helper::send_cmd_write(pid, BaseAddress, Buffer, BufferLength, ReturnLength);
		if (b)
		{
			return STATUS_SUCCESS;
		}
	}
	return OldZwWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
}

NTSTATUS
NTAPI
OnZwProtectVirtualMemory(
	__in HANDLE ProcessHandle,
	__inout PVOID *BaseAddress,
	__inout PSIZE_T RegionSize,
	__in ULONG NewProtect,
	__out PULONG OldProtect
	)
{
	__try
	{
		auto pid = helper::get_process_id(ProcessHandle);
		if (pid)
		{
			auto b = helper::send_cmd_protect(pid, *BaseAddress, *RegionSize, NewProtect, OldProtect);
			if (b)
			{
				return STATUS_SUCCESS;
			}
		}
	}
	__except (1)
	{

	}
	return OldZwProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}