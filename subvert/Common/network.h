#pragma once
#include "common.h"
#include <WinSock2.h>
#include <windows.h>
#include <WS2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
bool init_winsock();
bool  is_socket_inited();

enum PACKET_CMD_TYPE
{
	//命令
	MinCmd=1,
	CmdRead,
	CmdWrite,
	CmdAlloc,
	CmdProtect,
	CmdCreateThread,
	CmdQueryEx,
	//返回命令
	RetRead,
	RetWrite,
	RetAlloc,
	RetProtect,
	RetCreateThread,
	RetQueryEx,
	//系统特殊命令
	CmdQuerySysInfo,
	RetQuerySysInfo,
	CmdQuerySysInfo64,
	RetQuerySysInfo64,
	//进程特殊
	CmdQueryProcessInfo,
	RetQueryProcessInfo,
	//线程特殊
	CmdQueryThreadInfo,
	RetQueryThreadInfo,
	//线程特殊
	CmdSuspendThread,
	CmdResumeThread,
	CmdGetThreadContext,
	RetGetThreadContext,
	CmdSetThreadContext,
	RetSetThreadContext,


	//最大
	MaxCmd,
};
#pragma pack(1)
typedef struct _PACKET_CMD_
{
	DWORD32 dwCmd;
	BYTE Cmd[1];
}PACKET_CMD,*PPACKET_CMD;
//读命令
typedef struct _CMD_READ_
{
	DWORD64 ProcessId;
	DWORD64 Address;
	DWORD64 Size;
}CMD_READ, *PCMD_READ;
//写命令
typedef struct _CMD_WRITE_
{
	DWORD64 ProcessId;
	DWORD64 Address;
	DWORD64 Size;
	BYTE WriteBuf[1];
}CMD_WRITE,*PCMD_WRITE;
//分配内存
typedef struct _CMD_ALLOC_
{
	DWORD64 ProcessId;
	DWORD64 BaseAddress;
	DWORD64 Size;
	DWORD ProtectType;
	DWORD flAllocationType;
}CMD_ALLOC,*PCMD_ALLOC;
//创建线程
typedef struct _CMD_THREAD_
{
	DWORD64 ProcessId;
	DWORD64 RoutineAddress;
	DWORD64 RoutineParam;
}CMD_THREAD,*PCMD_THREAD;
//修改内存属性
typedef struct _CMD_PROTECT_
{
	DWORD64 ProcessId;
	DWORD64 Address;
	DWORD64 Size;
	DWORD ProtectType;
}CMD_PROTECT,*PCMD_PROTECT;

//返回数据格式
//读返回
typedef struct _RET_READ_
{
	DWORD ReadRet;
	DWORD64 Size;
	BYTE data[1];
}RET_READ, *PRET_READ;
//写返回
typedef struct _RET_WRITE_
{
	DWORD64 WriteSize;
	DWORD WriteRetStatus;
}RET_WRITE,*PRET_WRITE;
//分配返回
typedef struct _RET_ALLOC_
{
	DWORD64 Address;
}RET_ALLOC,*PRET_ALLOC;
//修改属性返回
typedef struct _RET_PROTECT_
{
	DWORD OldProtect;
	BOOL bRet;
}RET_PROTECT,*PRET_PROTECT;
//创建线程返回
typedef struct _RET_THREAD_
{
	DWORD ExitCode;
	DWORD64 ThreadId;
}RET_THREAD, *PRET_THREAD;

//QuerySystemInformation的命令
typedef struct _CMD_QUERY_SYSINFO_
{
	DWORD InfoClass;
	DWORD QuerySize;
}CMD_QUERY_SYSINFO,*PCMD_QUERY_SYSINFO;
//QuerySystemInformation出来的数据返回
typedef struct _RET_QUERY_SYSINFO_
{
	LONG Status;
	DWORD InfoSize;
	BYTE Info[1];//这里我们返回的是一整个的QuerySystemInformation的数据
}RET_QUERY_SYSINFO,*PRET_QUERY_SYSINFO;

typedef struct CMD_UNICODE_STRING {
	USHORT    Length;     //UNICODE占用的内存字节数，个数*2；
	USHORT      MaximumLength;
	BYTE   Buffer[1];     //注意这里指针的问题
};

typedef struct CMD_NtQuerySystemInformation
{
	NTSTATUS status;
	NTDLL::SYSTEM_INFORMATION_CLASS SystemInformationClass;
	ULONG SystemInformationLength;
	PBYTE SystemInformation[1];
	PULONG ReturnLength;
};

typedef struct  whNtQueryInformationProcessStruct
{
	DWORD32 ProcessHandle;
	DWORD32 ProcessInformationClass;
	DWORD32 ProcessInformation;
	ULONG32 ProcessInformationLength;
	DWORD32 ReturnLength OPTIONAL;
};

typedef struct _CMD_QUERY_PROCESSINFO_
{
	DWORD64 ProcessId;
	DWORD32 ProcessInformationClass;
	//DWORD32 ProcessInformation;
	ULONG32 ProcessInformationLength;
	//DWORD32 ReturnLength OPTIONAL;
	//whNtQueryInformationProcessStruct QuerySruct;
}CMD_QUERY_PROCESSINFO, *PCMD_QUERY_PROCESSINFO;
typedef struct _RET_QUERY_PROCESSINFO_
{
	LONG32 Status;
	DWORD32 InfoSize;
	BYTE Info[1];
}RET_QUERY_PROCESSINFO, *PRET_QUERY_PROCESSINFO;

//VirtualQueryEx( _In_ HANDLE hProcess, _In_opt_ LPCVOID lpAddress, _Out_writes_bytes_to_(dwLength, return) PMEMORY_BASIC_INFORMATION lpBuffer, _In_ SIZE_T dwLength )
typedef struct CMD_QUERYEX_
{
	DWORD64 ProcessId;
	DWORD64 Address;
	DWORD64 Size;
}CMD_QUERYEX,*PCMD_QUERYEX;

typedef struct RET_QUERYEX
{
	DWORD64 Ret_Size;
	MEMORY_BASIC_INFORMATION64 info;
};
#pragma pack()
namespace network
{
	using packet_handler = std::function<bool(SOCKET, PVOID, SIZE_T)>;
	bool on_cmd_nothing(SOCKET _socket, PVOID _packet, SIZE_T _packet_size);
	bool on_cmd_read(SOCKET _socket, PVOID _packet, SIZE_T _packet_size);
	bool on_cmd_write(SOCKET _socket, PVOID _packet, SIZE_T _packet_size);
	bool on_cmd_create_thread(SOCKET _socket, PVOID _packet, SIZE_T _packet_size);
	bool On_Cmd_NtQuerySystemInformation(SOCKET _socket, PVOID _packet, SIZE_T _packet_size);
	bool on_cmd_setthreadcontext(SOCKET _socket, PVOID _packet, SIZE_T _packet_size);
	void init_srv();
}