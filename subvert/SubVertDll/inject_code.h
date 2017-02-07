#pragma once
#include "../Common/common.h"
namespace inject
{
	static unsigned long GetMainThreadId(unsigned long ProcessId)
	{
		unsigned long cbBuffer = 0x5000;  //Initial Buffer Size
		void* Buffer = (void*)LocalAlloc(0, cbBuffer);
		if (Buffer == 0) return 0;
		bool x = false;
		bool error = false;
		while (x == false)
		{
			int ret = NTDLL::NtQuerySystemInformation(NTDLL::SystemExtendedProcessInformation, Buffer, cbBuffer, 0);
			if (ret < 0)
			{
				if (ret == STATUS_INFO_LENGTH_MISMATCH)
				{
					cbBuffer = cbBuffer + cbBuffer;
					LocalFree(Buffer);
					Buffer = (void*)LocalAlloc(0, cbBuffer);
					if (Buffer == 0) return 0;
					x = false;
				}
				else
				{
					x = true;
					error = true;
				}
			}
			else x = true;
		}
		if (error == false)
		{
			NTDLL::SYSTEM_PROCESSES_INFORMATION* p = (NTDLL::SYSTEM_PROCESSES_INFORMATION*)Buffer;
			while (1)
			{
				if (p->UniqueProcessId == (HANDLE)ProcessId)
				{
					//for (ULONG i=0;i<p->ThreadCount;i++)
					{
						unsigned long ThreadId = (unsigned long)p->Threads[0].ClientId.UniqueThread;
						//auto Base = p->Threads[0].StartAddress;
						//DBG_PRINT(_T("秘密通信  秘密通信秘密通信 线程ID=%d 地址=%p\r\n"), ThreadId, Base);
						//GetModuleFileNameEx()
						LocalFree(Buffer);
						return ThreadId;
					}

				}
				if (p->NextEntryDelta == 0) break;
				p = (NTDLL::SYSTEM_PROCESSES_INFORMATION*)((unsigned char*)p + (p->NextEntryDelta));
			}
		}
		LocalFree(Buffer);
		return 0;
	}
	static PVOID load_dll(std::wstring filename)
	{
		//using namespace NTDLL;
		HANDLE hSection, hFile;
		UNICODE_STRING dllName;
		PVOID BaseAddress = NULL;
		SIZE_T size = 0;
		NTSTATUS stat;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &dllName, OBJ_CASE_INSENSITIVE };
		IO_STATUS_BLOCK iosb;
		auto full_dll_path = filename.c_str();

		RtlInitUnicodeString(&dllName, full_dll_path);

		//_asm int 3;
		stat = ZwOpenFile(&hFile, FILE_EXECUTE | SYNCHRONIZE, &oa, &iosb,
			FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

		if (!NT_SUCCESS(stat)) {
			DBG_PRINTA("WRN: Can't open %ws: %x\n", full_dll_path, stat);
			return 0;
		}

		oa.ObjectName = 0;

		stat = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, 0, PAGE_EXECUTE,
			SEC_IMAGE, hFile);

		if (!NT_SUCCESS(stat)) {
			DBG_PRINTA("WRN: Can't create section %ws: %x\n", full_dll_path, stat);
			return 0;
		}

		stat = ZwMapViewOfSection(hSection, GetCurrentProcess(), &BaseAddress, 0,
			1000, 0, &size, (NTDLL::SECTION_INHERIT)1, MEM_TOP_DOWN, PAGE_READWRITE);

		if (!NT_SUCCESS(stat)) {
			DBG_PRINTA("WRN: Can't map section %ws: %x\n", full_dll_path, stat);
			return 0;
		}

		ZwClose(hSection);
		ZwClose(hFile);

		DBG_PRINTA("DBG: Successfully loaded %ws\n", full_dll_path);
		return BaseAddress;
	}
	static void free_dll(HANDLE hMod)
	{
		ZwUnmapViewOfSection(GetCurrentProcess(), hMod);
	}
	static PVOID get_module_handle_process(DWORD64 ProcessId, LPCTSTR lpszModuleName, BOOL bGet32Module)
	{
		auto snapshot = std::experimental::make_unique_resource(
			CreateToolhelp32Snapshot(bGet32Module ? TH32CS_SNAPMODULE32
				|TH32CS_SNAPMODULE : TH32CS_SNAPMODULE, DWORD(ProcessId)),
			&CloseHandle);
		auto hSnap = snapshot.get();
		if (!hSnap || hSnap == INVALID_HANDLE_VALUE)
		{
			DBG_PRINTA("SnapFailed\r\n");
			return nullptr;
		}
		MODULEENTRY32W me32 = {};
		me32.dwSize = sizeof(MODULEENTRY32W);
		if (!Module32First(hSnap, &me32))
		{
			DBG_PRINTA("Can not GetXX\r\n");
			return nullptr;
		}

		do
		{
			DBG_PRINT(TEXT("\n\n     MODULE NAME:     %s"), me32.szModule);
			DBG_PRINT(TEXT("\n     Executable     = %s"), me32.szExePath);
			DBG_PRINT(TEXT("\n     Process ID     = 0x%08X"), me32.th32ProcessID);
			DBG_PRINT(TEXT("\n     Ref count (g)  = 0x%04X"), me32.GlblcntUsage);
			DBG_PRINT(TEXT("\n     Ref count (p)  = 0x%04X"), me32.ProccntUsage);
			DBG_PRINT(TEXT("\n     Base address   = 0x%p"), PVOID(me32.modBaseAddr));
			DBG_PRINT(TEXT("\n     Base size      = %d"), me32.modBaseSize);
			if (_tcsicmp(me32.szModule, lpszModuleName) == 0)
			{
				if (bGet32Module)
				{
					if (_tcsstr(_tcslwr(me32.szExePath),L"\\syswow64\\"))
					{
						return PVOID(me32.modBaseAddr);
					}
				}
				else
					return PVOID(me32.modBaseAddr);
			}
			RtlZeroMemory(&me32, sizeof(me32));
			me32.dwSize = sizeof(MODULEENTRY32W);
		} while (Module32Next(hSnap, &me32));

		return nullptr;
	}

	static ULONG_PTR get_proc_address(PVOID Image, LPCSTR functionname)
	{
#define RVATOVA(_base_, _offset_) ((PUCHAR)(_base_) + (ULONG)(_offset_))
		__try
		{
			PIMAGE_EXPORT_DIRECTORY pExport = NULL;

			PIMAGE_NT_HEADERS32 pHeaders32 = (PIMAGE_NT_HEADERS32)
				((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

			if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
			{
				// 32-bit image
				if (pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
				{
					pExport = (PIMAGE_EXPORT_DIRECTORY)RVATOVA(
						Image,
						pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
					);
				}
			}
			else if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
			{
				// 64-bit image
				PIMAGE_NT_HEADERS64 pHeaders64 = (PIMAGE_NT_HEADERS64)
					((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

				if (pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
				{
					pExport = (PIMAGE_EXPORT_DIRECTORY)RVATOVA(
						Image,
						pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
					);
				}
			}

			if (pExport)
			{
				PULONG AddressOfFunctions = (PULONG)RVATOVA(Image, pExport->AddressOfFunctions);
				PSHORT AddrOfOrdinals = (PSHORT)RVATOVA(Image, pExport->AddressOfNameOrdinals);
				PULONG AddressOfNames = (PULONG)RVATOVA(Image, pExport->AddressOfNames);
				ULONG i = 0;
				for (i = 0; i < pExport->NumberOfFunctions; i++)
				{
					if (!strcmp((char *)RVATOVA(Image, AddressOfNames[i]), functionname))
					{
						return AddressOfFunctions[AddrOfOrdinals[i]];
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{

		}
		return 0;
	}
	static PVOID get_pro_address_process(
		DWORD64 ProcessId,
		LPCTSTR lpszModuleName,
		LPCSTR lpszApi,
		BOOL bGet32)
	{

		std::wstring dll_name = std::wstring(L"\\SystemRoot\\System32\\");
		if (bGet32)
		{
			dll_name = std::wstring(L"\\SystemRoot\\SysWow64\\");
		}
		dll_name += std::wstring(lpszModuleName);
		auto pBase = get_module_handle_process(ProcessId, lpszModuleName, bGet32);
		if (!pBase)
		{
			return nullptr;
		}
		auto dll = std::experimental::make_unique_resource(
			load_dll(dll_name), &free_dll
		);
		auto pImageBase = dll.get();
		if (!pImageBase)
		{
			return nullptr;
		}
		auto ulRVA = get_proc_address(pImageBase, lpszApi);
		if (!ulRVA)
		{
			return nullptr;
		}
		auto pRet = PVOID((PUCHAR)pBase + ulRVA);
		return pRet;
	}
	static PVOID WriteStubEx(HANDLE hProcess, LPCWSTR lpszDllFilePath)
	{
		ULONG_PTR stublen;
		PVOID LoadLibAddr, mem;
		unsigned char shellcode_basecode[] = {
			0x60,0x9c,0xe8,0x00,0x00,0x00,0x00,0x59,0x83,0xe9,0x07,0x8d,0x41,0x20,0x50,0xff,
			0x51,0xfc,0x9d,0x61,0xc3,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
		};
		LoadLibAddr = get_pro_address_process(GetProcessId(hProcess), _T("kernel32.dll"), "LoadLibraryW", TRUE);
		stublen = sizeof(LoadLibAddr);
		mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		DBG_PRINT(_T("秘密通信 Allocate mem =%p\r\n"), mem);
		//printf("Memory allocated at %p\nAbout to write stub code...\n", mem);
		WriteProcessMemory(hProcess, mem, &LoadLibAddr, sizeof(PVOID), NULL);
		WriteProcessMemory(hProcess, (LPVOID)((LPBYTE)mem + 4), shellcode_basecode, stublen, NULL);
		WriteProcessMemory(hProcess, (LPVOID)((LPBYTE)mem + 4 + stublen), lpszDllFilePath, MAX_PATH * sizeof(WCHAR), NULL);
		return (PVOID)((LPBYTE)mem + 4);
	}
	static bool create_thread(IN HANDLE ProcessHanlde, IN PVOID Routine, IN PVOID Param)
	{
		const auto THREAD_CREATE_FLAGS_CREATE_SUSPENDED = 0x00000001;
		const auto THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH = 0x00000002;
		const auto THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER = 0x00000004;

		HANDLE hThread = nullptr;
		OBJECT_ATTRIBUTES ob = { 0 };
		auto flags = THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH;

		InitializeObjectAttributes(&ob, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		auto status = ZwCreateThreadEx(
			&hThread,
			THREAD_ALL_ACCESS,
			&ob,
			ProcessHanlde,
			Routine,
			Param,
			flags,
			0,
			0x10000,
			0x100000,
			NULL
		);
		auto exit_3 = std::experimental::make_scope_exit([&]() {if (hThread)
			ZwClose(hThread); });

		if (!NT_SUCCESS(status))
		{
		//	DBG_PRINT(_T("ZwCreateThreadEx failed\r\n"));
			return false;
		}
		return true;
	}
	static BOOL inject_apc_dll(DWORD dwProcessId, LPCWSTR lpszDllFilePath)
	{
		using NT_QUEUE_APC_THREAD = NTSTATUS(NTAPI *)(HANDLE, PVOID, PVOID, PVOID, PVOID);
		auto MainThreadId = GetMainThreadId(dwProcessId);
		auto ret = FALSE;
		auto h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (h_process && h_process != INVALID_HANDLE_VALUE)
		{
			WCHAR szName[MAX_PATH] = { 0 };
			wcscpy_s(szName, sizeof(szName), lpszDllFilePath);
			auto h_Thread = OpenThread(THREAD_ALL_ACCESS, FALSE, MainThreadId);
			if (h_Thread && h_Thread != INVALID_HANDLE_VALUE)
			{
				auto  NtQueueApcThread = (NT_QUEUE_APC_THREAD)(GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueueApcThread"));

				//printf("Attempting Injection using NtQueueApcThread...\n");
				//PVOID shell_code = nullptr;
				auto mem = WriteStubEx(h_process, szName);

				NtQueueApcThread(h_Thread, mem, NULL, NULL, NULL);
				//printf("NtQueueApcThread called: %d\n", GetLastError());
				ret = TRUE;
				CloseHandle(h_Thread);
			}
			CloseHandle(h_process);
		}
		return ret;
	}

	static bool inject_code_context(
		DWORD ProcessId,
		LPCWSTR lpszFileName,
		HANDLE ProcessHandle)
	{
		bool ret = false;
		WCHAR szName[MAX_PATH] = { 0 };
		wcscpy_s(szName, sizeof(szName), lpszFileName);
		auto MainThreadId = inject::GetMainThreadId(ProcessId);
		auto h_Thread = OpenThread(THREAD_ALL_ACCESS, FALSE, MainThreadId);
		if (h_Thread && h_Thread != INVALID_HANDLE_VALUE)
		{

			auto dwRet = Wow64SuspendThread(h_Thread);
			if (dwRet != (DWORD)-1)
			{
			//	PVOID shell_code = nullptr;
				auto mem = inject::WriteStubEx(ProcessHandle, szName);
				WOW64_CONTEXT ctx;
				ctx.ContextFlags = CONTEXT_FULL;
				if (Wow64GetThreadContext(h_Thread, &ctx))
				{
					ctx.Esp -= 4;
					WriteProcessMemory(ProcessHandle, reinterpret_cast<PVOID>(ctx.Esp), &ctx.Eip, sizeof(PVOID), NULL);
					ctx.Eip = reinterpret_cast<DWORD>(mem);
					if (Wow64SetThreadContext(h_Thread, &ctx))
						ret = true;
				}
				ResumeThread(h_Thread);
				//Sleep(5000);//等一下好清除Shellcode
				//auto nop_mem = malloc(PAGE_SIZE);
				//if (nop_mem)
				//{
				//	WriteProcessMemory(ProcessHandle, mem, nop_mem, PAGE_SIZE, NULL);
				//	free(nop_mem);
				//}
			}
			CloseHandle(h_Thread);
		}
		return ret;
	}
	static BOOL inject_remote_thread(DWORD dwProcessId, LPCWSTR lpszDllFilePath)
	{
		//远程线程
		auto ret = FALSE;
		auto h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (h_process && h_process != INVALID_HANDLE_VALUE)
		{
			WCHAR szName[MAX_PATH] = { 0 };
			wcscpy_s(szName, sizeof(szName), lpszDllFilePath);
			auto ptr_String = VirtualAllocEx(h_process, NULL, sizeof(szName), MEM_COMMIT, PAGE_READWRITE);
			if (ptr_String)
			{
				DWORD dwWrite = 0;
				auto res = WriteProcessMemory(h_process, ptr_String, szName, sizeof(szName), &dwWrite);
				if (res)
				{
				//	auto h_kernel32 = GetModuleHandle(_T("kernel32.dll"));
					auto pfn_caller = get_pro_address_process(dwProcessId, _T("kernel32.dll"), "LoadLibraryW", TRUE);
					//GetProcAddress(h_kernel32, "LoadLibraryW");
					auto hThread = CreateRemoteThread(h_process, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pfn_caller), ptr_String, 0, NULL);
					if (hThread && hThread != INVALID_HANDLE_VALUE)
					{
						ret = TRUE;
						CloseHandle(hThread);
					}
				}
			}
			CloseHandle(h_process);
		}
		return ret;
	}
}