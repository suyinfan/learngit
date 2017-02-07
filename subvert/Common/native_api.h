#pragma once
extern "C"
{
	NTSTATUS
		NTAPI
		ZwClose(
			_In_ HANDLE Handle
		);

	NTSTATUS
		NTAPI
		RtlAdjustPrivilege(
			ULONG Privilege,
			BOOLEAN Enable,
			BOOLEAN Client,
			PBOOLEAN WasEnabled
		);
	PIMAGE_NT_HEADERS
		NTAPI
		RtlImageNtHeader(
			PVOID Base
		);

	HANDLE
		NTAPI
		CsrGetProcessId();

	NTSTATUS
		NTAPI
		ZwQueryVirtualMemory(
			_In_ HANDLE ProcessHandle,
			_In_opt_ PVOID BaseAddress,
			_In_ NTDLL::MEMORY_INFORMATION_CLASS MemoryInformationClass,
			_Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
			_In_ SIZE_T MemoryInformationLength,
			_Out_opt_ PSIZE_T ReturnLength
		);
	NTSTATUS
		NTAPI
		ZwAllocateVirtualMemory(
			_In_ HANDLE ProcessHandle,
			_Inout_ PVOID *BaseAddress,
			_In_ ULONG_PTR ZeroBits,
			_Inout_ PSIZE_T RegionSize,
			_In_ ULONG AllocationType,
			_In_ ULONG Protect
		);
	NTSTATUS
		NTAPI
		ZwWriteVirtualMemory(
			IN HANDLE ProcessHandle,
			IN PVOID BaseAddress,
			IN PVOID Buffer,
			IN ULONG BufferLength,
			OUT PULONG ReturnLength OPTIONAL);

	NTSTATUS
		NTAPI
		ZwCreateThreadEx(
			OUT PHANDLE hThread,
			IN ACCESS_MASK DesiredAccess,
			IN PVOID ObjectAttributes,
			IN HANDLE ProcessHandle,
			IN PVOID lpStartAddress,
			IN PVOID lpParameter,
			IN ULONG Flags,
			IN SIZE_T StackZeroBits,
			IN SIZE_T SizeOfStackCommit,
			IN SIZE_T SizeOfStackReserve,
			IN NTDLL::PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList);

	NTSTATUS
		NTAPI
		ZwOpenProcess(
			_Out_ PHANDLE ProcessHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ NTDLL::PCLIENT_ID ClientId
		);

	NTSTATUS
		NTAPI
		RtlCreateUserThread(
			HANDLE,
			PSECURITY_DESCRIPTOR,
			BOOLEAN,
			ULONG,
			PULONG,
			PULONG,
			PVOID,
			PVOID,
			PHANDLE,
			NTDLL::PCLIENT_ID);

	NTSTATUS
		NTAPI
		ZwOpenFile(
			_Out_ PHANDLE FileHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_ POBJECT_ATTRIBUTES ObjectAttributes,
			_Out_ PIO_STATUS_BLOCK IoStatusBlock,
			_In_ ULONG ShareAccess,
			_In_ ULONG OpenOptions
		);

	NTSTATUS
		NTAPI
		ZwCreateSection(
			_Out_ PHANDLE SectionHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ PLARGE_INTEGER MaximumSize,
			_In_ ULONG SectionPageProtection,
			_In_ ULONG AllocationAttributes,
			_In_opt_ HANDLE FileHandle
		);

	NTSTATUS
		NTAPI
		ZwMapViewOfSection(
			_In_ HANDLE SectionHandle,
			_In_ HANDLE ProcessHandle,
			_Outptr_result_bytebuffer_(*ViewSize) PVOID *BaseAddress,
			_In_ ULONG_PTR ZeroBits,
			_In_ SIZE_T CommitSize,
			_Inout_opt_ PLARGE_INTEGER SectionOffset,
			_Inout_ PSIZE_T ViewSize,
			_In_ NTDLL::SECTION_INHERIT InheritDisposition,
			_In_ ULONG AllocationType,
			_In_ ULONG Win32Protect
		);

	NTSTATUS
		NTAPI
		ZwUnmapViewOfSection(
			_In_ HANDLE ProcessHandle,
			_In_opt_ PVOID BaseAddress
		);

	//Wow64GetThreadContext

	NTSTATUS
		NTAPI
		ZwOpenDirectoryObject(
			_Out_ PHANDLE DirectoryHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_ POBJECT_ATTRIBUTES ObjectAttributes
		);

	NTSTATUS
		NTAPI
		ZwQueryDirectoryObject(
			__in HANDLE DirectoryHandle,
			__out_bcount_opt(Length) PVOID Buffer,
			__in ULONG Length,
			__in BOOLEAN ReturnSingleEntry,
			__in BOOLEAN RestartScan,
			__inout PULONG Context,
			__out_opt PULONG ReturnLength
		);

	ULONG
		NTAPI
		DbgPrompt(
			_In_z_ PCCH Prompt,
			_Out_writes_bytes_(Length) PCH Response,
			_In_ ULONG Length
		);


	NTSTATUS NTAPI ZwSetInformationProcess(HANDLE, NTDLL::PROCESSINFOCLASS, PVOID, ULONG);

	NTSTATUS
		NTAPI
		ZwProtectVirtualMemory(
			__in HANDLE ProcessHandle,
			__inout PVOID *BaseAddress,
			__inout PSIZE_T RegionSize,
			__in ULONG NewProtect,
			__out PULONG OldProtect
			);

};
