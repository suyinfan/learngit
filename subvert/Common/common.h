#pragma once
//////////////////////////////////////////////////////////////////////////
#pragma warning(disable:4996)
#pragma warning(disable:4101)
#pragma warning(disable:4005)
#pragma warning(disable:4091)
#pragma warning(disable:4800)
#pragma warning(disable:4312)
#pragma warning(disable:4311)
#pragma warning(disable:4244)
//////////////////////////////////////////////////////////////////////////
#include <tchar.h>
#include <Windows.h>
#include <assert.h>
#include <winternl.h>

#include <vector>
#include <memory>
#include <map>
#include <algorithm>
#include <utility>
#include <thread>
#include <chrono>
#include <functional>
#include <atomic>
#include <string>
#include <array>
#include <sstream>

#include <tlhelp32.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <winioctl.h>
#include <strsafe.h>
#include <intrin.h>
#include <intsafe.h>
#include <Sfc.h>
#include <winsvc.h>
namespace flt
{
#include <fltUser.h>
}
namespace NTDLL
{
	#include <ntstatus.h>
	extern"C"
	{
		#include "ntos.h"
		typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY
		{
			ULONG Attribute;    // PROC_THREAD_ATTRIBUTE_XXX
			SIZE_T Size;
			ULONG_PTR Value;
			ULONG Unknown;
		} NT_PROC_THREAD_ATTRIBUTE_ENTRY, *NT_PPROC_THREAD_ATTRIBUTE_ENTRY;

		typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST
		{
			ULONG Length;
			NT_PROC_THREAD_ATTRIBUTE_ENTRY Entry[1];
		} NT_PROC_THREAD_ATTRIBUTE_LIST, *PNT_PROC_THREAD_ATTRIBUTE_LIST;

	}

};

#pragma comment(lib,"psapi.lib")
#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"Wbemuuid.lib")
#pragma comment(lib,"Mpr.lib")
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"FltLib.lib")
#pragma comment(lib,"Sfc.lib")



#include "scope_exit.h"
#include "unique_resource.h"
#include "SingleTon.h"
#include "native_api.h"


#define PAGE_SHIFT 12L
#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))
#define BYTES_TO_PAGES(Size)  (((Size) >> PAGE_SHIFT) + \
                               (((Size) & (PAGE_SIZE - 1)) != 0))


#if !defined(PUBLIC)
void debug_log(TCHAR *format, ...);
void debug_log_A(CHAR *format, ...);
#define DBG_PRINT(format, ...)  \
   debug_log((format), __VA_ARGS__)
#define DBG_PRINTA(format, ...)  \
   debug_log_A((format), __VA_ARGS__)
#else
#define DBG_PRINT(format, ...)
#define DBG_PRINTA(format, ...)
#endif


inline bool IsX64() {
#ifdef _AMD64_
	return true;
#else
	return false;
#endif
}


//#include <pshpack1.h>
template <typename T>
struct _LIST_ENTRY_T
{
	T Flink;
	T Blink;
};

template <typename T>
struct _UNICODE_STRING_T
{
	WORD Length;
	WORD MaximumLength;
	T Buffer;
};

template <typename T, typename NGF, int A>
struct _PEB_T
{
	typedef T type;

	union
	{
		struct
		{
			BYTE InheritedAddressSpace;
			BYTE ReadImageFileExecOptions;
			BYTE BeingDebugged;
			BYTE BitField;
		};
		T dummy01;
	};
	T Mutant;
	T ImageBaseAddress;
	T Ldr;
	T ProcessParameters;
	T SubSystemData;
	T ProcessHeap;
	T FastPebLock;
	T AtlThunkSListPtr;
	T IFEOKey;
	T CrossProcessFlags;
	T UserSharedInfoPtr;
	DWORD SystemReserved;
	DWORD AtlThunkSListPtr32;
	T ApiSetMap;
	T TlsExpansionCounter;
	T TlsBitmap;
	DWORD TlsBitmapBits[2];
	T ReadOnlySharedMemoryBase;
	T HotpatchInformation;
	T ReadOnlyStaticServerData;
	T AnsiCodePageData;
	T OemCodePageData;
	T UnicodeCaseTableData;
	DWORD NumberOfProcessors;
	union
	{
		DWORD NtGlobalFlag;
		NGF dummy02;
	};
	LARGE_INTEGER CriticalSectionTimeout;
	T HeapSegmentReserve;
	T HeapSegmentCommit;
	T HeapDeCommitTotalFreeThreshold;
	T HeapDeCommitFreeBlockThreshold;
	DWORD NumberOfHeaps;
	DWORD MaximumNumberOfHeaps;
	T ProcessHeaps;
	T GdiSharedHandleTable;
	T ProcessStarterHelper;
	T GdiDCAttributeList;
	T LoaderLock;
	DWORD OSMajorVersion;
	DWORD OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	DWORD OSPlatformId;
	DWORD ImageSubsystem;
	DWORD ImageSubsystemMajorVersion;
	T ImageSubsystemMinorVersion;
	T ActiveProcessAffinityMask;
	T GdiHandleBuffer[A];
	T PostProcessInitRoutine;
	T TlsExpansionBitmap;
	DWORD TlsExpansionBitmapBits[32];
	T SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	T pShimData;
	T AppCompatInfo;
	_UNICODE_STRING_T<T> CSDVersion;
	T ActivationContextData;
	T ProcessAssemblyStorageMap;
	T SystemDefaultActivationContextData;
	T SystemAssemblyStorageMap;
	T MinimumStackCommit;
	T FlsCallback;
	_LIST_ENTRY_T<T> FlsListHead;
	T FlsBitmap;
	DWORD FlsBitmapBits[4];
	T FlsHighIndex;
	T WerRegistrationData;
	T WerShipAssertPtr;
	T pContextData;
	T pImageHeaderHash;
	T TracingFlags;
	T CsrServerReadOnlySharedMemoryBase;
};

typedef _PEB_T<DWORD, DWORD64, 34> _PEB32;
typedef _PEB_T<DWORD64, DWORD, 30> _PEB64;

// PEB helper
template<typename T>
struct _PEB_T2
{
	typedef typename std::conditional<std::is_same<T, DWORD>::value, _PEB32, _PEB64>::type type;
};


template<typename T>
struct _PEB_LDR_DATA2
{
	unsigned long Length;
	unsigned char Initialized;
	T SsHandle;
	_LIST_ENTRY_T<T> InLoadOrderModuleList;
	_LIST_ENTRY_T<T> InMemoryOrderModuleList;
	_LIST_ENTRY_T<T> InInitializationOrderModuleList;
	T EntryInProgress;
	unsigned char ShutdownInProgress;
	T ShutdownThreadId;
};

template<typename T>
struct _LDR_DATA_TABLE_ENTRY_BASE
{
	_LIST_ENTRY_T<T> InLoadOrderLinks;
	_LIST_ENTRY_T<T> InMemoryOrderLinks;
	_LIST_ENTRY_T<T> InInitializationOrderLinks;
	T DllBase;
	T EntryPoint;
	unsigned long SizeOfImage;
	_UNICODE_STRING_T<T> FullDllName;
	_UNICODE_STRING_T<T> BaseDllName;
	unsigned long Flags;
	unsigned short LoadCount;
	unsigned short TlsIndex;
	_LIST_ENTRY_T<T> HashLinks;
	unsigned long TimeDateStamp;
	T EntryPointActivationContext;
	T PatchInformation;
};

typedef _PEB_LDR_DATA2<DWORD>     _PEB_LDR_DATA232;
typedef _PEB_LDR_DATA2<DWORD64>   _PEB_LDR_DATA264;
typedef _PEB_LDR_DATA2<DWORD_PTR>  PEB_LDR_DATA_T;

typedef _LDR_DATA_TABLE_ENTRY_BASE<DWORD>     _LDR_DATA_TABLE_ENTRY_BASE32;
typedef _LDR_DATA_TABLE_ENTRY_BASE<DWORD64>   _LDR_DATA_TABLE_ENTRY_BASE64;
typedef _LDR_DATA_TABLE_ENTRY_BASE<DWORD_PTR>  LDR_DATA_TABLE_ENTRY_BASE_T;

#define FIELD_OFFSET(type, field)    ((LONG)(LONG_PTR)&(((type *)0)->field))

typedef struct _INJECT_BUFFER
{
	UCHAR code[0x200];
	UCHAR original_code[8];
	PVOID hook_func;
	union
	{
		_UNICODE_STRING_T<DWORD> path;
		_UNICODE_STRING_T<DWORD64> path64;
	};
	wchar_t buffer[488];
	PVOID module;
	ULONG complete;
} INJECT_BUFFER, *PINJECT_BUFFER;
//#include <poppack.h>