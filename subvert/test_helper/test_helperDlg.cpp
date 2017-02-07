
// test_helperDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "test_helper.h"
#include "test_helperDlg.h"
#include "afxdialogex.h"
#include "../Common/common.h"
#include "../Common/ioctrl.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// Ctest_helperDlg 对话框



Ctest_helperDlg::Ctest_helperDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_TEST_HELPER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void Ctest_helperDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_list);
}

BEGIN_MESSAGE_MAP(Ctest_helperDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &Ctest_helperDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &Ctest_helperDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &Ctest_helperDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON4, &Ctest_helperDlg::OnBnClickedButton4)
	ON_BN_CLICKED(IDC_BUTTON5, &Ctest_helperDlg::OnBnClickedButton5)
	//ON_EN_CHANGE(IDC_EDIT3, &Ctest_helperDlg::OnEnChangeEdit3)
	//ON_EN_CHANGE(IDC_FILE, &Ctest_helperDlg::OnEnChangeFile)
	ON_BN_CLICKED(IDC_BUTTON6, &Ctest_helperDlg::OnBnClickedButton6)
	ON_BN_CLICKED(IDC_BUTTON7, &Ctest_helperDlg::OnBnClickedButton7)
	ON_BN_CLICKED(IDC_BUTTON8, &Ctest_helperDlg::OnBnClickedButton8)
	ON_BN_CLICKED(IDC_BUTTON9, &Ctest_helperDlg::OnBnClickedButton9)
END_MESSAGE_MAP()


// Ctest_helperDlg 消息处理程序

BOOL Ctest_helperDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	LoadLibrary(_T("helper_dll.dll"));


	TCHAR *tab[8] = { _T("进程"),_T("PID"),_T("cntUsage"),_T("th32DefaultHeapID"),
		_T("th32ModuleID"),_T("cntThreads"),_T("th32ParentProcessID"),
		_T("pcPriClassBase") };
	for (int i = 0; i < 8; i++)
	{
		m_list.InsertColumn(i, tab[i], LVCFMT_LEFT, 80);
	}

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void Ctest_helperDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR Ctest_helperDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void Ctest_helperDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码

	CString szA;
	GetDlgItemText(IDC_EDIT1, szA);
	CString szAddr;
	GetDlgItemText(IDC_ADDR, szAddr);
	auto addr = _tcstoul(szAddr, nullptr, 16);
	auto pid = _ttoi(szA);
	SIZE_T dwRet = 0;
	auto handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	PVOID base = PVOID(addr);
	BYTE out[10] = { 0 };
	ReadProcessMemory(handle, base, out, 10, &dwRet);
	CloseHandle(handle);
	CString szB;
	szB.Format(_T("%x %x"), out[0], out[1]);
	AfxMessageBox(szB);

}


void Ctest_helperDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	CString szA;
	GetDlgItemText(IDC_EDIT1, szA);
	auto pid = _ttoi(szA);
	CString szAddr;
	GetDlgItemText(IDC_ADDR, szAddr);
	auto addr = _tcstoul(szAddr, nullptr, 16);
	SIZE_T dwRet = 0;
	auto handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	PVOID base = PVOID(addr);
	BYTE out[10] = { 0 };
	out[0] = 0x90;
	out[1] = 0x90;
	WriteProcessMemory(handle, base, out, 2, &dwRet);
	CloseHandle(handle);
}

BOOL Ctest_helperDlg::GetProcessList()
{
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	DBG_PRINTA("START 1\r\n");
	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	DBG_PRINTA("START 2\r\n");
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		
		return(FALSE);
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	DBG_PRINTA("START\r\n");
	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		DBG_PRINT(TEXT("Process32First")); // show cause of failure
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return(FALSE);
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	CString str;
	int i = 0;
	do
	{   //一下是将pe的值，添加到列表中
		m_list.InsertItem(i, pe32.szExeFile);//插入进程名
		str.Format(_T("%d"), pe32.th32ProcessID);
		m_list.SetItemText(i, 1, str);
		str.Format(_T("%d"), pe32.cntUsage);
		m_list.SetItemText(i, 2, str);
		str.Format(_T("%d"), pe32.th32DefaultHeapID);
		m_list.SetItemText(i, 3, str);
		str.Format(_T("%d"), pe32.th32ModuleID);
		m_list.SetItemText(i, 4, str);
		str.Format(_T("%d"), pe32.cntThreads);
		m_list.SetItemText(i, 5, str);
		str.Format(_T("%d"), pe32.th32ParentProcessID);
		m_list.SetItemText(i, 6, str);
		str.Format(_T("%d"), pe32.pcPriClassBase);
		m_list.SetItemText(i, 7, str);
		i++;
	//{
		/*DBG_PRINT(TEXT("\n\n====================================================="));
		DBG_PRINT(TEXT("\nPROCESS NAME:  %s"), pe32.szExeFile);
		DBG_PRINT(TEXT("\n-------------------------------------------------------"));
		DBG_PRINT(TEXT("\n  Process ID        = %d"), pe32.th32ProcessID);
		DBG_PRINT(TEXT("\n  Thread count      = %d"), pe32.cntThreads);
		DBG_PRINT(TEXT("\n  Parent process ID = %d"), pe32.th32ParentProcessID);
		DBG_PRINT(TEXT("\n  Priority base     = %d"), pe32.pcPriClassBase);*/
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	str.Format(_T("%d"), i);
	SetDlgItemText(IDC_CNT, str);

	return(TRUE);
}

void Ctest_helperDlg::OnBnClickedButton3()
{
	m_list.DeleteAllItems();
	// TODO: 在此添加控件通知处理程序代码
	GetProcessList();
}


void Ctest_helperDlg::OnBnClickedButton4()
{
	// TODO: 在此添加控件通知处理程序代码
	CString szA;
	GetDlgItemText(IDC_EDIT1, szA);
	auto dwProcessId = _ttoi(szA);
	CString lpszDllFilePath;
	GetDlgItemText(IDC_FILE, lpszDllFilePath);
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
				auto h_kernel32 = GetModuleHandle(_T("kernel32.dll"));
				auto pfn_caller = GetProcAddress(h_kernel32, "LoadLibraryW");
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
	return;
}


void Ctest_helperDlg::OnBnClickedButton5()
{
	// TODO: 在此添加控件通知处理程序代码
	CString szA;
	GetDlgItemText(IDC_EDIT1, szA);
	auto pid = _ttoi(szA);

	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	// Print the process identifier.

	DBG_PRINTA("\nProcess ID: %u\n", pid);

	// Get a handle to the process.

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, pid);
	if (NULL == hProcess)
		return ;

	// Get a list of all the modules in this process.

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.

			//if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
			//	sizeof(szModName) / sizeof(TCHAR)))
			//{
			//	// Print the module name and handle value.

				DBG_PRINT(TEXT("\t(0x%08X)\n"),hMods[i]);
		//	}
		}
	}

	// Release the handle to the process.

	CloseHandle(hProcess);

	/*return*/;
	auto snapshot = std::experimental::make_unique_resource(
		CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, DWORD(pid)),
		&CloseHandle);
	auto hSnap = snapshot.get();
	if (!hSnap || hSnap == INVALID_HANDLE_VALUE)
	{
		DBG_PRINTA("SnapFailed %x\r\n",GetLastError());
		return;
	}
	MODULEENTRY32W me32 = {};
	me32.dwSize = sizeof(MODULEENTRY32W);
	if (!Module32First(hSnap, &me32))
	{
		DBG_PRINTA("Can not GetXX\r\n");
		return;
	}

	do
	{
		DBG_PRINT(TEXT("MODULE NAME:     %s\r\n"), me32.szModule);
		DBG_PRINT(TEXT("Executable     = %s\r\n"), me32.szExePath);
		DBG_PRINT(TEXT("Process ID     = 0x%08X\r\n"), me32.th32ProcessID);
		DBG_PRINT(TEXT("Ref count (g)  = 0x%04X\r\n"), me32.GlblcntUsage);
		DBG_PRINT(TEXT("Ref count (p)  = 0x%04X\r\n"), me32.ProccntUsage);
		DBG_PRINT(TEXT("Base address   = 0x%p\r\n"), PVOID(me32.modBaseAddr));
		DBG_PRINT(TEXT("Base size      = %d\r\n"), me32.modBaseSize);
		RtlZeroMemory(&me32, sizeof(me32));
		me32.dwSize = sizeof(MODULEENTRY32W);
	} while (Module32Next(hSnap, &me32));

	return;
}


void Ctest_helperDlg::OnEnChangeEdit3()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}


void Ctest_helperDlg::OnEnChangeFile()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}


void Ctest_helperDlg::OnBnClickedButton6()
{
	// TODO: 在此添加控件通知处理程序代码
	const auto handle = std::experimental::make_unique_resource(
		CreateFile(TEXT("\\\\.\\Subvert"), GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr),
		&CloseHandle);
	auto returned = DWORD(0);
	auto bRet = DeviceIoControl(handle.get(), DRV_IOCTL_UNHIDE_MEM, nullptr, 0, NULL, 0,
		&returned, nullptr);
}


void Ctest_helperDlg::OnBnClickedButton7()
{
	static bool b_disabe = false;
	// TODO: 在此添加控件通知处理程序代码
	const auto handle = std::experimental::make_unique_resource(
		CreateFile(TEXT("\\\\.\\Subvert"), GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr),
		&CloseHandle);
	auto returned = DWORD(0);
	auto bRet = DeviceIoControl(handle.get(), DRV_IOCTL_NOTIFY_DISABLE, nullptr, 0, NULL, 0,
		&returned, nullptr);
	if (b_disabe)
	{
		b_disabe = false;
		SetDlgItemText(IDC_BUTTON7, TEXT("禁止回调"));
	}
	else
	{
		SetDlgItemText(IDC_BUTTON7, TEXT("开启回调"));
		b_disabe = true;
	}
}

void dbg_routine(int pid)
{
	auto AttachDbg = [](DWORD dwProcessId) {
		DebugSetProcessKillOnExit(TRUE);
		if (dwProcessId != (DWORD)-1)
		{
			DBG_PRINTA("ProcessId = %d\r\n", dwProcessId);
			//OutputDebugString(_T("Find ok ExSS\r\n"));
			//TCHAR szLog[MAX_PATH];
			if (DebugActiveProcess(dwProcessId))
			{
				DBG_PRINTA("附加成功\r\n");
				return TRUE;
			}
			else
			{
				DBG_PRINTA("DebugActiveProcess Last Error = %d\r\n", GetLastError());
			}
		}
		return FALSE;
	};
	if (AttachDbg(DWORD(pid)))
	{
		BOOL m_firstEvent = TRUE;
		while (1)
		{
			//CString formatString;
			unsigned long exception_code = 0;
			DEBUG_EVENT DE = { 0 };
			DWORD dwStatus = DBG_CONTINUE;
			if (WaitForDebugEvent(&DE, INFINITE))
			{
				if (m_firstEvent)
				{
					::MessageBox(NULL, TEXT("附加ok"), TEXT("附加成功"), MB_OK);
					m_firstEvent = FALSE;
					DBG_PRINT(TEXT("附加成功"));
				}
				switch (DE.dwDebugEventCode)
				{
				case CREATE_PROCESS_DEBUG_EVENT:
					DBG_PRINT(_T("Create Process pid=%d, tid=%d\r\n"), DE.dwProcessId, DE.dwThreadId);
					ContinueDebugEvent(DE.dwProcessId, DE.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
					break;
				case CREATE_THREAD_DEBUG_EVENT:
					DBG_PRINT(_T("Create thread pid=%d, tid=%d\r\n"), DE.dwProcessId, DE.dwThreadId);
					ContinueDebugEvent(DE.dwProcessId, DE.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
					break;
				case EXCEPTION_DEBUG_EVENT:
					exception_code = DE.u.Exception.ExceptionRecord.ExceptionCode;
					DBG_PRINT(_T("Exception pid=%d, tid=%d,expcode = %x\r\n"), DE.dwProcessId, DE.dwThreadId, exception_code);
					if (exception_code == EXCEPTION_BREAKPOINT)
					{
						//判断是否是自己设置的int3!??!<--难题1
					}
					if (exception_code == EXCEPTION_SINGLE_STEP)
					{
						//判断是否是自己的硬断<--难题2
					}
					/*	if (exception_code == EXCEPTION_INVALID_HANDLE)
					{
					dwStatus = DBG_CONTINUE;
					}*/
					if (DE.u.Exception.dwFirstChance == 0)
					{
						OutputDebugString(_T("Find Not Handled Exception\r\n"));
						dwStatus = DBG_CONTINUE;
					}
					else
					{
						dwStatus = DBG_EXCEPTION_NOT_HANDLED;
					}
					ContinueDebugEvent(DE.dwProcessId, DE.dwThreadId, dwStatus);
					break;
				case EXIT_THREAD_DEBUG_EVENT:
					DBG_PRINT(_T("exit thread pid=%d, tid=%d\r\n"), DE.dwProcessId, DE.dwThreadId);
					ContinueDebugEvent(DE.dwProcessId, DE.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
					break;
				case LOAD_DLL_DEBUG_EVENT:
					DBG_PRINT(_T("load dll pid=%d, tid=%d\r\n"), DE.dwProcessId, DE.dwThreadId);
					ContinueDebugEvent(DE.dwProcessId, DE.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
					break;
				case UNLOAD_DLL_DEBUG_EVENT:
					DBG_PRINT(_T("unload dll pid=%d, tid=%d\r\n"), DE.dwProcessId, DE.dwThreadId);
					ContinueDebugEvent(DE.dwProcessId, DE.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
					break;
				case EXIT_PROCESS_DEBUG_EVENT:
					DBG_PRINT(_T("Exit Process pid=%d, tid=%d\r\n"), DE.dwProcessId, DE.dwThreadId);
					ContinueDebugEvent(DE.dwProcessId, DE.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
					break;
				default:
					DBG_PRINT(_T("unknown pid=%d, tid=%d, decode = %d\r\n"), DE.dwProcessId, DE.dwThreadId, DE.dwDebugEventCode);
					ContinueDebugEvent(DE.dwProcessId, DE.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
					break;
				}
				//OutputDebugString(formatString);
			}
		}
	}
}

void Ctest_helperDlg::OnBnClickedButton8()
{
	// TODO: 在此添加控件通知处理程序代码
	CString szA;
	GetDlgItemText(IDC_EDIT1, szA);
	auto pid = _ttoi(szA);

	auto dbg_thread = std::thread(dbg_routine, pid);
	dbg_thread.detach();
}


void Ctest_helperDlg::OnBnClickedButton9()
{
	// TODO: 
	const auto handle = std::experimental::make_unique_resource(
		CreateFile(TEXT("\\\\.\\Subvert"), GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr),
		&CloseHandle);
	auto returned = DWORD(0);
	auto bRet = DeviceIoControl(handle.get(), DRV_IOCTL_PATH_SWAPCONTEXT, nullptr, 0, NULL, 0,
		&returned, nullptr);
}
