
// plugins_help_exe.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// Cplugins_help_exeApp: 
// �йش����ʵ�֣������ plugins_help_exe.cpp
//

class Cplugins_help_exeApp : public CWinApp
{
public:
	Cplugins_help_exeApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern Cplugins_help_exeApp theApp;