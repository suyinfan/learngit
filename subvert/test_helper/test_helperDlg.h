
// test_helperDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"


// Ctest_helperDlg 对话框
class Ctest_helperDlg : public CDialogEx
{
// 构造
public:
	Ctest_helperDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_TEST_HELPER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedButton4();
	BOOL GetProcessList();
	CListCtrl m_list;
	afx_msg void OnBnClickedButton5();
	afx_msg void OnEnChangeEdit3();
	afx_msg void OnEnChangeFile();
	afx_msg void OnBnClickedButton6();
	afx_msg void OnBnClickedButton7();
	afx_msg void OnBnClickedButton8();
	afx_msg void OnBnClickedButton9();
};
