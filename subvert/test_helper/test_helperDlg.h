
// test_helperDlg.h : ͷ�ļ�
//

#pragma once
#include "afxcmn.h"


// Ctest_helperDlg �Ի���
class Ctest_helperDlg : public CDialogEx
{
// ����
public:
	Ctest_helperDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_TEST_HELPER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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
