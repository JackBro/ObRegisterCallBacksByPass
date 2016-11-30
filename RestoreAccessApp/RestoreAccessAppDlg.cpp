
// RestoreAccessAppDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "RestoreAccessApp.h"
#include "RestoreAccessAppDlg.h"
#include "afxdialogex.h"
#include <windows.h>  
#include <winsvc.h>  
#include <conio.h>  
#include <stdio.h>
#include <winioctl.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define DRIVER_NAME "RestoreAccessEx"
#define DRIVER_PATH ".\\RestoreAccess.sys"
#define DRIVER_PATH_WIN7 ".\\RestoreAccessExWin7x64.sys"

#define IOCTRL_BASE 0x800  

#define IOCTL_CODE(i) CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define CTL_HELLO IOCTL_CODE(0)  
#define CTL_ULONG IOCTL_CODE(1)  
#define CTL_WCHAR IOCTL_CODE(2)  
#define CTL_RESTORE_OBJECT_ACCESS IOCTL_CODE(3)

#define MAKELONG64(a, b)	((LONG64)(((DWORD)(((DWORD_PTR)(a)) & 0xffffffff)) | \
	((ULONG64)((DWORD)(((DWORD_PTR)(b)) & 0xffffffff))) << 32))

HANDLE g_hDevice = NULL;

//装载NT驱动程序
BOOL LoadDriver(char* lpszDriverName, char* lpszDriverPath, char* lpszDriverPathEx)
{
	//char szDriverImagePath[256] = "D:\\DriverTest\\ntmodelDrv.sys";
	char szDriverImagePath[256] = { 0 };
	//得到完整的驱动路径
	GetFullPathName(lpszDriverPath, 256, szDriverImagePath, NULL);
	AfxMessageBox(szDriverImagePath);
	if (!PathFileExists(szDriverImagePath))
	{
		GetFullPathName(lpszDriverPathEx, 256, szDriverImagePath, NULL);
		AfxMessageBox(szDriverImagePath,MB_OK);
	}
		
	

	BOOL bRet = FALSE;

	SC_HANDLE hServiceMgr = NULL;//SCM管理器的句柄
	SC_HANDLE hServiceDDK = NULL;//NT驱动程序的服务句柄

								 //打开服务控制管理器
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (hServiceMgr == NULL)
	{
		//OpenSCManager失败
		printf("OpenSCManager() Failed %d ! \n", GetLastError());
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		////OpenSCManager成功
		printf("OpenSCManager() ok ! \n");
	}

	//创建驱动所对应的服务
	hServiceDDK = CreateService(hServiceMgr,
		lpszDriverName, //驱动程序的在注册表中的名字  
		lpszDriverName, // 注册表驱动程序的 DisplayName 值  
		SERVICE_ALL_ACCESS, // 加载驱动程序的访问权限  
		SERVICE_KERNEL_DRIVER,// 表示加载的服务是驱动程序  
		SERVICE_DEMAND_START, // 注册表驱动程序的 Start 值  自动启动 开机启动 手动启动 禁用
		SERVICE_ERROR_IGNORE, // 注册表驱动程序的 ErrorControl 值  
		szDriverImagePath, // 注册表驱动程序的 ImagePath 值  
		NULL,  //GroupOrder HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GroupOrderList
		NULL,
		NULL,
		NULL,
		NULL);

	DWORD dwRtn;
	//判断服务是否失败
	if (hServiceDDK == NULL)
	{
		dwRtn = GetLastError();
		if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS)
		{
			//由于其他原因创建服务失败
			printf("CrateService() Failed %d ! \n", dwRtn);
			bRet = FALSE;
			goto BeforeLeave;
		}
		else
		{
			//服务创建失败，是由于服务已经创立过
			printf("CrateService() Failed Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n");
			AfxMessageBox("CrateService() Failed Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS!",MB_OK);
		}

		// 驱动程序已经加载，只需要打开  
		hServiceDDK = OpenService(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
		if (hServiceDDK == NULL)
		{
			//如果打开服务也失败，则意味错误
			dwRtn = GetLastError();
			printf("OpenService() Failed %d ! \n", dwRtn);
			AfxMessageBox("OpenService failed !\n");
			bRet = FALSE;
			goto BeforeLeave;
		}
		else
		{
			printf("OpenService() ok ! \n");
		}
	}
	else
	{
		printf("CrateService() ok ! \n");
	}

	//开启此项服务
	bRet = StartService(hServiceDDK, NULL, NULL);
	if (!bRet)
	{
		DWORD dwRtn = GetLastError();
		if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING)
		{
			printf("StartService() Failed %d ! \n", dwRtn);
			AfxMessageBox("StartService() failed !");
			bRet = FALSE;
			goto BeforeLeave;
		}
		else
		{
			if (dwRtn == ERROR_IO_PENDING)
			{
				//设备被挂住
				printf("StartService() Failed ERROR_IO_PENDING ! \n");
				AfxMessageBox("StartService() Failed ERROR_IO_PENDING ! !");
				bRet = FALSE;
				goto BeforeLeave;
			}
			else
			{
				//服务已经开启
				printf("StartService() Failed ERROR_SERVICE_ALREADY_RUNNING ! \n");
				AfxMessageBox("StartService() Failed ERROR_SERVICE_ALREADY_RUNNING !");
				bRet = TRUE;
				goto BeforeLeave;
			}
		}
	}
	bRet = TRUE;
	//离开前关闭句柄
BeforeLeave:
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;
}

//卸载驱动程序  
BOOL UnloadDriver(char * szSvrName)
{
	BOOL bRet = FALSE;
	SC_HANDLE hServiceMgr = NULL;//SCM管理器的句柄
	SC_HANDLE hServiceDDK = NULL;//NT驱动程序的服务句柄
	SERVICE_STATUS SvrSta;
	//打开SCM管理器
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hServiceMgr == NULL)
	{
		//带开SCM管理器失败
		printf("OpenSCManager() Failed %d ! \n", GetLastError());
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		//带开SCM管理器失败成功
		printf("OpenSCManager() ok ! \n");
	}
	//打开驱动所对应的服务
	hServiceDDK = OpenService(hServiceMgr, szSvrName, SERVICE_ALL_ACCESS);

	if (hServiceDDK == NULL)
	{
		//打开驱动所对应的服务失败
		printf("OpenService() Failed %d ! \n", GetLastError());
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		printf("OpenService() ok ! \n");
	}
	//停止驱动程序，如果停止失败，只有重新启动才能，再动态加载。  
	if (!ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrSta))
	{
		printf("ControlService() Failed %d !\n", GetLastError());
	}
	else
	{
		//打开驱动所对应的失败
		printf("ControlService() ok !\n");
	}


	//动态卸载驱动程序。  

	if (!DeleteService(hServiceDDK))
	{
		//卸载失败
		printf("DeleteSrevice() Failed %d !\n", GetLastError());
	}
	else
	{
		//卸载成功
		printf("DelServer:deleteSrevice() ok !\n");
	}

	bRet = TRUE;
BeforeLeave:
	//离开前关闭打开的句柄
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;
}


BOOL RestoreAccess(DWORD ActiveId, DWORD PassiveId)
{
	ULONG64 ProcessId = 0;
	DWORD dwRet = 0;

	ProcessId = MAKELONG64(PassiveId, ActiveId);

	if (g_hDevice)
	{
		if (!DeviceIoControl(g_hDevice,
			CTL_RESTORE_OBJECT_ACCESS,
			&ProcessId,
			sizeof(ActiveId) + sizeof(PassiveId),
			NULL,
			0,
			&dwRet,
			NULL))
		{
			return FALSE;
		}
	}

	return TRUE;
}


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CRestoreAccessAppDlg 对话框



CRestoreAccessAppDlg::CRestoreAccessAppDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_RESTOREACCESSAPP_DIALOG, pParent)
	, m_RestorePid(0)
	, m_GamePid(0)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CRestoreAccessAppDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_AESTORE_PID, m_RestorePid);
	DDX_Text(pDX, IDC_EDIT_GAME_PID, m_GamePid);
}

BEGIN_MESSAGE_MAP(CRestoreAccessAppDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BTN_LOAD, &CRestoreAccessAppDlg::OnBnClickedBtnLoad)
	ON_BN_CLICKED(IDC_BTN_UNLOAD, &CRestoreAccessAppDlg::OnBnClickedBtnUnload)
	ON_BN_CLICKED(IDC_BTN_RESTORE, &CRestoreAccessAppDlg::OnBnClickedBtnRestore)
END_MESSAGE_MAP()


// CRestoreAccessAppDlg 消息处理程序

BOOL CRestoreAccessAppDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	//ShowWindow(SW_MINIMIZE);

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CRestoreAccessAppDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CRestoreAccessAppDlg::OnPaint()
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
HCURSOR CRestoreAccessAppDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CRestoreAccessAppDlg::OnBnClickedBtnLoad()
{
	BOOL bRet = LoadDriver(DRIVER_NAME, DRIVER_PATH, DRIVER_PATH_WIN7);
	if (!bRet)
	{
		AfxMessageBox("LoadNtDriver error !", MB_OK);
		return;
	}

	//AfxMessageBox("LoadDriver Success !",MB_OK);

	Sleep(1000);
	
	g_hDevice = CreateFile("\\\\.\\RestoreAccess",
		GENERIC_WRITE | GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	if (g_hDevice != INVALID_HANDLE_VALUE)
	{
		//AfxMessageBox("Create Device ok !");
	}
	else
	{
		AfxMessageBox("Create Device Failed  !");
		return;
	}

	this->GetDlgItem(IDC_BTN_UNLOAD)->EnableWindow();
	this->GetDlgItem(IDC_BTN_RESTORE)->EnableWindow();
}


void CRestoreAccessAppDlg::OnBnClickedBtnUnload()
{
	if (g_hDevice)
		CloseHandle(g_hDevice);

	BOOL bRet = UnloadDriver(DRIVER_NAME);
	if (!bRet)
	{
		AfxMessageBox("UnloadNTDriver error !", MB_OK);
		return;
	}

	AfxMessageBox("UnloadNTDriver Success !", MB_OK);
}


void CRestoreAccessAppDlg::OnBnClickedBtnRestore()
{
	UpdateData(TRUE);

	DWORD ResPid = m_RestorePid;
	DWORD GamePid = m_GamePid;
	if (!RestoreAccess(ResPid, GamePid))
	{
		AfxMessageBox("Restore failed !",MB_OK);
	}
	else
	{
		AfxMessageBox("Restore success !",MB_OK);
	}
}
