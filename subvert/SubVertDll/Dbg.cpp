#include "stdafx.h"
#include "../Common/common.h"

namespace debugger
{
	//..�������棬R3�Խ����Ի���
	//
	//MyDebugActiveProcess��ʵ�֣���DebugeeDllע�뵽�����ԵĽ����DebugeeDll��DllMain��PROCESS ATTACH��ʼ����
	//MyWaitForDebugEvent��ʵ�֣�����DebugeeDll����Ϣ(Debugee����ϢҲ�Ǵ�socket������)
	//MyContinueDebugEvent��ʵ�֣�...
	//ִ�жϵ��ʵ�֣�֪ͨDebuggeeDll��DebuggeeDll�Զϵ����ڵĵ�ַhook����д0xCC����ҪVEH,���ֽ��̲��У�
	//���ʶϵ��ʵ�֣�֪ͨDebuggeeDll��dll�Զϵ�λ�ý���XXOO(DRX����PAGE�����޸ġ�����ҪVEH)
	//SetContext/GetContext/Suspend/Resume��ʵ�֣�APIת������

}