#include "stdafx.h"
#include "../Common/common.h"

namespace debugger
{
	//..调试引擎，R3自建调试机制
	//
	//MyDebugActiveProcess的实现：将DebugeeDll注入到被调试的进程里，DebugeeDll的DllMain里PROCESS ATTACH开始工作
	//MyWaitForDebugEvent的实现：接受DebugeeDll的消息(Debugee的消息也是从socket发来的)
	//MyContinueDebugEvent的实现：...
	//执行断点的实现：通知DebuggeeDll，DebuggeeDll对断点所在的地址hook或者写0xCC（需要VEH,部分进程不行）
	//访问断点的实现：通知DebuggeeDll，dll对断点位置进行XXOO(DRX或者PAGE属性修改——需要VEH)
	//SetContext/GetContext/Suspend/Resume的实现：API转发而已

}