#include "stdafx.h"
#include "common.h"
#include <strsafe.h>
#ifndef PUBLIC
void debug_log(TCHAR *format, ...)
{

	va_list args;
	va_start(args, format);
	TCHAR buf[1024];
	NTSTATUS stat;
	size_t wsize = 0;
	stat = _vstprintf(buf, format, args);
	if (!NT_SUCCESS(stat)) {
		buf[1023] = _T('\0');
	}

	OutputDebugString(buf);
	va_end(args);
}
void debug_log_A(CHAR *format, ...)
{

	va_list args;
	va_start(args, format);
	CHAR buf[1024];
	NTSTATUS stat;
	size_t wsize = 0;
	stat = vsprintf(buf, format, args);
	if (!NT_SUCCESS(stat)) {
		buf[1023] = _T('\0');
	}

	OutputDebugStringA(buf);
	va_end(args);
}
#endif