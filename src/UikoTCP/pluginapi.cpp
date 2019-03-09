#include "StdAfx.h"
#include "pluginapi.h"
#include <windows.h>

unsigned int g_stringsize;
stack_t  **g_stacktop;
TCHAR *g_variables;

// #ifdef UNICODE
// #pragma comment(lib, "pluginapi_u.lib")
// #else 
// #pragma comment(lib, "pluginapi.lib")
// #endif


// utility functions (not required but often useful)

int NSISCALL popstring(TCHAR *str)
{
	stack_t *th;
	if (!g_stacktop || !*g_stacktop) return 1;
	th=(*g_stacktop);
	if (str) lstrcpy(str,th->text);
	*g_stacktop = th->next;
	GlobalFree((HGLOBAL)th);
	return 0;
}

int NSISCALL popstringn(TCHAR *str, int maxlen)
{
	stack_t *th;
	if (!g_stacktop || !*g_stacktop) return 1;
	th=(*g_stacktop);
	if (str) lstrcpyn(str,th->text,maxlen?maxlen:g_stringsize);
	*g_stacktop = th->next;
	GlobalFree((HGLOBAL)th);
	return 0;
}

void NSISCALL pushstring(const TCHAR *str)
{
	stack_t *th;
	if (!g_stacktop) return;
	th=(stack_t*)GlobalAlloc(GPTR,sizeof(stack_t)+g_stringsize);
	lstrcpyn(th->text,str,g_stringsize);
	th->next=*g_stacktop;
	*g_stacktop=th;
}

TCHAR * NSISCALL getuservariable(const int varnum)
{
	if (varnum < 0 || varnum >= __INST_LAST) return NULL;
	return g_variables+varnum*g_stringsize;
}

void NSISCALL setuservariable(const int varnum, const TCHAR *var)
{
	if (var != NULL && varnum >= 0 && varnum < __INST_LAST) 
		lstrcpy(g_variables + varnum*g_stringsize, var);
}

// playing with integers

int NSISCALL myatoi(const TCHAR *s)
{
	int v=0;
	if (*s == '0' && (s[1] == 'x' || s[1] == 'X'))
	{
		s++;
		for (;;)
		{
			int c=*(++s);
			if (c >= '0' && c <= '9') c-='0';
			else if (c >= 'a' && c <= 'f') c-='a'-10;
			else if (c >= 'A' && c <= 'F') c-='A'-10;
			else break;
			v<<=4;
			v+=c;
		}
	}
	else if (*s == '0' && s[1] <= '7' && s[1] >= '0')
	{
		for (;;)
		{
			int c=*(++s);
			if (c >= '0' && c <= '7') c-='0';
			else break;
			v<<=3;
			v+=c;
		}
	}
	else
	{
		int sign=0;
		if (*s == '-') sign++; else s--;
		for (;;)
		{
			int c=*(++s) - '0';
			if (c < 0 || c > 9) break;
			v*=10;
			v+=c;
		}
		if (sign) v = -v;
	}

	return v;
}

unsigned NSISCALL myatou(const TCHAR *s)
{
	unsigned int v=0;

	for (;;)
	{
		unsigned int c=*s++;
		if (c >= '0' && c <= '9') c-='0';
		else break;
		v*=10;
		v+=c;
	}
	return v;
}

int NSISCALL myatoi_or(const TCHAR *s)
{
	int v=0;
	if (*s == '0' && (s[1] == 'x' || s[1] == 'X'))
	{
		s++;
		for (;;)
		{
			int c=*(++s);
			if (c >= '0' && c <= '9') c-='0';
			else if (c >= 'a' && c <= 'f') c-='a'-10;
			else if (c >= 'A' && c <= 'F') c-='A'-10;
			else break;
			v<<=4;
			v+=c;
		}
	}
	else if (*s == '0' && s[1] <= '7' && s[1] >= '0')
	{
		for (;;)
		{
			int c=*(++s);
			if (c >= '0' && c <= '7') c-='0';
			else break;
			v<<=3;
			v+=c;
		}
	}
	else
	{
		int sign=0;
		if (*s == '-') sign++; else s--;
		for (;;)
		{
			int c=*(++s) - '0';
			if (c < 0 || c > 9) break;
			v*=10;
			v+=c;
		}
		if (sign) v = -v;
	}

	// Support for simple ORed expressions
	if (*s == '|') 
	{
		v |= myatoi_or(s+1);
	}

	return v;
}

int NSISCALL popint()
{
	TCHAR buf[128];
	if (popstringn(buf,sizeof(buf)))
		return 0;

	return myatoi(buf);
}

int NSISCALL popint_or()
{
	TCHAR buf[128];
	if (popstringn(buf,sizeof(buf)))
		return 0;

	return myatoi_or(buf);
}

void NSISCALL pushint(int value)
{
	TCHAR buffer[1024];
#ifdef UNICODE
	wsprintf(buffer, _T("%d"), value);
#else
	sprintf_s(buffer, "%d", value);
#endif
	
	pushstring(buffer);
}