#ifndef OS_WINDOWS_WINDBGHELP_HPP
#define OS_WINDOWS_WINDBGHELP_HPP

#include <windows.h>
#include <imagehlp.h>
#include<tchar.h>


// Please note: dbghelp.dll may not have been loaded, or it may have been loaded but not
//  all functions may be available (because on the target system dbghelp.dll is of an
//  older version).
// In all these cases we return an error from the WindowsDbgHelp::symXXXX() wrapper. We never
//  assert. It should always be safe to call these functions, but caller has to process the
//  return code (which he would have to do anyway).
namespace WindowsDbgHelp {

    DWORD symSetOptions(DWORD);
    DWORD symGetOptions(void);
    BOOL symInitialize(HANDLE, PCTSTR, BOOL);

    BOOL symGetSymFromAddr64(HANDLE, DWORD64, PDWORD64, PIMAGEHLP_SYMBOL64);

    DWORD unDecorateSymbolName(const char*, char*, DWORD, DWORD);

    BOOL symSetSearchPath(HANDLE, PCTSTR);
    BOOL symGetSearchPath(HANDLE, PTSTR, int);

    BOOL stackWalk64(DWORD MachineType,
        HANDLE hProcess,
        HANDLE hThread,
        LPSTACKFRAME64 StackFrame,
        PVOID ContextRecord);
    PVOID symFunctionTableAccess64(HANDLE hProcess, DWORD64 AddrBase);

    DWORD64 symGetModuleBase64(HANDLE hProcess, DWORD64 dwAddr);

    BOOL symGetModuleInfo64(HANDLE hProcess, DWORD64 dwAddr, PIMAGEHLP_MODULE64 ModuleInfo);

    BOOL miniDumpWriteDump(HANDLE hProcess, DWORD ProcessId, HANDLE hFile,
        MINIDUMP_TYPE DumpType, PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
        PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
        PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

    BOOL symGetLineFromAddr64(HANDLE hProcess, DWORD64 dwAddr,
        PDWORD pdwDisplacement, PIMAGEHLP_LINE64 Line);

    // Call at DLL_PROCESS_ATTACH.
    void pre_initialize();

    bool GetModuleInfo(HANDLE hProcess, DWORD64 baseAddr,
        IMAGEHLP_MODULE64* pModuleInfo);

};


inline void TCHAR2Char(const TCHAR* tchar, char* _char)
{
    int iLength;
    iLength = WideCharToMultiByte(CP_ACP, 0, tchar, -1, NULL, 0, NULL, NULL);
    WideCharToMultiByte(CP_ACP, 0, tchar, -1, _char, iLength, NULL, NULL);
}

inline void Char2TCHAR(const char* _char, TCHAR* tchar)
{
    int iLength;
    iLength = MultiByteToWideChar(CP_ACP, 0, _char, strlen(_char) + 1, NULL, 0);
    MultiByteToWideChar(CP_ACP, 0, _char, strlen(_char) + 1, tchar, iLength);
}

#endif // OS_WINDOWS_WINDBGHELP_HPP