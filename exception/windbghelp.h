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
    BOOL miniDumpWriteDump(HANDLE hProcess, DWORD ProcessId, HANDLE hFile,
        MINIDUMP_TYPE DumpType, PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
        PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
        PMINIDUMP_CALLBACK_INFORMATION CallbackParam);
    BOOL symGetLineFromAddr64(HANDLE hProcess, DWORD64 dwAddr,
        PDWORD pdwDisplacement, PIMAGEHLP_LINE64 Line);

    // Call at DLL_PROCESS_ATTACH.
    void pre_initialize();

};

#endif // OS_WINDOWS_WINDBGHELP_HPP