#include "windbghelp.h"
#include <windows.h>
#include <cassert>
#include <iostream>

//简化一下类型定义    pfn_SymSetOptions等价于DWORD(WINAPI* )(DWORD)类型
typedef DWORD(WINAPI* pfn_SymSetOptions)(DWORD); 
typedef DWORD(WINAPI* pfn_SymGetOptions)(void);
typedef BOOL(WINAPI* pfn_SymInitialize)(HANDLE, PCTSTR, BOOL);
typedef BOOL(WINAPI* pfn_SymGetSymFromAddr64)(HANDLE, DWORD64, PDWORD64, PIMAGEHLP_SYMBOL64);
typedef DWORD(WINAPI* pfn_UnDecorateSymbolName)(const char*, char*, DWORD, DWORD);
typedef BOOL(WINAPI* pfn_SymSetSearchPath)(HANDLE, PCTSTR);
typedef BOOL(WINAPI* pfn_SymGetSearchPath)(HANDLE, PTSTR, int);
typedef BOOL(WINAPI* pfn_StackWalk64)(DWORD MachineType,
    HANDLE hProcess,
    HANDLE hThread,
    LPSTACKFRAME64 StackFrame,
    PVOID ContextRecord,
    PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine,
    PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
    PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
    PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress);
typedef PVOID(WINAPI* pfn_SymFunctionTableAccess64)(HANDLE hProcess, DWORD64 AddrBase);
typedef DWORD64(WINAPI* pfn_SymGetModuleBase64)(HANDLE hProcess, DWORD64 dwAddr);
typedef BOOL(WINAPI* pfn_SymGetModuleInfo64)(HANDLE hProcess, DWORD64 dwAddr, PIMAGEHLP_MODULE64 ModuleInfo);//新增SymGetModuleInfo64
typedef BOOL(WINAPI* pfn_MiniDumpWriteDump) (HANDLE hProcess, DWORD ProcessId, HANDLE hFile,
    MINIDUMP_TYPE DumpType, PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION    CallbackParam);
typedef BOOL(WINAPI* pfn_SymGetLineFromAddr64) (HANDLE hProcess, DWORD64 dwAddr,
    PDWORD pdwDisplacement, PIMAGEHLP_LINE64 Line);
typedef LPAPI_VERSION(WINAPI* pfn_ImagehlpApiVersion)(void);

// Add functions as needed.
#define FOR_ALL_FUNCTIONS(DO) \
 DO(ImagehlpApiVersion) \
 DO(SymGetOptions) \
 DO(SymSetOptions) \
 DO(SymInitialize) \
 DO(SymGetSymFromAddr64) \
 DO(UnDecorateSymbolName) \
 DO(SymSetSearchPath) \
 DO(SymGetSearchPath) \
 DO(StackWalk64) \
 DO(SymFunctionTableAccess64) \
 DO(SymGetModuleBase64) \
 DO(MiniDumpWriteDump) \
 DO(SymGetLineFromAddr64)\
 DO(SymGetModuleInfo64)

//这是函数声明 static 修饰， pfn_pfn_##functionname是上面typedef的函数类，g_pfn_##functionname是函数名
#define DECLARE_FUNCTION_POINTER(functionname) \
static pfn_##functionname g_pfn_##functionname;   

FOR_ALL_FUNCTIONS(DECLARE_FUNCTION_POINTER)


static HMODULE g_dll_handle = NULL;
static DWORD g_dll_load_error = 0;
static API_VERSION g_version = { 0, 0, 0, 0 };

enum class state {
    state_uninitialized = 0,
    state_ready = 1,
    state_error = 2
};
static state g_state = state::state_uninitialized;

static void initialize() {

    assert(g_state == state::state_uninitialized, "wrong sequence");
    g_state = state::state_error;

    g_dll_handle = ::LoadLibrary(_T("DBGHELP.DLL"));
    if (g_dll_handle == NULL) {
        g_dll_load_error = ::GetLastError();
    }
    else {
        // Note: We loaded the DLL successfully. From here on we count
        // initialization as success. We still may fail to load all of the
        // desired function pointers successfully, but DLL may still be usable
        // enough for our purposes.
        g_state = state::state_ready;

#define DO_RESOLVE(functionname) \
      g_pfn_##functionname = (pfn_##functionname) ::GetProcAddress(g_dll_handle, #functionname);

        FOR_ALL_FUNCTIONS(DO_RESOLVE)

            // Retrieve version information.
            if (g_pfn_ImagehlpApiVersion) {
                const API_VERSION* p = g_pfn_ImagehlpApiVersion();
                memcpy(&g_version, p, sizeof(API_VERSION));
            }
    }

}


///////////////////// External functions //////////////////////////

// All outside facing functions are synchronized. Also, we run
// initialization on first touch.

static CRITICAL_SECTION g_cs;

namespace { // Do not export.
    class WindowsDbgHelpEntry {
    public:
        WindowsDbgHelpEntry() {
            ::EnterCriticalSection(&g_cs);
            if (g_state == state::state_uninitialized) {
                initialize();
            }
        }
        ~WindowsDbgHelpEntry() {
            ::LeaveCriticalSection(&g_cs);
        }
    };
}

// Called at DLL_PROCESS_ATTACH.
void WindowsDbgHelp::pre_initialize() {
    ::InitializeCriticalSection(&g_cs);
}

DWORD WindowsDbgHelp::symSetOptions(DWORD arg) {
    WindowsDbgHelpEntry entry_guard;
    if (g_pfn_SymSetOptions != NULL) {
        return g_pfn_SymSetOptions(arg);
    }
    return 0;
}

DWORD WindowsDbgHelp::symGetOptions(void) {
    WindowsDbgHelpEntry entry_guard;
    if (g_pfn_SymGetOptions != NULL) {
        return g_pfn_SymGetOptions();
    }
    return 0;
}

BOOL WindowsDbgHelp::symInitialize(HANDLE hProcess, PCTSTR UserSearchPath, BOOL fInvadeProcess) {
    WindowsDbgHelpEntry entry_guard;
    if (g_pfn_SymInitialize != NULL) {
        return g_pfn_SymInitialize(hProcess, UserSearchPath, fInvadeProcess);
    }
    return FALSE;
}

BOOL WindowsDbgHelp::symGetSymFromAddr64(HANDLE hProcess, DWORD64 the_address,
    PDWORD64 Displacement, PIMAGEHLP_SYMBOL64 Symbol) {
    WindowsDbgHelpEntry entry_guard;
    if (g_pfn_SymGetSymFromAddr64 != NULL) {
        return g_pfn_SymGetSymFromAddr64(hProcess, the_address, Displacement, Symbol);
    }
    return FALSE;
}

DWORD WindowsDbgHelp::unDecorateSymbolName(const char* DecoratedName, char* UnDecoratedName,
    DWORD UndecoratedLength, DWORD Flags) {
    WindowsDbgHelpEntry entry_guard;
    if (g_pfn_UnDecorateSymbolName != NULL) {
        return g_pfn_UnDecorateSymbolName(DecoratedName, UnDecoratedName, UndecoratedLength, Flags);
    }
    if (UnDecoratedName != NULL && UndecoratedLength > 0) {
        UnDecoratedName[0] = '\0';
    }
    return 0;
}

BOOL WindowsDbgHelp::symSetSearchPath(HANDLE hProcess, PCTSTR SearchPath) {
    WindowsDbgHelpEntry entry_guard;
    if (g_pfn_SymSetSearchPath != NULL) {
        return g_pfn_SymSetSearchPath(hProcess, SearchPath);
    }
    return FALSE;
}

BOOL WindowsDbgHelp::symGetSearchPath(HANDLE hProcess, PTSTR SearchPath, int SearchPathLength) {
    WindowsDbgHelpEntry entry_guard;
    if (g_pfn_SymGetSearchPath != NULL) {
        return g_pfn_SymGetSearchPath(hProcess, SearchPath, SearchPathLength);
    }
    return FALSE;
}

BOOL WindowsDbgHelp::stackWalk64(DWORD MachineType,
    HANDLE hProcess,
    HANDLE hThread,
    LPSTACKFRAME64 StackFrame,
    PVOID ContextRecord) {
    WindowsDbgHelpEntry entry_guard;
    if (g_pfn_StackWalk64 != NULL) {
        return g_pfn_StackWalk64(MachineType, hProcess, hThread, StackFrame,
            ContextRecord,
            NULL, // ReadMemoryRoutine
            g_pfn_SymFunctionTableAccess64, // FunctionTableAccessRoutine,
            g_pfn_SymGetModuleBase64, // GetModuleBaseRoutine
            NULL // TranslateAddressRoutine
        );
    }
    return FALSE;
}

PVOID WindowsDbgHelp::symFunctionTableAccess64(HANDLE hProcess, DWORD64 AddrBase) {
    WindowsDbgHelpEntry entry_guard;
    if (g_pfn_SymFunctionTableAccess64 != NULL) {
        return g_pfn_SymFunctionTableAccess64(hProcess, AddrBase);
    }
    return NULL;
}

DWORD64 WindowsDbgHelp::symGetModuleBase64(HANDLE hProcess, DWORD64 dwAddr) {
    WindowsDbgHelpEntry entry_guard;
    if (g_pfn_SymGetModuleBase64 != NULL) {
        return g_pfn_SymGetModuleBase64(hProcess, dwAddr);
    }
    return 0;
}

BOOL WindowsDbgHelp::symGetModuleInfo64(HANDLE hProcess, DWORD64 dwAddr, PIMAGEHLP_MODULE64 ModuleInfo) {
    WindowsDbgHelpEntry entry_guard;
    if (g_pfn_SymGetModuleInfo64 != NULL) {
        if (g_pfn_SymGetModuleInfo64(hProcess, dwAddr, ModuleInfo) == false) {
                DWORD error_code = GetLastError();
                std::cout << "symGetModuleInfo64 failed,error code:" << error_code << std::endl;
        }
        return true;
        //return g_pfn_SymGetModuleInfo64(hProcess, dwAddr, ModuleInfo);
    }
    return 0;
}

BOOL WindowsDbgHelp::miniDumpWriteDump(HANDLE hProcess, DWORD ProcessId, HANDLE hFile,
    MINIDUMP_TYPE DumpType, PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION CallbackParam) {
    WindowsDbgHelpEntry entry_guard;
    if (g_pfn_MiniDumpWriteDump != NULL) {
        return g_pfn_MiniDumpWriteDump(hProcess, ProcessId, hFile, DumpType,
            ExceptionParam, UserStreamParam, CallbackParam);
    }
    return FALSE;
}

BOOL WindowsDbgHelp::symGetLineFromAddr64(HANDLE hProcess, DWORD64 dwAddr,
    PDWORD pdwDisplacement, PIMAGEHLP_LINE64 Line) {
    WindowsDbgHelpEntry entry_guard;
    if (g_pfn_SymGetLineFromAddr64 != NULL) {
        if (g_pfn_SymGetLineFromAddr64(hProcess, dwAddr, pdwDisplacement, Line) == false) {
            DWORD error_code = GetLastError();
            switch (error_code) {
            case 126:
                std::cout << _T("Debug info in current module has not loaded.") << std::endl;
                return false;
            case 487:
                std::cout << "No debug info in current module." << std::endl;
                return false;
            default:
                std::cout << _T("SymGetLineFromAddr64 failed: ") << error_code << std::endl;
                return false;
            }
        }
        return true;
        // return g_pfn_SymGetLineFromAddr64(hProcess, dwAddr, pdwDisplacement, Line);
        //return g_pfn_SymGetLineFromAddr64(hProcess, dwAddr, pdwDisplacement, Line);
    }
    return FALSE;
}

bool WindowsDbgHelp::GetModuleInfo(HANDLE hProcess, DWORD64 baseAddr,
    IMAGEHLP_MODULE64* pModuleInfo) {
    WindowsDbgHelpEntry entry_guard;
    memset(pModuleInfo, 0, sizeof(IMAGEHLP_MODULE64));
    if (g_pfn_SymGetModuleInfo64 == NULL) {
        SetLastError(ERROR_DLL_INIT_FAILED);
        return FALSE;
    }
    // First try to use the larger ModuleInfo-Structure
    pModuleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    void* pData = malloc(4096); // reserve enough memory, so the bug in v6.3.5.1 does not lead to memory-overwrites...
    if (pData == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    // could not retrieve the bigger structure, try with the smaller one (as defined in VC7.1)...
    pModuleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    memcpy(pData, pModuleInfo, sizeof(IMAGEHLP_MODULE64));
    if (symGetModuleInfo64(hProcess, baseAddr, (IMAGEHLP_MODULE64*)pData) != FALSE) {
        // only copy as much memory as is reserved...
        memcpy(pModuleInfo, pData, sizeof(IMAGEHLP_MODULE64));
        pModuleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
        free(pData);
        return TRUE;
    }
    free(pData);
    SetLastError(ERROR_DLL_INIT_FAILED);
    return FALSE;

}
