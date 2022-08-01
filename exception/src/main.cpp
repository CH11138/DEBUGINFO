#include "StackWalker.h"
#include <tchar.h>
#include <fstream>
#include <process.h>
#include <string>

#include<time.h>

#pragma warning(disable:4996)

StackWalker SW = StackWalker();
class water {
public:
    water(double ph = 10) {
        this->ph = ph;
    }
    double get_ph() const { return ph; }
    void set_ph(double ph){ this->ph = ph; }
private:
    double ph;
};

void create_water() {
    std::shared_ptr<water> ptr = nullptr;   //异常
    //ptr->set_ph(100);
    std::cout << ptr->get_ph();
}

void test() {
    std::cout << "test()\n";
    create_water();
}
void test2() {
    std::cout << "test2()\n";
    test();
}
DWORD seh_filer(int code)
{
    switch (code)
    {
    case EXCEPTION_ACCESS_VIOLATION:
        printf("Access violation，error code：%x\n", code);
        break;
    case EXCEPTION_BREAKPOINT:
        printf("Breakpoint，error code：%x\n", code);
        break;
    case EXCEPTION_DATATYPE_MISALIGNMENT:
        printf("Misaligned data，error code：%x\n", code);
        break;
    case EXCEPTION_SINGLE_STEP:
        printf("Single instruction，error code：%x\n", code);
        break;
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        printf("Out of array bounds，error code：%x\n", code);
        break;
    case EXCEPTION_FLT_DENORMAL_OPERAND:
        printf("Denormalized floating-point value，error code：%x\n", code);
        break;
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        printf("Floating point divide-by-zero，error code：%x\n", code);
        break;
    case EXCEPTION_FLT_INEXACT_RESULT:
        printf("Inexact floating point value，error code：%x\n", code);
        break;
    case EXCEPTION_FLT_INVALID_OPERATION:
        printf("Invalid floating point operation，error code：%x\n", code);
        break;
    case EXCEPTION_FLT_OVERFLOW:
        printf("Floating point overflow，error code：%x\n", code);
        break;
    case EXCEPTION_FLT_STACK_CHECK:
        printf("Floating point stack overflow，error code：%x\n", code);
        break;
    case EXCEPTION_FLT_UNDERFLOW:
        printf("Floating point underflow，error code：%x\n", code);
        break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
        printf("Integer divide by zero，error code：%x\n", code);
        break;
    case EXCEPTION_INT_OVERFLOW:
        printf("Integer overflow，error code：%x\n", code);
        break;
    case EXCEPTION_IN_PAGE_ERROR:
        printf("Invalid page access，error code：%x\n", code);
        break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:
        printf("invalid instruction，error code：%x\n", code);
        break;
    case EXCEPTION_STACK_OVERFLOW:
        printf("Stack overflow，error code：%x\n", code);
        break;
    case EXCEPTION_INVALID_HANDLE:
        printf("Invalid handle，error code：%x\n", code);
        break;
    default:
        if (code & (1 << 29))
            printf("Custom exception，error code：%x\n", code);
        else
            printf("Unknown exception，error code：%x\n", code);
        break;
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

LONG WINAPI ExpFilter(EXCEPTION_POINTERS* pExp, DWORD dwExpCode)
{
    seh_filer(dwExpCode);
    //StackWalker sw;  // output to default (Debug-Window)
    StackWalker sw; // output to the console
    sw.ShowCallstack(GetCurrentThread(), pExp->ContextRecord);
    std::cout << "----------------------分割线------------------------------------\n";

    std::ofstream log_file;
    struct tm* cur_time = nullptr;
    //memset(cur_time, 0, sizeof(cur_time));
    time_t nowtime = time(NULL);
    cur_time = std::localtime(&nowtime);
    char buf[30];
    strftime(buf, sizeof(buf), "%Y_%m_%d_%H_%M_%S", cur_time);
    //std::string path = ".\\log\\hs_err_pid" + std::to_string(_getpid()) + ".log";

    std::string filename = buf;
    std::string path = ".\\log\\hs_err_" + filename + ".log";
  
    log_file.open(path, std::ios::in|std::ios::out | std::ios::trunc);
    if (log_file.is_open()) {
        std::cout << "# An error report file with more information is saved as:  " << path << std::endl;
        std::cout << std::endl;
//#define USE_LOG_FILE
    } else {
        std::cout << "# Can not save log file, dump to screen.." << std::endl;
//#define USE_COUT
    }
    sw.show_callstack(log_file, pExp->ContextRecord);
    log_file.close();
    return EXCEPTION_EXECUTE_HANDLER;
}

static BOOL PreventSetUnhandledExceptionFilter()
{
    HMODULE hKernel32 = LoadLibrary(_T("kernel32.dll"));
    if (hKernel32 == NULL)
        return FALSE;
    void* pOrgEntry = GetProcAddress(hKernel32, "SetUnhandledExceptionFilter");
    if (pOrgEntry == NULL)
        return FALSE;

#ifdef _M_IX86
    // Code for x86:
    // 33 C0                xor         eax,eax
    // C2 04 00             ret         4
    unsigned char szExecute[] = { 0x33, 0xC0, 0xC2, 0x04, 0x00 };
#elif _M_X64
    // 33 C0                xor         eax,eax
    // C3                   ret
    unsigned char szExecute[] = { 0x33, 0xC0, 0xC3 };
#elif _M_ARM64  
    unsigned char szExecute[] = {
        0x00, 0x00, 0x80, 0x52, // mov     w0, #0
        0xC0, 0x03, 0x5F, 0xD6 // ret       
    };
#else
#error "The following code only works for x86 and x64!"
#endif

    DWORD dwOldProtect = 0;
    BOOL  bProt = VirtualProtect(pOrgEntry, sizeof(szExecute), PAGE_EXECUTE_READWRITE, &dwOldProtect);

    SIZE_T bytesWritten = 0;
    BOOL   bRet = WriteProcessMemory(GetCurrentProcess(), pOrgEntry, szExecute, sizeof(szExecute),
        &bytesWritten);

    if ((bProt != FALSE) && (dwOldProtect != PAGE_EXECUTE_READWRITE))
    {
        DWORD dwBuf;
        VirtualProtect(pOrgEntry, sizeof(szExecute), dwOldProtect, &dwBuf);
    }
    return bRet;
}

static TCHAR s_szExceptionLogFileName[_MAX_PATH] = _T("\\exceptions.log"); // default
static BOOL  s_bUnhandledExeptionFilterSet = FALSE;
static LONG __stdcall CrashHandlerExceptionFilter(EXCEPTION_POINTERS* pExPtrs)
{
    StackWalker sw; // output to console
    sw.ShowCallstack(GetCurrentThread(), pExPtrs->ContextRecord);
    TCHAR lString[500];
    _stprintf_s(lString,
        _T("*** Unhandled Exception! See console output for more infos!\n")
        _T("   ExpCode: 0x%8.8X\n")
        _T("   ExpFlags: %d\n")
#if _MSC_VER >= 1900
        _T("   ExpAddress: 0x%8.8p\n")
#else
        _T("   ExpAddress: 0x%8.8X\n")
#endif
        _T("   Please report!"),
        pExPtrs->ExceptionRecord->ExceptionCode, pExPtrs->ExceptionRecord->ExceptionFlags,
        pExPtrs->ExceptionRecord->ExceptionAddress);
    FatalAppExit(-1, lString);
    return EXCEPTION_CONTINUE_SEARCH;
}

static void InitUnhandledExceptionFilter()
{
    TCHAR szModName[_MAX_PATH];
    if (GetModuleFileName(NULL, szModName, sizeof(szModName) / sizeof(TCHAR)) != 0)
    {
        _tcscpy_s(s_szExceptionLogFileName, szModName);
        _tcscat_s(s_szExceptionLogFileName, _T(".exp.log"));
    }
    if (s_bUnhandledExeptionFilterSet == FALSE)
    {
        // set global exception handler (for handling all unhandled exceptions)
        SetUnhandledExceptionFilter(CrashHandlerExceptionFilter);
#if defined _M_X64 || defined _M_IX86 || defined _M_ARM64
        PreventSetUnhandledExceptionFilter();
#endif
        s_bUnhandledExeptionFilterSet = TRUE;
    }
}

int main() {

    std::cout << "1111\n";
    __try {
        //BYTE* pch;
        //pch = (BYTE*)00001234;   //给予一个非法地址 
        //*pch = 6; //对非法地址赋值，会造成Access Violation 异常 
        test2();
    }

    __except (ExpFilter(GetExceptionInformation(), GetExceptionCode())) {
        //SW.ShowCallstack();
    }    
     

    return 0;
}