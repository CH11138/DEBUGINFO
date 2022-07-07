// exception.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <iostream>

#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <string>
#include <typeinfo>
#include <unordered_map>
#include <utility>
#include<stdio.h>
#include<winsock2.h>    //该头文件需在windows.h之前
#include<windows.h>
#include<string>
#include <versionhelpers.h>
#include<winver.h>

#include<process.h>
#include<Psapi.h>
#include<inttypes.h>    //---PRIxPTR
#include <iomanip>


#include<ImageHlp.h>   //----STACKFRAME
#include <cassert>
#include "windbghelp.h"
#include "symbolengine.h"
 


#pragma warning(disable: 4996)
#pragma comment(lib, "version.lib")

using namespace std;

#define DEBUG 0;
#define PTR_FORMAT "0x%08" PRIxPTR

typedef u_char* address;

// Callback for loaded module information
// Input parameters:
//    char*     module_file_name,
//    address   module_base_addr,
//    address   module_top_addr,
//    void*     param
typedef int (*LoadedModulesCallbackFunc)(const char*, address, address, void*);
typedef uint64_t u8;

// Convert pointer to intptr_t, for use in printing pointers.
inline intptr_t p2i(const volatile void* p) {
    return (intptr_t)p;
}


int  checkline() {
    int line = __LINE__;
    return line;
}


//系统版本信息
void print_windows_version(std::ostream& st) {
    VS_FIXEDFILEINFO* file_info;
    TCHAR kernel32_path[MAX_PATH];
    UINT len, ret;

    bool is_workstation = !IsWindowsServer();

    // Get the full path to \Windows\System32\kernel32.dll and use that for
    // determining what version of Windows we're running on.
    len = MAX_PATH - (UINT)strlen("\\kernel32.dll") - 1;
    ret = GetSystemDirectory(kernel32_path, len);
    if (ret == 0 || ret > len) {
        st << "Call to GetSystemDirectory failed\n";
        return;
    }
    //TCHAR --> char* 需要unicode字符集换成多字节字符集
    strncat(kernel32_path, "\\kernel32.dll", MAX_PATH - ret);

    DWORD version_size = GetFileVersionInfoSize(kernel32_path, NULL);
    if (version_size == 0) {
        st << "Call to GetFileVersionInfoSize failed\n";
        return;
    }
    //与java原来相比，简化了申请内存方式，合理性存疑。。。
    LPTSTR version_info = (LPTSTR)malloc(version_size * sizeof(DWORD));
    if (version_info == NULL) {
        st << "Failed to allocate version_info";
        return;
    }
    //
    if (!GetFileVersionInfo(kernel32_path, NULL, version_size, version_info)) {
        free(version_info);
        st << "Call to GetFileVersionInfo failed\n";
        return;
    }

    if (!VerQueryValue(version_info, TEXT("\\"), (LPVOID*)&file_info, &len)) {
        free(version_info);
        st << "Call to VerQueryValue failed" << std::endl;
        return;
    }

    int major_version = HIWORD(file_info->dwProductVersionMS);
    int minor_version = LOWORD(file_info->dwProductVersionMS);
    int build_number = HIWORD(file_info->dwProductVersionLS);
    int build_minor = LOWORD(file_info->dwProductVersionLS);
    int os_vers = major_version * 1000 + minor_version;
    free(version_info);

    st << " Windows ";
    switch (os_vers) {
    case 6000:
        if (is_workstation) {
            st << "Vista";
        }
        else {
            st << "Server 2008";
        }
        break;

    case 6001:
        if (is_workstation) {
            st << "7";
        }
        else {
            st << "Server 2008 R2";
        }
        break;

    case 6002:
        if (is_workstation) {
            st << "8";
        }
        else {
            st << "Server 2012";
        }
        break;

    case 6003:
        if (is_workstation) {
            st << "8.1";
        }
        else {
            st << "Server 2012 R2";
        }
        break;

    case 10000:
        if (is_workstation) {
            if (build_number >= 22000) {
                st << "11";
            }
            else {
                st << "10";
            }
        }
        else {
            // distinguish Windows Server by build number
            // - 2016 GA 10/2016 build: 14393
            // - 2019 GA 11/2018 build: 17763
            // - 2022 GA 08/2021 build: 20348
            if (build_number > 20347) {
                st << "Server 2022";
            }
            else if (build_number > 17762) {
                st << "Server 2019";
            }
            else {
                st << "Server 2016";
            }
        }
        break;
    default:
        // Unrecognized windows, print out its major and minor versions
        st << major_version << "." << minor_version;
        break;
    }
    // Retrieve SYSTEM_INFO from GetNativeSystemInfo call so that we could
    // find out whether we are running on 64 bit processor or not
    SYSTEM_INFO si;
    ZeroMemory(&si, sizeof(SYSTEM_INFO));
    GetNativeSystemInfo(&si);
    if ((si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ||
        (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64)) {
        st << " , 64 bit";
    }
    st << " Build " << build_number;
    st << " (" << major_version << "." << minor_version << "." << build_number << "." << build_minor << ")";

    st << std::endl;
}

//cpu相关信息
void getSysInfo(std::ostream& st)
{
    
    //OSVERSIONINFOEX osvi;
    //osvi.dwOSVersionInfoSize = sizeof(osvi);
    //if (GetVersionEx((LPOSVERSIONINFOW)&osvi))
    //{
    //    cout << "操作系统版本 :   " << osvi.dwMajorVersion << "."<<osvi.dwMinorVersion <<"."<< osvi.dwBuildNumber << "."<<endl;
    //    cout << "Service Pack :   " << osvi.wServicePackMajor << osvi.wServicePackMinor << endl;
    //}
   
    SYSTEM_INFO  sysInfo;    //该结构体包含了当前计算机的信息：计算机的体系结构、中央处理器的类型、系统中中央处理器的数量、页面的大小以及其他信息。
    GetSystemInfo(&sysInfo);
    if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        st << "操作系统架构: X64(AMD or Intel)" << endl;
    }
    else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM) {
        st << "操作系统架构: AMD" << endl;
    }
    else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) {
        st << "操作系统架构: Intel 服务器" << endl;
    }
    else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
        st << "操作系统架构: X86\n" << endl;
    }
    else {
        st << "操作系统架构: 未知的架构\n" << endl;
    }

    st << "cpu级别 :        " << sysInfo.wProcessorLevel << endl;
    st << "cpu型号 :        " << hex << sysInfo.wProcessorRevision << endl;
    st << "cpu掩码 :        " << dec<<sysInfo.dwActiveProcessorMask << endl;
    st << "cpu核心数 :        " << sysInfo.dwNumberOfProcessors << endl;
    st << "处理器类型 :        " << sysInfo.dwProcessorType << endl;
    st << "页面大小 :          " << sysInfo.dwPageSize << endl;
    st << "应用程序最小地址 :  " << sysInfo.lpMinimumApplicationAddress << endl;
    st << "应用程序最大地址 :  " << sysInfo.lpMaximumApplicationAddress << endl;
    st << "虚拟内存分配粒度 :  " << sysInfo.dwAllocationGranularity << endl;
}


// List of environment variables that should be reported in error log file.
static const char* env_list[] = {
    //// All platforms
    "JAVA_HOME", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH",
    "PATH", "USERNAME",

    //// Env variables that are defined on Linux/BSD
    "LD_LIBRARY_PATH", "LD_PRELOAD", "SHELL", "DISPLAY",
    "HOSTTYPE", "OSTYPE", "ARCH", "MACHTYPE",
    "LANG", "LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LC_TIME",
    "TERM", "TMPDIR", "TZ",

    //// defined on AIX
    "LIBPATH", "LDR_PRELOAD", "LDR_PRELOAD64",

    // defined on Linux/AIX/BSD
    "_JAVA_SR_SIGNUM",

    //// defined on Darwin
    "DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH", "DYLD_FALLBACK_FRAMEWORK_PATH",
    "DYLD_INSERT_LIBRARIES",

    // defined on Windows
    "OS", "PROCESSOR_IDENTIFIER", "_ALT_JAVA_HOME_DIR", "TMP", "TEMP",
    (const char*)0 
};

//环境变量信息
void print_environment_variables(ostream& st, const char** env_list) {
    if (env_list) {
        st << "Environment Variables:" << endl;

        for (int i = 0; env_list[i] != NULL; i++) {
            char* envvar = ::getenv(env_list[i]);
            if (envvar != NULL) {
                st << env_list[i] << "=" << envvar;
                // Use separate cr() printing to avoid unnecessary buffer operations that might cause truncation.
                st << std::endl;
            }
        }
    }
}

//-----------------动态链接库 或者内存映射--------------------
int get_loaded_modules_info(LoadedModulesCallbackFunc callback, void* param)
{
    HANDLE hProcess;

#define MAX_NUM_MODULES 128
    HMODULE modules[MAX_NUM_MODULES];
    static char filename[MAX_PATH];
    int result = 0;
    int pid = _getpid();   //修改 ----得到当前进程ID
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);
    if (hProcess == NULL)
        return 0;

    DWORD size_needed;
    if (!EnumProcessModules(hProcess, modules, sizeof(modules), &size_needed))
    {
        CloseHandle(hProcess);
        return 0;
    }

    // number of modules that are currently loaded
    int num_modules = size_needed / sizeof(HMODULE);

    for (int i = 0; i < min(num_modules, MAX_NUM_MODULES); i++)
    {
        // Get Full pathname:
        if (!GetModuleFileNameEx(hProcess, modules[i], filename, sizeof(filename)))
        {
            filename[0] = '\0';
        }

        MODULEINFO modinfo;
        if (!GetModuleInformation(hProcess, modules[i], &modinfo, sizeof(modinfo)))
        {
            modinfo.lpBaseOfDll = nullptr;
            modinfo.SizeOfImage = 0;
        }

        // Invoke callback function
        result = callback(filename, (address)modinfo.lpBaseOfDll,
            (address)((u8)modinfo.lpBaseOfDll + (u8)modinfo.SizeOfImage), param);
        if (result)
            break;
    }

    CloseHandle(hProcess);
    return result;
}

static int _print_module(const char* fname, address base_address,
    address top_address, void* param)
{
    if (!param)
        return -1;

    ostream* st = (ostream*)param;
#if DEBUG
    (*st) << "st ok" << std::endl;
#endif
    //ostream似乎无法直接打印unsigned char*类型
    //auto ba = std::format("{:016x}", base_address);

  /*  (*st)<<hex<< setfill('0')<< setw(8)<<base_address 
        << "-" 
        << hex << setfill('0') << setw(8) << top_address
        << "\t" << fname << "\n"; */

    printf(PTR_FORMAT " - " PTR_FORMAT " \t%s\n", base_address, top_address, fname);



    return 0;
}

void print_dll_info(ostream* st)
{
    (*st) << ("Dynamic libraries:") << std::endl;
    get_loaded_modules_info(_print_module, (void*)st);
}

//-----------------动态链接库 或者内存映射--------------------

//------------------------------打印堆栈边界
// current_stack_base()
//   Returns the base of the stack, which is the stack's
//   starting address.  This function must be called
//   while running on the stack of the thread being queried.
//返回堆栈的起始地址
address current_stack_base()
{
    MEMORY_BASIC_INFORMATION minfo;
    address stack_bottom;
    size_t stack_size;

    VirtualQuery(&minfo, &minfo, sizeof(minfo));
    stack_bottom = (address)minfo.AllocationBase;
    stack_size = minfo.RegionSize;

    // Add up the sizes of all the regions with the same
    // AllocationBase.
    while (1)
    {
        VirtualQuery(stack_bottom + stack_size, &minfo, sizeof(minfo));
        if (stack_bottom == (address)minfo.AllocationBase)
        {
            stack_size += minfo.RegionSize;
        }
        else
        {
            break;
        }
    }
    return stack_bottom + stack_size;
}
//返回当前栈的大小
size_t current_stack_size()
{
    size_t sz;
    MEMORY_BASIC_INFORMATION minfo;
    VirtualQuery(&minfo, &minfo, sizeof(minfo));
    sz = (size_t)current_stack_base() - (size_t)minfo.AllocationBase;
    return sz;
}

//打印堆栈边界
void print_stack_bound(ostream& st) {
    st << "stack:   ";
    address stack_top = current_stack_base();
    size_t stack_size = current_stack_size();
    address stack_bottom = stack_top - stack_size;
    printf("[" PTR_FORMAT "," PTR_FORMAT "]", p2i(stack_bottom), p2i(stack_top));
    st << std::endl;

    //...  frame   _context   stack pointer
    //_conetext参数传的是windows下struct _EXCEPTION_POINTERS中的ContextRecord，本质是_CONTEXT
    //未完成....
}

//------------------------------打印堆栈边界

//  -------------printing native stack-------------

static const char* file_separator() { return "/"; }

struct _modinfo
{
    address addr;
    char* full_path; // point to a char buffer
    int buflen;      // size of the buffer
    address base_addr;
};

static int _locate_module_by_addr(const char* mod_fname, address base_addr,
    address top_address, void* param)
{
    struct _modinfo* pmod = (struct _modinfo*)param;
    if (!pmod)
        return -1;

    if (base_addr <= pmod->addr &&
        top_address > pmod->addr)
    {
        // if a buffer is provided, copy path name to the buffer
        if (pmod->full_path)
        {
            snprintf(pmod->full_path, pmod->buflen, "%s", mod_fname);
        }
        pmod->base_addr = base_addr;
        return 1;
    }
    return 0;
}

bool dll_address_to_library_name(address addr, char* buf,
    int buflen, int* offset)
{
    // buf is not optional, but offset is optional
    assert(buf != NULL, "sanity check");
    // NOTE: the reason we don't use SymGetModuleInfo() is it doesn't always
    //       return the full path to the DLL file, sometimes it returns path
    //       to the corresponding PDB file (debug info); sometimes it only
    //       returns partial path, which makes life painful.

    struct _modinfo mi;
    mi.addr = addr;
    mi.full_path = buf;
    mi.buflen = buflen;
    if (get_loaded_modules_info(_locate_module_by_addr, (void*)&mi))
    {
        // buf already contains path name
        if (offset)
            *offset = addr - mi.base_addr;
        return true;
    }

    buf[0] = '\0';
    if (offset)
        *offset = -1;
    return false;
}


bool dll_address_to_function_name(address addr, char* buf,
    int buflen, int* offset,bool demangle)
{
    // buf is not optional, but offset is optional
    assert(buf != NULL, "sanity check");

    if (SymbolEngine::decode(addr, buf, buflen, offset, demangle))  //decode过于复杂... 待研究...
    {
        return true;
    }
    if (offset != NULL)
        *offset = -1;
    buf[0] = '\0';
    return false;
}

void print_C_frame(ostream& st, char* buf, int buflen, address pc) {
    // C/C++ frame
    //bool in_vm = address_is_in_vm(pc);  //check if addr is inside jvm.dll  
    //st<<in_vm ? "V" : "C";
    //Windows下似乎不用检查 跳过
    st << "C ";

    int offset;
    bool found;

    if (buf == NULL || buflen < 1) return;
    // libname
    buf[0] = '\0';
    found = dll_address_to_library_name(pc, buf, buflen, &offset);
    if (found && buf[0] != '\0') {
        // skip directory names
        const char* p1, * p2;
        p1 = buf;
        int len = (int)strlen(file_separator());
        while ((p2 = strstr(p1, file_separator())) != NULL) p1 = p2 + len;
        printf("  [%s+0x%x]", p1, offset);
    }
    else {
        printf("  " PTR_FORMAT, p2i(pc));
    }

    found = dll_address_to_function_name(pc, buf, buflen, &offset,/*默认参数true*/true);
    if (found) {
        printf("  %s+0x%x", buf, offset);
    }
}

bool platform_print_native_stack(ostream& st, const void* context, char* buf, int buf_size) {

    CONTEXT ctx;
    if (context != NULL) {
        memcpy(&ctx, context, sizeof(ctx));
    }
    else {
        RtlCaptureContext(&ctx);
    }

    st << "Native frames : (J = compiled Java code, j = interpreted, Vv = VM code, C = native code)" << endl;

    STACKFRAME stk;
    memset(&stk, 0, sizeof(stk));
    stk.AddrStack.Offset = ctx.Rsp;
    stk.AddrStack.Mode = AddrModeFlat;
    stk.AddrFrame.Offset = ctx.Rbp;
    stk.AddrFrame.Mode = AddrModeFlat;
    stk.AddrPC.Offset = ctx.Rip;
    stk.AddrPC.Mode = AddrModeFlat;

    int count = 0;
    address lastpc = 0;

    intptr_t StackPrintLimit = 100;  //手动定义

    while (count++ < StackPrintLimit) {
        intptr_t* sp = (intptr_t*)stk.AddrStack.Offset;
        intptr_t* fp = (intptr_t*)stk.AddrFrame.Offset; // NOT necessarily the same as ctx.Rbp!
        address pc = (address)stk.AddrPC.Offset;

        if (pc != NULL) {
            if (count == 2 && lastpc == pc) {
                // Skip it -- StackWalk64() may return the same PC
                // (but different SP) on the first try.
            }
            else {
                // Don't try to create a frame(sp, fp, pc) -- on WinX64, stk.AddrFrame
                // may not contain what Java expects, and may cause the frame() constructor
                // to crash. Let's just print out the symbolic address.
                print_C_frame(st, buf, buf_size, pc);
                // print source file and line, if available
                char buf[128];
                int line_no;
                if (SymbolEngine::get_source_info(pc, buf, sizeof(buf), &line_no)) {
                    //st->print("  (%s:%d)", buf, line_no);
                    st << "  (" << buf << ":" << line_no << ")";
                }
                st << endl;
            }
            lastpc = pc;
        }

        PVOID p = WindowsDbgHelp::symFunctionTableAccess64(GetCurrentProcess(), stk.AddrPC.Offset);
        if (!p) {
            // StackWalk64() can't handle this PC. Calling StackWalk64 again may cause crash.
            break;
        }

        BOOL result = WindowsDbgHelp::stackWalk64(
            IMAGE_FILE_MACHINE_AMD64,  // __in      DWORD MachineType,
            GetCurrentProcess(),       // __in      HANDLE hProcess,
            GetCurrentThread(),        // __in      HANDLE hThread,
            &stk,                      // __inout   LP STACKFRAME64 StackFrame,
            &ctx);                     // __inout   PVOID ContextRecord,

        if (!result) {
            break;
        }
    }
    if (count > StackPrintLimit) {
        st << "...<more frames>..." << endl;
    }
    st << std::endl;

    return true;
}

//  -------------printing native stack-------------


//----------------线程信息------------------------

int current_process_id() {
    return (int)(_getpid());
}

intptr_t current_thread_id() {
    return GetCurrentThreadId(); 
}

//// Thread::print_on_error() is called by fatal error handler. Don't use
//// any lock or allocate memory.
//void print_on_error(ostream* st, char* buf, int buflen){
//    //assert(!(is_Compiler_thread() || is_Java_thread()), "Can't call name() here if it allocates");
//
//    st->print("%s \"%s\"", type_name(), name());
//
//    OSThread* os_thr = osthread();
//    if (os_thr != NULL) {
//        if (os_thr->get_state() != ZOMBIE) {
//            st->print(" [stack: " PTR_FORMAT "," PTR_FORMAT "]",
//                p2i(stack_end()), p2i(stack_base()));
//            st->print(" [id=%d]", osthread()->thread_id());
//        }
//        else {
//            st->print(" terminated");
//        }
//    }
//    else {
//        st->print(" unknown state (no osThread)");
//    }
//    ThreadsSMRSupport::print_info_on(this, st);
//}






//----------------线程信息------------------------


void sysT() {
    cout << "-----------------系统信息----------------"<<endl;
    print_windows_version(std::cout);  
}

void cpuT() {
    cout << "-----------------cpu测试-----------------" << endl;
    getSysInfo(std::cout);

}

void environmentT() {
    cout << "----------------环境变量测试-------------" << endl;
    print_environment_variables(std::cout, env_list);
}


void dllT() {
    cout << "----------------动态链接库测试-------------" << endl;
    print_dll_info(&std::cout);
}

void stackBoundT() {
    cout << "-----------------堆栈边界--------------------" << endl;
    print_stack_bound(std::cout);
}

void nativeStackT() {
    cout << "-----------------printing native stack----------" << endl;
    static char buf[2000];
    platform_print_native_stack(std::cout, NULL, buf, sizeof(buf));
}


void main_01()
{
    //cpu测试 ---------------------->测试正确
    // 
    cpuT();
    
    //系统版本信息测试  --------------->测试正确
    // 
    sysT();                

    //环境变量测试  ------------------->测试正确
    // 
    environmentT(); 

    //动态链接库测试 ------------------->链接库的地址输出格式存在问题
    
    dllT();

    //堆栈边界测试 ----------------------->测试似乎成功...
    stackBoundT();


    //堆栈信息测试  ------------------------->测试似乎正确
    ////要先初始化symbolenginede和windbghelp中的临界区
    SymbolEngine::pre_initialize();
    WindowsDbgHelp::pre_initialize();
    nativeStackT();

    //线程信息测试 -------------------------->
    
    //int line = __LINE__;
    //std::cout << line << "    " << checkline() << std::endl;
    //return EXCEPTION_EXECUTE_HANDLER;
}

DWORD main_02(EXCEPTION_POINTERS* ep)
{
    //cpu测试 ---------------------->测试正确
    // 
    cpuT();

    //系统版本信息测试  --------------->测试正确
    // 
    sysT();

    //环境变量测试  ------------------->测试正确
    // 
    environmentT();

    //动态链接库测试 ------------------->链接库的地址输出格式存在问题

    dllT();

    //堆栈边界测试 ----------------------->测试似乎成功...
    stackBoundT();


    //堆栈信息测试  ------------------------->测试似乎正确
    ////要先初始化symbolenginede和windbghelp中的临界区
    SymbolEngine::pre_initialize();
    WindowsDbgHelp::pre_initialize();
    nativeStackT();


    return EXCEPTION_EXECUTE_HANDLER;
}

class water
{
public:
    water() {
        PH = 100;
    }

    ~water() {

    }
    int getWater() { 
        int a = 0; 
        return PH / a;
    }

private:
    int PH = 10;
};

int create_class() {
    std::shared_ptr<water> run = {};
    return run->getWater();
}

int zero() {

 
    int a = 0;
    int b = 10;
    if (a == 0) RaiseException(EXCEPTION_INT_DIVIDE_BY_ZERO, 0, 0, 0);
    return b / a;
 
}

int seh_filer(int code)
{
    switch (code)
    {
    case EXCEPTION_ACCESS_VIOLATION:
        printf("存储保护异常，错误代码：%x\n", code);
        break;
    case EXCEPTION_BREAKPOINT:
        printf("中断异常，错误代码：%x\n", code);
        break;
    case EXCEPTION_DATATYPE_MISALIGNMENT:
        printf("数据类型未对齐异常，错误代码：%x\n", code);
        break;
    case EXCEPTION_SINGLE_STEP:
        printf("单步中断异常，错误代码：%x\n", code);
        break;
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        printf("数组越界异常，错误代码：%x\n", code);
        break;
    case EXCEPTION_FLT_DENORMAL_OPERAND:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_INEXACT_RESULT:
    case EXCEPTION_FLT_INVALID_OPERATION:
    case EXCEPTION_FLT_OVERFLOW:
    case EXCEPTION_FLT_STACK_CHECK:
    case EXCEPTION_FLT_UNDERFLOW:
        printf("浮点数计算异常，错误代码：%x\n", code);
        break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
        printf("被0除异常，错误代码：%x\n", code);
        break;
    case EXCEPTION_INT_OVERFLOW:
        printf("数据溢出异常，错误代码：%x\n", code);
        break;
    case EXCEPTION_IN_PAGE_ERROR:
        printf("页错误异常，错误代码：%x\n", code);
        break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:
        printf("非法指令异常，错误代码：%x\n", code);
        break;
    case EXCEPTION_STACK_OVERFLOW:
        printf("堆栈溢出异常，错误代码：%x\n", code);
        break;
    case EXCEPTION_INVALID_HANDLE:
        printf("无效句病异常，错误代码：%x\n", code);
        break;
    default:
        if (code & (1 << 29))
            printf("用户自定义的软件异常，错误代码：%x\n", code);
        else
            printf("其它异常，错误代码：%x\n", code);
        break;
    }
    return 1;
}

int filter(unsigned int code, struct _EXCEPTION_POINTERS* ep) {
    if (code == EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_EXECUTE_HANDLER;
    }
    else {
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

int exception_int_divide_by_zero_filter(LPEXCEPTION_POINTERS p_exinfo)
{
    if (p_exinfo->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO)
    {
        printf("被0除异常\n");
        return 1;
    }
    else return 0;
}

int exception_access_violation_filter(LPEXCEPTION_POINTERS p_exinfo)
{
    if (p_exinfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
    {
        printf("存储保护异常\n");
        return 1;
    }
    else return 0;
}

int main() {

    ////可以捕获
    //__try {
    //    BYTE* pch;
    //    pch = (BYTE*)00001234;   //给予一个非法地址 
    //    *pch = 6; //对非法地址赋值，会造成Access Violation 异常 
    //}
    //__except (seh_filer(GetExceptionCode())) {
    //    main_01();
    //    cout << "访问异常" << endl;
    //}


    
    ////可以捕获
    __try {
        create_class();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        main_01();
        cout << "2222\n";
    }


    //可以捕获
    //__try {
    //    create_class();
    //    //zero();
    //}
    //__except (seh_filer(GetExceptionCode())) {
    //    main_01();
    //    cout << "2222\n";
    //}



    //__try {
    //    create_class();
    //}
    //__except (main_02(GetExceptionInformation())) {
    //    cout << "111111" << endl;
    //}





    return 0;
}


