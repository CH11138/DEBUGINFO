/**********************************************************************
 *
 * StackWalker.cpp
 * https://github.com/JochenKalmbach/StackWalker
 *
 * Old location: http://stackwalker.codeplex.com/
 *
 *
 * History:
 *  2005-07-27   v1    - First public release on http://www.codeproject.com/
 *                       http://www.codeproject.com/threads/StackWalker.asp
 *  2005-07-28   v2    - Changed the params of the constructor and ShowCallstack
 *                       (to simplify the usage)
 *  2005-08-01   v3    - Changed to use 'CONTEXT_FULL' instead of CONTEXT_ALL
 *                       (should also be enough)
 *                     - Changed to compile correctly with the PSDK of VC7.0
 *                       (GetFileVersionInfoSizeA and GetFileVersionInfoA is wrongly defined:
 *                        it uses LPSTR instead of LPCSTR as first parameter)
 *                     - Added declarations to support VC5/6 without using 'dbghelp.h'
 *                     - Added a 'pUserData' member to the ShowCallstack function and the
 *                       PReadProcessMemoryRoutine declaration (to pass some user-defined data,
 *                       which can be used in the readMemoryFunction-callback)
 *  2005-08-02   v4    - OnSymInit now also outputs the OS-Version by default
 *                     - Added example for doing an exception-callstack-walking in main.cpp
 *                       (thanks to owillebo: http://www.codeproject.com/script/profile/whos_who.asp?id=536268)
 *  2005-08-05   v5    - Removed most Lint (http://www.gimpel.com/) errors... thanks to Okko Willeboordse!
 *  2008-08-04   v6    - Fixed Bug: Missing LEAK-end-tag
 *                       http://www.codeproject.com/KB/applications/leakfinder.aspx?msg=2502890#xx2502890xx
 *                       Fixed Bug: Compiled with "WIN32_LEAN_AND_MEAN"
 *                       http://www.codeproject.com/KB/applications/leakfinder.aspx?msg=1824718#xx1824718xx
 *                       Fixed Bug: Compiling with "/Wall"
 *                       http://www.codeproject.com/KB/threads/StackWalker.aspx?msg=2638243#xx2638243xx
 *                       Fixed Bug: Now checking SymUseSymSrv
 *                       http://www.codeproject.com/KB/threads/StackWalker.aspx?msg=1388979#xx1388979xx
 *                       Fixed Bug: Support for recursive function calls
 *                       http://www.codeproject.com/KB/threads/StackWalker.aspx?msg=1434538#xx1434538xx
 *                       Fixed Bug: Missing FreeLibrary call in "GetModuleListTH32"
 *                       http://www.codeproject.com/KB/threads/StackWalker.aspx?msg=1326923#xx1326923xx
 *                       Fixed Bug: SymDia is number 7, not 9!
 *  2008-09-11   v7      For some (undocumented) reason, dbhelp.h is needing a packing of 8!
 *                       Thanks to Teajay which reported the bug...
 *                       http://www.codeproject.com/KB/applications/leakfinder.aspx?msg=2718933#xx2718933xx
 *  2008-11-27   v8      Debugging Tools for Windows are now stored in a different directory
 *                       Thanks to Luiz Salamon which reported this "bug"...
 *                       http://www.codeproject.com/KB/threads/StackWalker.aspx?msg=2822736#xx2822736xx
 *  2009-04-10   v9      License slightly corrected (<ORGANIZATION> replaced)
 *  2009-11-01   v10     Moved to http://stackwalker.codeplex.com/
 *  2009-11-02   v11     Now try to use IMAGEHLP_MODULE64_V3 if available
 *  2010-04-15   v12     Added support for VS2010 RTM
 *  2010-05-25   v13     Now using secure MyStrcCpy. Thanks to luke.simon:
 *                       http://www.codeproject.com/KB/applications/leakfinder.aspx?msg=3477467#xx3477467xx
 *  2013-01-07   v14     Runtime Check Error VS2010 Debug Builds fixed:
 *                       http://stackwalker.codeplex.com/workitem/10511
 *
 *
 * LICENSE (http://www.opensource.org/licenses/bsd-license.php)
 *
 *   Copyright (c) 2005-2013, Jochen Kalmbach
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without modification,
 *   are permitted provided that the following conditions are met:
 *
 *   Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *   Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *   Neither the name of Jochen Kalmbach nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 *   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **********************************************************************/

#include "StackWalker.h"

#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <windows.h>
#include <new>

#include <VersionHelpers.h>
#include <Psapi.h>
#include <process.h>
#include<inttypes.h>    //---PRIxPTR

#define FMT_HEADER_ONLY 1
#include "fmt/core.h"

#pragma comment(lib, "version.lib") // for "VerQueryValue"

#pragma warning(disable : 4826)
#if _MSC_VER >= 1900
#pragma warning(disable : 4091)   // For fix unnamed enums from DbgHelp.h
#endif


// If VC7 and later, then use the shipped 'dbghelp.h'-file
#pragma pack(push, 8)
#if _MSC_VER >= 1300
#include <dbghelp.h>
#include <iomanip>
#else
// inline the important dbghelp.h-declarations...
typedef enum
{
  SymNone = 0,
  SymCoff,
  SymCv,
  SymPdb,
  SymExport,
  SymDeferred,
  SymSym,
  SymDia,
  SymVirtual,
  NumSymTypes
} SYM_TYPE;
typedef struct _IMAGEHLP_LINE64
{
  DWORD   SizeOfStruct; // set to sizeof(IMAGEHLP_LINE64)
  PVOID   Key;          // internal
  DWORD   LineNumber;   // line number in file
  PCHAR   FileName;     // full filename
  DWORD64 Address;      // first instruction of line
} IMAGEHLP_LINE64, *PIMAGEHLP_LINE64;
typedef struct _IMAGEHLP_MODULE64
{
  DWORD    SizeOfStruct;         // set to sizeof(IMAGEHLP_MODULE64)
  DWORD64  BaseOfImage;          // base load address of module
  DWORD    ImageSize;            // virtual size of the loaded module
  DWORD    TimeDateStamp;        // date/time stamp from pe header
  DWORD    CheckSum;             // checksum from the pe header
  DWORD    NumSyms;              // number of symbols in the symbol table
  SYM_TYPE SymType;              // type of symbols loaded
  CHAR     ModuleName[32];       // module name
  CHAR     ImageName[256];       // image name
  CHAR     LoadedImageName[256]; // symbol file name
} IMAGEHLP_MODULE64, *PIMAGEHLP_MODULE64;
typedef struct _IMAGEHLP_SYMBOL64
{
  DWORD   SizeOfStruct;  // set to sizeof(IMAGEHLP_SYMBOL64)
  DWORD64 Address;       // virtual address including dll base address
  DWORD   Size;          // estimated size of symbol, can be zero
  DWORD   Flags;         // info about the symbols, see the SYMF defines
  DWORD   MaxNameLength; // maximum size of symbol name in 'Name'
  CHAR    Name[1];       // symbol name (null terminated string)
} IMAGEHLP_SYMBOL64, *PIMAGEHLP_SYMBOL64;
typedef enum
{
  AddrMode1616,
  AddrMode1632,
  AddrModeReal,
  AddrModeFlat
} ADDRESS_MODE;
typedef struct _tagADDRESS64
{
  DWORD64      Offset;
  WORD         Segment;
  ADDRESS_MODE Mode;
} ADDRESS64, *LPADDRESS64;
typedef struct _KDHELP64
{
  DWORD64 Thread;
  DWORD   ThCallbackStack;
  DWORD   ThCallbackBStore;
  DWORD   NextCallback;
  DWORD   FramePointer;
  DWORD64 KiCallUserMode;
  DWORD64 KeUserCallbackDispatcher;
  DWORD64 SystemRangeStart;
  DWORD64 Reserved[8];
} KDHELP64, *PKDHELP64;
typedef struct _tagSTACKFRAME64
{
  ADDRESS64 AddrPC;         // program counter
  ADDRESS64 AddrReturn;     // return address
  ADDRESS64 AddrFrame;      // frame pointer
  ADDRESS64 AddrStack;      // stack pointer
  ADDRESS64 AddrBStore;     // backing store pointer
  PVOID     FuncTableEntry; // pointer to pdata/fpo or NULL
  DWORD64   Params[4];      // possible arguments to the function
  BOOL      Far;            // WOW far call
  BOOL      Virtual;        // is this a virtual frame?
  DWORD64   Reserved[3];
  KDHELP64  KdHelp;
} STACKFRAME64, *LPSTACKFRAME64;
typedef BOOL(__stdcall* PREAD_PROCESS_MEMORY_ROUTINE64)(HANDLE  hProcess,
                                                        DWORD64 qwBaseAddress,
                                                        PVOID   lpBuffer,
                                                        DWORD   nSize,
                                                        LPDWORD lpNumberOfBytesRead);
typedef PVOID(__stdcall* PFUNCTION_TABLE_ACCESS_ROUTINE64)(HANDLE hProcess, DWORD64 AddrBase);
typedef DWORD64(__stdcall* PGET_MODULE_BASE_ROUTINE64)(HANDLE hProcess, DWORD64 Address);
typedef DWORD64(__stdcall* PTRANSLATE_ADDRESS_ROUTINE64)(HANDLE      hProcess,
                                                         HANDLE      hThread,
                                                         LPADDRESS64 lpaddr);

// clang-format off
#define SYMOPT_CASE_INSENSITIVE         0x00000001
#define SYMOPT_UNDNAME                  0x00000002
#define SYMOPT_DEFERRED_LOADS           0x00000004
#define SYMOPT_NO_CPP                   0x00000008
#define SYMOPT_LOAD_LINES               0x00000010
#define SYMOPT_OMAP_FIND_NEAREST        0x00000020
#define SYMOPT_LOAD_ANYTHING            0x00000040
#define SYMOPT_IGNORE_CVREC             0x00000080
#define SYMOPT_NO_UNQUALIFIED_LOADS     0x00000100
#define SYMOPT_FAIL_CRITICAL_ERRORS     0x00000200
#define SYMOPT_EXACT_SYMBOLS            0x00000400
#define SYMOPT_ALLOW_ABSOLUTE_SYMBOLS   0x00000800
#define SYMOPT_IGNORE_NT_SYMPATH        0x00001000
#define SYMOPT_INCLUDE_32BIT_MODULES    0x00002000
#define SYMOPT_PUBLICS_ONLY             0x00004000
#define SYMOPT_NO_PUBLICS               0x00008000
#define SYMOPT_AUTO_PUBLICS             0x00010000
#define SYMOPT_NO_IMAGE_SEARCH          0x00020000
#define SYMOPT_SECURE                   0x00040000
#define SYMOPT_DEBUG                    0x80000000
#define UNDNAME_COMPLETE                 (0x0000) // Enable full undecoration
#define UNDNAME_NAME_ONLY                (0x1000) // Crack only the name for primary declaration;
// clang-format on

#endif // _MSC_VER < 1300
#pragma pack(pop)

// Some missing defines (for VC5/6):
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#endif

// secure-CRT_functions are only available starting with VC8
#if _MSC_VER < 1400
#define strcpy_s(dst, len, src) strcpy(dst, src)
#define strncpy_s(dst, len, src, maxLen) strncpy(dst, len, src)
#define strcat_s(dst, len, src) strcat(dst, src)
#define _snprintf_s _snprintf
#define _tcscat_s _tcscat
#endif

static void MyStrCpy(char* szDest, size_t nMaxDestSize, const char* szSrc)
{
  if (nMaxDestSize <= 0)
    return;
  strncpy_s(szDest, nMaxDestSize, szSrc, _TRUNCATE);
  // INFO: _TRUNCATE will ensure that it is null-terminated;
  // but with older compilers (<1400) it uses "strncpy" and this does not!)
  szDest[nMaxDestSize - 1] = 0;
} // MyStrCpy

// Normally it should be enough to use 'CONTEXT_FULL' (better would be 'CONTEXT_ALL')
#define USED_CONTEXT_FLAGS CONTEXT_FULL

static const char* file_separator() { return "/"; }

static int console_count = 10; //����̨�������

struct _modinfo
{
    address addr;
    char* full_path; // point to a char buffer
    int buflen;      // size of the buffer
    address base_addr;
};

class StackWalkerInternal
{
public:
  StackWalkerInternal(StackWalker* parent, HANDLE hProcess, PCONTEXT ctx)
  {
    m_parent = parent;
    m_hDbhHelp = NULL;
    pSC = NULL;
    m_hProcess = hProcess;
    pSFTA = NULL;
    pSGLFA = NULL;
    pSGMB = NULL;
    pSGMI = NULL;
    pSGO = NULL;
    pSGSFA = NULL;
    pSI = NULL;
    pSLM = NULL;
    pSSO = NULL;
    pSW = NULL;
    pUDSN = NULL;
    pSGSP = NULL;
    m_ctx.ContextFlags = 0;
    if (ctx != NULL)
      m_ctx = *ctx;
  }

  ~StackWalkerInternal()
  {
    if (pSC != NULL)
      pSC(m_hProcess); // SymCleanup
    if (m_hDbhHelp != NULL)
      FreeLibrary(m_hDbhHelp);
    m_hDbhHelp = NULL;
    m_parent = NULL;
  }

  BOOL Init(LPCSTR szSymPath)
  {
    if (m_parent == NULL)
      return FALSE;
    // Dynamically load the Entry-Points for dbghelp.dll:
    // First try to load the newest one from
    TCHAR szTemp[4096];
    // But before we do this, we first check if the ".local" file exists
    if (GetModuleFileName(NULL, szTemp, 4096) > 0)
    {
      _tcscat_s(szTemp, _T(".local"));
      if (GetFileAttributes(szTemp) == INVALID_FILE_ATTRIBUTES)
      {
        // ".local" file does not exist, so we can try to load the dbghelp.dll from the "Debugging Tools for Windows"
        // Ok, first try the new path according to the architecture:
#ifdef _M_IX86
        if ((m_hDbhHelp == NULL) && (GetEnvironmentVariable(_T("ProgramFiles"), szTemp, 4096) > 0))
        {
          _tcscat_s(szTemp, _T("\\Debugging Tools for Windows (x86)\\dbghelp.dll"));
          // now check if the file exists:
          if (GetFileAttributes(szTemp) != INVALID_FILE_ATTRIBUTES)
          {
            m_hDbhHelp = LoadLibrary(szTemp);
          }
        }
#elif _M_X64
        if ((m_hDbhHelp == NULL) && (GetEnvironmentVariable(_T("ProgramFiles"), szTemp, 4096) > 0))
        {
          _tcscat_s(szTemp, _T("\\Debugging Tools for Windows (x64)\\dbghelp.dll"));
          // now check if the file exists:
          if (GetFileAttributes(szTemp) != INVALID_FILE_ATTRIBUTES)
          {
            m_hDbhHelp = LoadLibrary(szTemp);
          }
        }
#elif _M_IA64
        if ((m_hDbhHelp == NULL) && (GetEnvironmentVariable(_T("ProgramFiles"), szTemp, 4096) > 0))
        {
          _tcscat_s(szTemp, _T("\\Debugging Tools for Windows (ia64)\\dbghelp.dll"));
          // now check if the file exists:
          if (GetFileAttributes(szTemp) != INVALID_FILE_ATTRIBUTES)
          {
            m_hDbhHelp = LoadLibrary(szTemp);
          }
        }
#endif
        // If still not found, try the old directories...
        if ((m_hDbhHelp == NULL) && (GetEnvironmentVariable(_T("ProgramFiles"), szTemp, 4096) > 0))
        {
          _tcscat_s(szTemp, _T("\\Debugging Tools for Windows\\dbghelp.dll"));
          // now check if the file exists:
          if (GetFileAttributes(szTemp) != INVALID_FILE_ATTRIBUTES)
          {
            m_hDbhHelp = LoadLibrary(szTemp);
          }
        }
#if defined _M_X64 || defined _M_IA64
        // Still not found? Then try to load the (old) 64-Bit version:
        if ((m_hDbhHelp == NULL) && (GetEnvironmentVariable(_T("ProgramFiles"), szTemp, 4096) > 0))
        {
          _tcscat_s(szTemp, _T("\\Debugging Tools for Windows 64-Bit\\dbghelp.dll"));
          if (GetFileAttributes(szTemp) != INVALID_FILE_ATTRIBUTES)
          {
            m_hDbhHelp = LoadLibrary(szTemp);
          }
        }
#endif
      }
    }
    if (m_hDbhHelp == NULL) // if not already loaded, try to load a default-one
      m_hDbhHelp = LoadLibrary(_T("dbghelp.dll"));
    if (m_hDbhHelp == NULL)
      return FALSE;
    pSI = (tSI)GetProcAddress(m_hDbhHelp, "SymInitialize");
    pSC = (tSC)GetProcAddress(m_hDbhHelp, "SymCleanup");

    pSW = (tSW)GetProcAddress(m_hDbhHelp, "StackWalk64");
    pSGO = (tSGO)GetProcAddress(m_hDbhHelp, "SymGetOptions");
    pSSO = (tSSO)GetProcAddress(m_hDbhHelp, "SymSetOptions");

    pSFTA = (tSFTA)GetProcAddress(m_hDbhHelp, "SymFunctionTableAccess64");
    pSGLFA = (tSGLFA)GetProcAddress(m_hDbhHelp, "SymGetLineFromAddr64");
    pSGMB = (tSGMB)GetProcAddress(m_hDbhHelp, "SymGetModuleBase64");
    pSGMI = (tSGMI)GetProcAddress(m_hDbhHelp, "SymGetModuleInfo64");
    pSGSFA = (tSGSFA)GetProcAddress(m_hDbhHelp, "SymGetSymFromAddr64");
    pUDSN = (tUDSN)GetProcAddress(m_hDbhHelp, "UnDecorateSymbolName");
    pSLM = (tSLM)GetProcAddress(m_hDbhHelp, "SymLoadModule64");
    pSGSP = (tSGSP)GetProcAddress(m_hDbhHelp, "SymGetSearchPath");

    if (pSC == NULL || pSFTA == NULL || pSGMB == NULL || pSGMI == NULL || pSGO == NULL ||
        pSGSFA == NULL || pSI == NULL || pSSO == NULL || pSW == NULL || pUDSN == NULL ||
        pSLM == NULL)
    {
      FreeLibrary(m_hDbhHelp);
      m_hDbhHelp = NULL;
      pSC = NULL;
      return FALSE;
    }

    // SymInitialize
    if (this->pSI(m_hProcess, szSymPath, FALSE) == FALSE)
      this->m_parent->OnDbgHelpErr("SymInitialize", GetLastError(), 0);

    DWORD symOptions = this->pSGO(); // SymGetOptions
    symOptions |= SYMOPT_LOAD_LINES;
    symOptions |= SYMOPT_FAIL_CRITICAL_ERRORS;
    //symOptions |= SYMOPT_NO_PROMPTS;
    // SymSetOptions
    symOptions = this->pSSO(symOptions);

    char buf[StackWalker::STACKWALK_MAX_NAMELEN] = {0};
    if (this->pSGSP != NULL)
    {
      if (this->pSGSP(m_hProcess, buf, StackWalker::STACKWALK_MAX_NAMELEN) == FALSE)
        this->m_parent->OnDbgHelpErr("SymGetSearchPath", GetLastError(), 0);
    }
    char  szUserName[1024] = {0};
    DWORD dwSize = 1024;
    GetUserNameA(szUserName, &dwSize);
    this->m_parent->OnSymInit(buf, symOptions, szUserName);

    return TRUE;
  }

  StackWalker* m_parent;

  CONTEXT m_ctx;
  HMODULE m_hDbhHelp;
  HANDLE  m_hProcess;

#pragma pack(push, 8)
  typedef struct _IMAGEHLP_MODULE64_V3
  {
    DWORD    SizeOfStruct;         // set to sizeof(IMAGEHLP_MODULE64)
    DWORD64  BaseOfImage;          // base load address of module
    DWORD    ImageSize;            // virtual size of the loaded module
    DWORD    TimeDateStamp;        // date/time stamp from pe header
    DWORD    CheckSum;             // checksum from the pe header
    DWORD    NumSyms;              // number of symbols in the symbol table
    SYM_TYPE SymType;              // type of symbols loaded
    CHAR     ModuleName[32];       // module name
    CHAR     ImageName[256];       // image name
    CHAR     LoadedImageName[256]; // symbol file name
    // new elements: 07-Jun-2002
    CHAR  LoadedPdbName[256];   // pdb file name
    DWORD CVSig;                // Signature of the CV record in the debug directories
    CHAR  CVData[MAX_PATH * 3]; // Contents of the CV record
    DWORD PdbSig;               // Signature of PDB
    GUID  PdbSig70;             // Signature of PDB (VC 7 and up)
    DWORD PdbAge;               // DBI age of pdb
    BOOL  PdbUnmatched;         // loaded an unmatched pdb
    BOOL  DbgUnmatched;         // loaded an unmatched dbg
    BOOL  LineNumbers;          // we have line number information
    BOOL  GlobalSymbols;        // we have internal symbol information
    BOOL  TypeInfo;             // we have type information
    // new elements: 17-Dec-2003
    BOOL SourceIndexed; // pdb supports source server
    BOOL Publics;       // contains public symbols
  } IMAGEHLP_MODULE64_V3, *PIMAGEHLP_MODULE64_V3;

  typedef struct _IMAGEHLP_MODULE64_V2
  {
    DWORD    SizeOfStruct;         // set to sizeof(IMAGEHLP_MODULE64)
    DWORD64  BaseOfImage;          // base load address of module
    DWORD    ImageSize;            // virtual size of the loaded module
    DWORD    TimeDateStamp;        // date/time stamp from pe header
    DWORD    CheckSum;             // checksum from the pe header
    DWORD    NumSyms;              // number of symbols in the symbol table
    SYM_TYPE SymType;              // type of symbols loaded
    CHAR     ModuleName[32];       // module name
    CHAR     ImageName[256];       // image name
    CHAR     LoadedImageName[256]; // symbol file name
  } IMAGEHLP_MODULE64_V2, *PIMAGEHLP_MODULE64_V2;
#pragma pack(pop)

  // SymCleanup()
  typedef BOOL(__stdcall* tSC)(IN HANDLE hProcess);
  tSC pSC;

  // SymFunctionTableAccess64()
  typedef PVOID(__stdcall* tSFTA)(HANDLE hProcess, DWORD64 AddrBase);
  tSFTA pSFTA;

  // SymGetLineFromAddr64()
  typedef BOOL(__stdcall* tSGLFA)(IN HANDLE hProcess,
                                  IN DWORD64 dwAddr,
                                  OUT PDWORD pdwDisplacement,
                                  OUT PIMAGEHLP_LINE64 Line);
  tSGLFA pSGLFA;

  // SymGetModuleBase64()
  typedef DWORD64(__stdcall* tSGMB)(IN HANDLE hProcess, IN DWORD64 dwAddr);
  tSGMB pSGMB;

  // SymGetModuleInfo64()
  typedef BOOL(__stdcall* tSGMI)(IN HANDLE hProcess,
                                 IN DWORD64 dwAddr,
                                 OUT IMAGEHLP_MODULE64_V3* ModuleInfo);
  tSGMI pSGMI;

  // SymGetOptions()
  typedef DWORD(__stdcall* tSGO)(VOID);
  tSGO pSGO;

  // SymGetSymFromAddr64()
  typedef BOOL(__stdcall* tSGSFA)(IN HANDLE hProcess,
                                  IN DWORD64 dwAddr,
                                  OUT PDWORD64 pdwDisplacement,
                                  OUT PIMAGEHLP_SYMBOL64 Symbol);
  tSGSFA pSGSFA;

  // SymInitialize()
  typedef BOOL(__stdcall* tSI)(IN HANDLE hProcess, IN LPCSTR UserSearchPath, IN BOOL fInvadeProcess);
  tSI pSI;

  // SymLoadModule64()
  typedef DWORD64(__stdcall* tSLM)(IN HANDLE hProcess,
                                   IN HANDLE hFile,
                                   IN LPCSTR ImageName,
                                   IN LPCSTR ModuleName,
                                   IN DWORD64 BaseOfDll,
                                   IN DWORD SizeOfDll);
  tSLM pSLM;

  // SymSetOptions()
  typedef DWORD(__stdcall* tSSO)(IN DWORD SymOptions);
  tSSO pSSO;

  // StackWalk64()
  typedef BOOL(__stdcall* tSW)(DWORD                            MachineType,
                               HANDLE                           hProcess,
                               HANDLE                           hThread,
                               LPSTACKFRAME64                   StackFrame,
                               PVOID                            ContextRecord,
                               PREAD_PROCESS_MEMORY_ROUTINE64   ReadMemoryRoutine,
                               PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
                               PGET_MODULE_BASE_ROUTINE64       GetModuleBaseRoutine,
                               PTRANSLATE_ADDRESS_ROUTINE64     TranslateAddress);
  tSW pSW;

  // UnDecorateSymbolName()
  typedef DWORD(__stdcall WINAPI* tUDSN)(PCSTR DecoratedName,
                                         PSTR  UnDecoratedName,
                                         DWORD UndecoratedLength,
                                         DWORD Flags);
  tUDSN pUDSN;

  typedef BOOL(__stdcall WINAPI* tSGSP)(HANDLE hProcess, PSTR SearchPath, DWORD SearchPathLength);
  tSGSP pSGSP;

private:
// **************************************** ToolHelp32 ************************
#define MAX_MODULE_NAME32 255
#define TH32CS_SNAPMODULE 0x00000008
#pragma pack(push, 8)
  typedef struct tagMODULEENTRY32
  {
    DWORD   dwSize;
    DWORD   th32ModuleID;  // This module
    DWORD   th32ProcessID; // owning process
    DWORD   GlblcntUsage;  // Global usage count on the module
    DWORD   ProccntUsage;  // Module usage count in th32ProcessID's context
    BYTE*   modBaseAddr;   // Base address of module in th32ProcessID's context
    DWORD   modBaseSize;   // Size in bytes of module starting at modBaseAddr
    HMODULE hModule;       // The hModule of this module in th32ProcessID's context
    char    szModule[MAX_MODULE_NAME32 + 1];
    char    szExePath[MAX_PATH];
  } MODULEENTRY32;
  typedef MODULEENTRY32* PMODULEENTRY32;
  typedef MODULEENTRY32* LPMODULEENTRY32;


  BOOL GetModuleListTH32(HANDLE hProcess, DWORD pid)
  {
    // CreateToolhelp32Snapshot()
    typedef HANDLE(__stdcall * tCT32S)(DWORD dwFlags, DWORD th32ProcessID);
    // Module32First()
    typedef BOOL(__stdcall * tM32F)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
    // Module32Next()
    typedef BOOL(__stdcall * tM32N)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);

    // try both dlls...
    const TCHAR* dllname[] = {_T("kernel32.dll"), _T("tlhelp32.dll")};
    HINSTANCE    hToolhelp = NULL;
    tCT32S       pCT32S = NULL;
    tM32F        pM32F = NULL;
    tM32N        pM32N = NULL;

    HANDLE        hSnap;
    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    BOOL   keepGoing;
    size_t i;

    for (i = 0; i < (sizeof(dllname) / sizeof(dllname[0])); i++)
    {
      hToolhelp = LoadLibrary(dllname[i]);
      if (hToolhelp == NULL)
        continue;
      pCT32S = (tCT32S)GetProcAddress(hToolhelp, "CreateToolhelp32Snapshot");
      pM32F = (tM32F)GetProcAddress(hToolhelp, "Module32First");
      pM32N = (tM32N)GetProcAddress(hToolhelp, "Module32Next");
      if ((pCT32S != NULL) && (pM32F != NULL) && (pM32N != NULL))
        break; // found the functions!
      FreeLibrary(hToolhelp);
      hToolhelp = NULL;
    }

    if (hToolhelp == NULL)
      return FALSE;

    hSnap = pCT32S(TH32CS_SNAPMODULE, pid);
    if (hSnap == (HANDLE)-1)
    {
      FreeLibrary(hToolhelp);
      return FALSE;
    }

    keepGoing = !!pM32F(hSnap, &me);
    int cnt = 0;
    while (keepGoing)
    {
      this->LoadModule(hProcess, me.szExePath, me.szModule, (DWORD64)me.modBaseAddr,
                       me.modBaseSize);
      cnt++;
      keepGoing = !!pM32N(hSnap, &me);
    }
    CloseHandle(hSnap);
    FreeLibrary(hToolhelp);
    if (cnt <= 0)
      return FALSE;
    return TRUE;
  } // GetModuleListTH32

  // **************************************** PSAPI ************************
  typedef struct _MODULEINFO
  {
    LPVOID lpBaseOfDll;
    DWORD  SizeOfImage;
    LPVOID EntryPoint;
  } MODULEINFO, *LPMODULEINFO;

  BOOL GetModuleListPSAPI(HANDLE hProcess)
  {
    // EnumProcessModules()
    typedef BOOL(__stdcall * tEPM)(HANDLE hProcess, HMODULE * lphModule, DWORD cb,
                                   LPDWORD lpcbNeeded);
    // GetModuleFileNameEx()
    typedef DWORD(__stdcall * tGMFNE)(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename,
                                      DWORD nSize);
    // GetModuleBaseName()
    typedef DWORD(__stdcall * tGMBN)(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename,
                                     DWORD nSize);
    // GetModuleInformation()
    typedef BOOL(__stdcall * tGMI)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO pmi, DWORD nSize);

    HINSTANCE hPsapi;
    tEPM      pEPM;
    tGMFNE    pGMFNE;
    tGMBN     pGMBN;
    tGMI      pGMI;

    DWORD i;
    //ModuleEntry e;
    DWORD        cbNeeded;
    MODULEINFO   mi;
    HMODULE*     hMods = NULL;
    char*        tt = NULL;
    char*        tt2 = NULL;
    const SIZE_T TTBUFLEN = 8096;
    int          cnt = 0;

    hPsapi = LoadLibrary(_T("psapi.dll"));
    if (hPsapi == NULL)
      return FALSE;

    pEPM = (tEPM)GetProcAddress(hPsapi, "EnumProcessModules");
    pGMFNE = (tGMFNE)GetProcAddress(hPsapi, "GetModuleFileNameExA");
    pGMBN = (tGMFNE)GetProcAddress(hPsapi, "GetModuleBaseNameA");
    pGMI = (tGMI)GetProcAddress(hPsapi, "GetModuleInformation");
    if ((pEPM == NULL) || (pGMFNE == NULL) || (pGMBN == NULL) || (pGMI == NULL))
    {
      // we couldn't find all functions
      FreeLibrary(hPsapi);
      return FALSE;
    }

    hMods = (HMODULE*)malloc(sizeof(HMODULE) * (TTBUFLEN / sizeof(HMODULE)));
    tt = (char*)malloc(sizeof(char) * TTBUFLEN);
    tt2 = (char*)malloc(sizeof(char) * TTBUFLEN);
    if ((hMods == NULL) || (tt == NULL) || (tt2 == NULL))
      goto cleanup;

    if (!pEPM(hProcess, hMods, TTBUFLEN, &cbNeeded))
    {
      //_ftprintf(fLogFile, _T("%lu: EPM failed, GetLastError = %lu\n"), g_dwShowCount, gle );
      goto cleanup;
    }

    if (cbNeeded > TTBUFLEN)
    {
      //_ftprintf(fLogFile, _T("%lu: More than %lu module handles. Huh?\n"), g_dwShowCount, lenof( hMods ) );
      goto cleanup;
    }

    for (i = 0; i < cbNeeded / sizeof(hMods[0]); i++)
    {
      // base address, size
      pGMI(hProcess, hMods[i], &mi, sizeof(mi));
      // image file name
      tt[0] = 0;
      pGMFNE(hProcess, hMods[i], tt, TTBUFLEN);
      // module name
      tt2[0] = 0;
      pGMBN(hProcess, hMods[i], tt2, TTBUFLEN);

      DWORD dwRes = this->LoadModule(hProcess, tt, tt2, (DWORD64)mi.lpBaseOfDll, mi.SizeOfImage);
      if (dwRes != ERROR_SUCCESS)
        this->m_parent->OnDbgHelpErr("LoadModule", dwRes, 0);
      cnt++;
    }

  cleanup:
    if (hPsapi != NULL)
      FreeLibrary(hPsapi);
    if (tt2 != NULL)
      free(tt2);
    if (tt != NULL)
      free(tt);
    if (hMods != NULL)
      free(hMods);

    return cnt != 0;
  } // GetModuleListPSAPI

  DWORD LoadModule(HANDLE hProcess, LPCSTR img, LPCSTR mod, DWORD64 baseAddr, DWORD size)
  {
    CHAR* szImg = _strdup(img);
    CHAR* szMod = _strdup(mod);
    DWORD result = ERROR_SUCCESS;
    if ((szImg == NULL) || (szMod == NULL))
      result = ERROR_NOT_ENOUGH_MEMORY;
    else
    {
      if (pSLM(hProcess, 0, szImg, szMod, baseAddr, size) == 0)
        result = GetLastError();
    }
    ULONGLONG fileVersion = 0;
    if ((m_parent != NULL) && (szImg != NULL))
    {
      // try to retrieve the file-version:
      if ((this->m_parent->m_options & StackWalker::RetrieveFileVersion) != 0)
      {
        VS_FIXEDFILEINFO* fInfo = NULL;
        DWORD             dwHandle;
        DWORD             dwSize = GetFileVersionInfoSizeA(szImg, &dwHandle);
        if (dwSize > 0)
        {
          LPVOID vData = malloc(dwSize);
          if (vData != NULL)
          {
            if (GetFileVersionInfoA(szImg, dwHandle, dwSize, vData) != 0)
            {
              UINT  len;
              TCHAR szSubBlock[] = _T("\\");
              if (VerQueryValue(vData, szSubBlock, (LPVOID*)&fInfo, &len) == 0)
                fInfo = NULL;
              else
              {
                fileVersion =
                    ((ULONGLONG)fInfo->dwFileVersionLS) + ((ULONGLONG)fInfo->dwFileVersionMS << 32);
              }
            }
            free(vData);
          }
        }
      }

      // Retrieve some additional-infos about the module
      IMAGEHLP_MODULE64_V3 Module;
      const char*          szSymType = "-unknown-";
      if (this->GetModuleInfo(hProcess, baseAddr, &Module) != FALSE)
      {
        switch (Module.SymType)
        {
          case SymNone:
            szSymType = "-nosymbols-";
            break;
          case SymCoff: // 1
            szSymType = "COFF";
            break;
          case SymCv: // 2
            szSymType = "CV";
            break;
          case SymPdb: // 3
            szSymType = "PDB";
            break;
          case SymExport: // 4
            szSymType = "-exported-";
            break;
          case SymDeferred: // 5
            szSymType = "-deferred-";
            break;
          case SymSym: // 6
            szSymType = "SYM";
            break;
          case 7: // SymDia:
            szSymType = "DIA";
            break;
          case 8: //SymVirtual:
            szSymType = "Virtual";
            break;
        }
      }
      LPCSTR pdbName = Module.LoadedImageName;
      if (Module.LoadedPdbName[0] != 0)
        pdbName = Module.LoadedPdbName;
      this->m_parent->OnLoadModule(img, mod, baseAddr, size, result, szSymType, pdbName,
                                   fileVersion);
    }
    if (szImg != NULL)
      free(szImg);
    if (szMod != NULL)
      free(szMod);
    return result;
  }

public:
  BOOL LoadModules(HANDLE hProcess, DWORD dwProcessId)
  {
    // first try toolhelp32
    if (GetModuleListTH32(hProcess, dwProcessId))
      return true;
    // then try psapi
    return GetModuleListPSAPI(hProcess);
  }

  BOOL GetModuleInfo(HANDLE hProcess, DWORD64 baseAddr, IMAGEHLP_MODULE64_V3* pModuleInfo)
  {
    memset(pModuleInfo, 0, sizeof(IMAGEHLP_MODULE64_V3));
    if (this->pSGMI == NULL)
    {
      SetLastError(ERROR_DLL_INIT_FAILED);
      return FALSE;
    }
    // First try to use the larger ModuleInfo-Structure
    pModuleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64_V3);
    void* pData = malloc(
        4096); // reserve enough memory, so the bug in v6.3.5.1 does not lead to memory-overwrites...
    if (pData == NULL)
    {
      SetLastError(ERROR_NOT_ENOUGH_MEMORY);
      return FALSE;
    }
    memcpy(pData, pModuleInfo, sizeof(IMAGEHLP_MODULE64_V3));
    static bool s_useV3Version = true;
    if (s_useV3Version)
    {
      if (this->pSGMI(hProcess, baseAddr, (IMAGEHLP_MODULE64_V3*)pData) != FALSE)
      {
        // only copy as much memory as is reserved...
        memcpy(pModuleInfo, pData, sizeof(IMAGEHLP_MODULE64_V3));
        pModuleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64_V3);
        free(pData);
        return TRUE;
      }
      s_useV3Version = false; // to prevent unnecessary calls with the larger struct...
    }

    // could not retrieve the bigger structure, try with the smaller one (as defined in VC7.1)...
    pModuleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64_V2);
    memcpy(pData, pModuleInfo, sizeof(IMAGEHLP_MODULE64_V2));
    if (this->pSGMI(hProcess, baseAddr, (IMAGEHLP_MODULE64_V3*)pData) != FALSE)
    {
      // only copy as much memory as is reserved...
      memcpy(pModuleInfo, pData, sizeof(IMAGEHLP_MODULE64_V2));
      pModuleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64_V2);
      free(pData);
      return TRUE;
    }
    free(pData);
    SetLastError(ERROR_DLL_INIT_FAILED);
    return FALSE;
  }
};

// #############################################################

#if defined(_MSC_VER) && _MSC_VER >= 1400 && _MSC_VER < 1900
extern "C" void* __cdecl _getptd();
#endif
#if defined(_MSC_VER) && _MSC_VER >= 1900
extern "C" void** __cdecl __current_exception_context();
#endif

static PCONTEXT get_current_exception_context()
{
  PCONTEXT * pctx = NULL;
#if defined(_MSC_VER) && _MSC_VER >= 1400 && _MSC_VER < 1900  
  LPSTR ptd = (LPSTR)_getptd();
  if (ptd)
    pctx = (PCONTEXT *)(ptd + (sizeof(void*) == 4 ? 0x8C : 0xF8));
#endif
#if defined(_MSC_VER) && _MSC_VER >= 1900
  pctx = (PCONTEXT *)__current_exception_context();
#endif
  return pctx ? *pctx : NULL;
}

bool StackWalker::Init(ExceptType extype, int options, LPCSTR szSymPath, DWORD dwProcessId,
                       HANDLE hProcess, PEXCEPTION_POINTERS exp)
{
  PCONTEXT ctx = NULL;
  if (extype == AfterCatch)
    ctx = get_current_exception_context();
  if (extype == AfterExcept && exp)
    ctx = exp->ContextRecord;
  this->m_options = options;
  this->m_modulesLoaded = FALSE;
  this->m_szSymPath = NULL;
  this->m_MaxRecursionCount = 1000;
  this->m_sw = NULL;
  SetTargetProcess(dwProcessId, hProcess);
  SetSymPath(szSymPath);
  /* MSVC ignore std::nothrow specifier for `new` operator */
  LPVOID buf = malloc(sizeof(StackWalkerInternal));
  if (!buf)
    return false;
  memset(buf, 0, sizeof(StackWalkerInternal));
  this->m_sw = new(buf) StackWalkerInternal(this, this->m_hProcess, ctx);  // placement new
  return true;
}

StackWalker::StackWalker(DWORD dwProcessId, HANDLE hProcess)
{
  Init(NonExcept, OptionsAll, NULL, dwProcessId, hProcess);
}

StackWalker::StackWalker(int options, LPCSTR szSymPath, DWORD dwProcessId, HANDLE hProcess)
{
  Init(NonExcept, options, szSymPath, dwProcessId, hProcess);
}

StackWalker::StackWalker(ExceptType extype, int options, PEXCEPTION_POINTERS exp)
{
  Init(extype, options, NULL, GetCurrentProcessId(), GetCurrentProcess(), exp);
}

StackWalker::~StackWalker()
{
  SetSymPath(NULL);
  if (m_sw != NULL) {
    m_sw->~StackWalkerInternal();  // call the object's destructor
    free(m_sw);
  }
  m_sw = NULL;
}

bool StackWalker::SetSymPath(LPCSTR szSymPath)
{
  if (m_szSymPath)
    free(m_szSymPath);
  m_szSymPath = NULL;
  if (szSymPath == NULL)
    return true;
  m_szSymPath = _strdup(szSymPath);
  if (m_szSymPath)
    m_options |= SymBuildPath;
  return true;
}

bool StackWalker::SetTargetProcess(DWORD dwProcessId, HANDLE hProcess)
{
  m_dwProcessId = dwProcessId;
  m_hProcess = hProcess;
  if (m_sw)
    m_sw->m_hProcess = hProcess;
  return true;
}

PCONTEXT StackWalker::GetCurrentExceptionContext()
{
  return get_current_exception_context();
}

BOOL StackWalker::LoadModules()
{
  if (this->m_sw == NULL)
  {
    SetLastError(ERROR_DLL_INIT_FAILED);
    return FALSE;
  }
  if (m_modulesLoaded != FALSE)
    return TRUE;

  // Build the sym-path:
  char* szSymPath = NULL;
  if ((this->m_options & SymBuildPath) != 0)
  {
    const size_t nSymPathLen = 4096;
    szSymPath = (char*)malloc(nSymPathLen);
    if (szSymPath == NULL)
    {
      SetLastError(ERROR_NOT_ENOUGH_MEMORY);
      return FALSE;
    }
    szSymPath[0] = 0;
    // Now first add the (optional) provided sympath:
    if (this->m_szSymPath != NULL)
    {
      strcat_s(szSymPath, nSymPathLen, this->m_szSymPath);
      strcat_s(szSymPath, nSymPathLen, ";");
    }

    strcat_s(szSymPath, nSymPathLen, ".;");

    const size_t nTempLen = 1024;
    char         szTemp[nTempLen];
    // Now add the current directory:
    if (GetCurrentDirectoryA(nTempLen, szTemp) > 0)
    {
      szTemp[nTempLen - 1] = 0;
      strcat_s(szSymPath, nSymPathLen, szTemp);
      strcat_s(szSymPath, nSymPathLen, ";");
    }

    // Now add the path for the main-module:
    if (GetModuleFileNameA(NULL, szTemp, nTempLen) > 0)
    {
      szTemp[nTempLen - 1] = 0;
      for (char* p = (szTemp + strlen(szTemp) - 1); p >= szTemp; --p)
      {
        // locate the rightmost path separator
        if ((*p == '\\') || (*p == '/') || (*p == ':'))
        {
          *p = 0;
          break;
        }
      } // for (search for path separator...)
      if (strlen(szTemp) > 0)
      {
        strcat_s(szSymPath, nSymPathLen, szTemp);
        strcat_s(szSymPath, nSymPathLen, ";");
      }
    }
    if (GetEnvironmentVariableA("_NT_SYMBOL_PATH", szTemp, nTempLen) > 0)
    {
      szTemp[nTempLen - 1] = 0;
      strcat_s(szSymPath, nSymPathLen, szTemp);
      strcat_s(szSymPath, nSymPathLen, ";");
    }
    if (GetEnvironmentVariableA("_NT_ALTERNATE_SYMBOL_PATH", szTemp, nTempLen) > 0)
    {
      szTemp[nTempLen - 1] = 0;
      strcat_s(szSymPath, nSymPathLen, szTemp);
      strcat_s(szSymPath, nSymPathLen, ";");
    }
    if (GetEnvironmentVariableA("SYSTEMROOT", szTemp, nTempLen) > 0)
    {
      szTemp[nTempLen - 1] = 0;
      strcat_s(szSymPath, nSymPathLen, szTemp);
      strcat_s(szSymPath, nSymPathLen, ";");
      // also add the "system32"-directory:
      strcat_s(szTemp, nTempLen, "\\system32");
      strcat_s(szSymPath, nSymPathLen, szTemp);
      strcat_s(szSymPath, nSymPathLen, ";");
    }

    if ((this->m_options & SymUseSymSrv) != 0)
    {
      if (GetEnvironmentVariableA("SYSTEMDRIVE", szTemp, nTempLen) > 0)
      {
        szTemp[nTempLen - 1] = 0;
        strcat_s(szSymPath, nSymPathLen, "SRV*");
        strcat_s(szSymPath, nSymPathLen, szTemp);
        strcat_s(szSymPath, nSymPathLen, "\\websymbols");
        strcat_s(szSymPath, nSymPathLen, "*https://msdl.microsoft.com/download/symbols;");
      }
      else
        strcat_s(szSymPath, nSymPathLen,
                 "SRV*c:\\websymbols*https://msdl.microsoft.com/download/symbols;");
    }
  } // if SymBuildPath

  // First Init the whole stuff...
  BOOL bRet = this->m_sw->Init(szSymPath);
  if (szSymPath != NULL)
    free(szSymPath);
  szSymPath = NULL;
  if (bRet == FALSE)
  {
    this->OnDbgHelpErr("Error while initializing dbghelp.dll", 0, 0);
    SetLastError(ERROR_DLL_INIT_FAILED);
    return FALSE;
  }

  bRet = this->m_sw->LoadModules(this->m_hProcess, this->m_dwProcessId);
  if (bRet != FALSE)
    m_modulesLoaded = TRUE;
  return bRet;
}

// The following is used to pass the "userData"-Pointer to the user-provided readMemoryFunction
// This has to be done due to a problem with the "hProcess"-parameter in x64...
// Because this class is in no case multi-threading-enabled (because of the limitations
// of dbghelp.dll) it is "safe" to use a static-variable
static StackWalker::PReadProcessMemoryRoutine s_readMemoryFunction = NULL;
static LPVOID                                 s_readMemoryFunction_UserData = NULL;

BOOL StackWalker::ShowCallstack(HANDLE                    hThread,
                                const CONTEXT*            context,
                                PReadProcessMemoryRoutine readMemoryFunction,
                                LPVOID                    pUserData)
{
  CONTEXT                                   c;
  CallstackEntry                            csEntry;
  IMAGEHLP_SYMBOL64*                        pSym = NULL;
  StackWalkerInternal::IMAGEHLP_MODULE64_V3 Module;
  IMAGEHLP_LINE64                           Line;
  int                                       frameNum;
  bool                                      bLastEntryCalled = true;
  int                                       curRecursionCount = 0;

  if (m_modulesLoaded == FALSE)
    this->LoadModules(); // ignore the result...

  if (this->m_sw->m_hDbhHelp == NULL)
  {
    SetLastError(ERROR_DLL_INIT_FAILED);
    return FALSE;
  }

  s_readMemoryFunction = readMemoryFunction;
  s_readMemoryFunction_UserData = pUserData;

  if (context == NULL)
  {
    // If no context is provided, capture the context
    // See: https://stackwalker.codeplex.com/discussions/446958
#if _WIN32_WINNT <= 0x0501
    // If we need to support XP, we need to use the "old way", because "GetThreadId" is not available!
    if (hThread == GetCurrentThread())
#else
    if (GetThreadId(hThread) == GetCurrentThreadId())
#endif
    {
      if (m_sw->m_ctx.ContextFlags != 0)
        c = m_sw->m_ctx;   // context taken at Init
      else
        GET_CURRENT_CONTEXT_STACKWALKER_CODEPLEX(c, USED_CONTEXT_FLAGS);
    }
    else
    {
      SuspendThread(hThread);
      memset(&c, 0, sizeof(CONTEXT));
      c.ContextFlags = USED_CONTEXT_FLAGS;

      // TODO: Detect if you want to get a thread context of a different process, which is running a different processor architecture...
      // This does only work if we are x64 and the target process is x64 or x86;
      // It cannot work, if this process is x64 and the target process is x64... this is not supported...
      // See also: http://www.howzatt.demon.co.uk/articles/DebuggingInWin64.html
      if (GetThreadContext(hThread, &c) == FALSE)
      {
        ResumeThread(hThread);
        return FALSE;
      }
    }
  }
  else
    c = *context;

  // init STACKFRAME for first call
  STACKFRAME64 s; // in/out stackframe
  memset(&s, 0, sizeof(s));
  DWORD imageType;
#ifdef _M_IX86
  // normally, call ImageNtHeader() and use machine info from PE header
  imageType = IMAGE_FILE_MACHINE_I386;
  s.AddrPC.Offset = c.Eip;
  s.AddrPC.Mode = AddrModeFlat;
  s.AddrFrame.Offset = c.Ebp;
  s.AddrFrame.Mode = AddrModeFlat;
  s.AddrStack.Offset = c.Esp;
  s.AddrStack.Mode = AddrModeFlat;
#elif _M_X64
  imageType = IMAGE_FILE_MACHINE_AMD64;
  s.AddrPC.Offset = c.Rip;
  s.AddrPC.Mode = AddrModeFlat;
  s.AddrFrame.Offset = c.Rsp;
  s.AddrFrame.Mode = AddrModeFlat;
  s.AddrStack.Offset = c.Rsp;
  s.AddrStack.Mode = AddrModeFlat;
#elif _M_IA64
  imageType = IMAGE_FILE_MACHINE_IA64;
  s.AddrPC.Offset = c.StIIP;
  s.AddrPC.Mode = AddrModeFlat;
  s.AddrFrame.Offset = c.IntSp;
  s.AddrFrame.Mode = AddrModeFlat;
  s.AddrBStore.Offset = c.RsBSP;
  s.AddrBStore.Mode = AddrModeFlat;
  s.AddrStack.Offset = c.IntSp;
  s.AddrStack.Mode = AddrModeFlat;
#elif _M_ARM64
  imageType = IMAGE_FILE_MACHINE_ARM64;
  s.AddrPC.Offset = c.Pc;
  s.AddrPC.Mode = AddrModeFlat;
  s.AddrFrame.Offset = c.Fp;
  s.AddrFrame.Mode = AddrModeFlat;
  s.AddrStack.Offset = c.Sp;
  s.AddrStack.Mode = AddrModeFlat;
#else
#error "Platform not supported!"
#endif

  pSym = (IMAGEHLP_SYMBOL64*)malloc(sizeof(IMAGEHLP_SYMBOL64) + STACKWALK_MAX_NAMELEN);
  if (!pSym)
    goto cleanup; // not enough memory...
  memset(pSym, 0, sizeof(IMAGEHLP_SYMBOL64) + STACKWALK_MAX_NAMELEN);
  pSym->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
  pSym->MaxNameLength = STACKWALK_MAX_NAMELEN;

  memset(&Line, 0, sizeof(Line));
  Line.SizeOfStruct = sizeof(Line);

  memset(&Module, 0, sizeof(Module));
  Module.SizeOfStruct = sizeof(Module);

  for (frameNum = 0;; ++frameNum)
  {
    // get next stack frame (StackWalk64(), SymFunctionTableAccess64(), SymGetModuleBase64())
    // if this returns ERROR_INVALID_ADDRESS (487) or ERROR_NOACCESS (998), you can
    // assume that either you are done, or that the stack is so hosed that the next
    // deeper frame could not be found.
    // CONTEXT need not to be supplied if imageTyp is IMAGE_FILE_MACHINE_I386!
    if (!this->m_sw->pSW(imageType, this->m_hProcess, hThread, &s, &c, myReadProcMem,
                         this->m_sw->pSFTA, this->m_sw->pSGMB, NULL))
    {
      // INFO: "StackWalk64" does not set "GetLastError"...
      this->OnDbgHelpErr("StackWalk64", 0, s.AddrPC.Offset);
      break;
    }

    csEntry.offset = s.AddrPC.Offset;
    csEntry.name[0] = 0;
    csEntry.undName[0] = 0;
    csEntry.undFullName[0] = 0;
    csEntry.offsetFromSmybol = 0;
    csEntry.offsetFromLine = 0;
    csEntry.lineFileName[0] = 0;
    csEntry.lineNumber = 0;
    csEntry.loadedImageName[0] = 0;
    csEntry.moduleName[0] = 0;
    if (s.AddrPC.Offset == s.AddrReturn.Offset)
    {
      if ((this->m_MaxRecursionCount > 0) && (curRecursionCount > m_MaxRecursionCount))
      {
        this->OnDbgHelpErr("StackWalk64-Endless-Callstack!", 0, s.AddrPC.Offset);
        break;
      }
      curRecursionCount++;
    }
    else
      curRecursionCount = 0;
    if (s.AddrPC.Offset != 0)
    {
      // we seem to have a valid PC
      // show procedure info (SymGetSymFromAddr64())
      if (this->m_sw->pSGSFA(this->m_hProcess, s.AddrPC.Offset, &(csEntry.offsetFromSmybol),
                             pSym) != FALSE)
      {
        MyStrCpy(csEntry.name, STACKWALK_MAX_NAMELEN, pSym->Name);
        // UnDecorateSymbolName()
        this->m_sw->pUDSN(pSym->Name, csEntry.undName, STACKWALK_MAX_NAMELEN, UNDNAME_NAME_ONLY);   
        this->m_sw->pUDSN(pSym->Name, csEntry.undFullName, STACKWALK_MAX_NAMELEN, UNDNAME_COMPLETE);
      }
      else
      {
        this->OnDbgHelpErr("SymGetSymFromAddr64", GetLastError(), s.AddrPC.Offset);
      }

      // show line number info, NT5.0-method (SymGetLineFromAddr64())
      if (this->m_sw->pSGLFA != NULL)
      { // yes, we have SymGetLineFromAddr64()
        if (this->m_sw->pSGLFA(this->m_hProcess, s.AddrPC.Offset, &(csEntry.offsetFromLine),
                               &Line) != FALSE)
        {
          csEntry.lineNumber = Line.LineNumber;
          MyStrCpy(csEntry.lineFileName, STACKWALK_MAX_NAMELEN, Line.FileName);
        }
        else
        {
          this->OnDbgHelpErr("SymGetLineFromAddr64", GetLastError(), s.AddrPC.Offset);
        }
      } // yes, we have SymGetLineFromAddr64()

      // show module info (SymGetModuleInfo64())
      if (this->m_sw->GetModuleInfo(this->m_hProcess, s.AddrPC.Offset, &Module) != FALSE)
      { // got module info OK
        switch (Module.SymType)
        {
          case SymNone:
            csEntry.symTypeString = "-nosymbols-";
            break;
          case SymCoff:
            csEntry.symTypeString = "COFF";
            break;
          case SymCv:
            csEntry.symTypeString = "CV";
            break;
          case SymPdb:
            csEntry.symTypeString = "PDB";
            break;
          case SymExport:
            csEntry.symTypeString = "-exported-";
            break;
          case SymDeferred:
            csEntry.symTypeString = "-deferred-";
            break;
          case SymSym:
            csEntry.symTypeString = "SYM";
            break;
#if API_VERSION_NUMBER >= 9
          case SymDia:
            csEntry.symTypeString = "DIA";
            break;
#endif
          case 8: //SymVirtual:
            csEntry.symTypeString = "Virtual";
            break;
          default:
            //_snprintf( ty, sizeof(ty), "symtype=%ld", (long) Module.SymType );
            csEntry.symTypeString = NULL;
            break;
        }

        MyStrCpy(csEntry.moduleName, STACKWALK_MAX_NAMELEN, Module.ModuleName);
        csEntry.baseOfImage = Module.BaseOfImage;
        MyStrCpy(csEntry.loadedImageName, STACKWALK_MAX_NAMELEN, Module.LoadedImageName);
      } // got module info OK
      else
      {
        this->OnDbgHelpErr("SymGetModuleInfo64", GetLastError(), s.AddrPC.Offset);
      }
    } // we seem to have a valid PC

    CallstackEntryType et = nextEntry;
    if (frameNum == 0)
      et = firstEntry;
    bLastEntryCalled = false;
    this->OnCallstackEntry(et, csEntry);

    if (s.AddrReturn.Offset == 0)
    {
      bLastEntryCalled = true;
      this->OnCallstackEntry(lastEntry, csEntry);
      SetLastError(ERROR_SUCCESS);
      break;
    }
  } // for ( frameNum )

cleanup:
  if (pSym)
    free(pSym);

  if (bLastEntryCalled == false)
    this->OnCallstackEntry(lastEntry, csEntry);

  if (context == NULL)
    ResumeThread(hThread);

  return TRUE;
}

BOOL StackWalker::ShowObject(LPVOID pObject)
{
  // Load modules if not done yet
  if (m_modulesLoaded == FALSE)
    this->LoadModules(); // ignore the result...

  // Verify that the DebugHelp.dll was actually found
  if (this->m_sw->m_hDbhHelp == NULL)
  {
    SetLastError(ERROR_DLL_INIT_FAILED);
    return FALSE;
  }

  // SymGetSymFromAddr64() is required
  if (this->m_sw->pSGSFA == NULL)
    return FALSE;

  // Show object info (SymGetSymFromAddr64())
  DWORD64            dwAddress = DWORD64(pObject);
  DWORD64            dwDisplacement = 0;
  const SIZE_T       symSize = sizeof(IMAGEHLP_SYMBOL64) + STACKWALK_MAX_NAMELEN;
  IMAGEHLP_SYMBOL64* pSym = (IMAGEHLP_SYMBOL64*) malloc(symSize);
  if (!pSym)
    return FALSE;
  memset(pSym, 0, symSize);
  pSym->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
  pSym->MaxNameLength = STACKWALK_MAX_NAMELEN;
  if (this->m_sw->pSGSFA(this->m_hProcess, dwAddress, &dwDisplacement, pSym) == FALSE)
  {
    this->OnDbgHelpErr("SymGetSymFromAddr64", GetLastError(), dwAddress);
    return FALSE;
  }
  // Object name output
  this->OnOutput(pSym->Name);

  free(pSym);
  return TRUE;
};

BOOL __stdcall StackWalker::myReadProcMem(HANDLE  hProcess,
                                          DWORD64 qwBaseAddress,
                                          PVOID   lpBuffer,
                                          DWORD   nSize,
                                          LPDWORD lpNumberOfBytesRead)
{
  if (s_readMemoryFunction == NULL)
  {
    SIZE_T st;
    BOOL   bRet = ReadProcessMemory(hProcess, (LPVOID)qwBaseAddress, lpBuffer, nSize, &st);
    *lpNumberOfBytesRead = (DWORD)st;
    //printf("ReadMemory: hProcess: %p, baseAddr: %p, buffer: %p, size: %d, read: %d, result: %d\n", hProcess, (LPVOID) qwBaseAddress, lpBuffer, nSize, (DWORD) st, (DWORD) bRet);
    return bRet;
  }
  else
  {
    return s_readMemoryFunction(hProcess, qwBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead,
                                s_readMemoryFunction_UserData);
  }
}

void StackWalker::OnLoadModule(LPCSTR    img,
                               LPCSTR    mod,
                               DWORD64   baseAddr,
                               DWORD     size,
                               DWORD     result,
                               LPCSTR    symType,
                               LPCSTR    pdbName,
                               ULONGLONG fileVersion)
{
  CHAR   buffer[STACKWALK_MAX_NAMELEN];
  size_t maxLen = STACKWALK_MAX_NAMELEN;
#if _MSC_VER >= 1400
  maxLen = _TRUNCATE;
#endif
  if (fileVersion == 0)
    _snprintf_s(buffer, maxLen, "%s:%s (%p), size: %d (result: %d), SymType: '%s', PDB: '%s'\n",
                img, mod, (LPVOID)baseAddr, size, result, symType, pdbName);
  else
  {
    DWORD v4 = (DWORD)(fileVersion & 0xFFFF);
    DWORD v3 = (DWORD)((fileVersion >> 16) & 0xFFFF);
    DWORD v2 = (DWORD)((fileVersion >> 32) & 0xFFFF);
    DWORD v1 = (DWORD)((fileVersion >> 48) & 0xFFFF);
    _snprintf_s(
        buffer, maxLen,
        "%s:%s (%p), size: %d (result: %d), SymType: '%s', PDB: '%s', fileVersion: %d.%d.%d.%d\n",
        img, mod, (LPVOID)baseAddr, size, result, symType, pdbName, v1, v2, v3, v4);
  }
  buffer[STACKWALK_MAX_NAMELEN - 1] = 0; // be sure it is NULL terminated
  OnOutput(buffer);
}

void StackWalker::OnCallstackEntry(CallstackEntryType eType, CallstackEntry& entry)
{
  CHAR   buffer[STACKWALK_MAX_NAMELEN];
  size_t maxLen = STACKWALK_MAX_NAMELEN;
#if _MSC_VER >= 1400
  maxLen = _TRUNCATE;
#endif
  if ((eType != lastEntry) && (entry.offset != 0))
  {
    if (entry.name[0] == 0)
      MyStrCpy(entry.name, STACKWALK_MAX_NAMELEN, "(function-name not available)");
    if (entry.undName[0] != 0)
      MyStrCpy(entry.name, STACKWALK_MAX_NAMELEN, entry.undName);
    if (entry.undFullName[0] != 0)
      MyStrCpy(entry.name, STACKWALK_MAX_NAMELEN, entry.undFullName);
    if (entry.lineFileName[0] == 0)
    {
      MyStrCpy(entry.lineFileName, STACKWALK_MAX_NAMELEN, "(filename not available)");
      if (entry.moduleName[0] == 0)
        MyStrCpy(entry.moduleName, STACKWALK_MAX_NAMELEN, "(module-name not available)");
      _snprintf_s(buffer, maxLen, "%p (%s): %s: %s\n", (LPVOID)entry.offset, entry.moduleName,
                  entry.lineFileName, entry.name);
    }
    else
      _snprintf_s(buffer, maxLen, "%s (%d): %s\n", entry.lineFileName, entry.lineNumber,
                  entry.name);
    buffer[STACKWALK_MAX_NAMELEN - 1] = 0;
    OnOutput(buffer);
    printf("%s", buffer);
  }
}

void StackWalker::OnDbgHelpErr(LPCSTR szFuncName, DWORD gle, DWORD64 addr)
{
  CHAR   buffer[STACKWALK_MAX_NAMELEN];
  size_t maxLen = STACKWALK_MAX_NAMELEN;
#if _MSC_VER >= 1400
  maxLen = _TRUNCATE;
#endif
  _snprintf_s(buffer, maxLen, "ERROR: %s, GetLastError: %d (Address: %p)\n", szFuncName, gle,
              (LPVOID)addr);
  buffer[STACKWALK_MAX_NAMELEN - 1] = 0;
  OnOutput(buffer);
}

void StackWalker::OnSymInit(LPCSTR szSearchPath, DWORD symOptions, LPCSTR szUserName)
{
  CHAR   buffer[STACKWALK_MAX_NAMELEN];
  size_t maxLen = STACKWALK_MAX_NAMELEN;
#if _MSC_VER >= 1400
  maxLen = _TRUNCATE;
#endif
  _snprintf_s(buffer, maxLen, "SymInit: Symbol-SearchPath: '%s', symOptions: %d, UserName: '%s'\n",
              szSearchPath, symOptions, szUserName);
  buffer[STACKWALK_MAX_NAMELEN - 1] = 0;
  OnOutput(buffer);
  // Also display the OS-version
#if _MSC_VER <= 1200
  OSVERSIONINFOA ver;
  ZeroMemory(&ver, sizeof(OSVERSIONINFOA));
  ver.dwOSVersionInfoSize = sizeof(ver);
  if (GetVersionExA(&ver) != FALSE)
  {
    _snprintf_s(buffer, maxLen, "OS-Version: %d.%d.%d (%s)\n", ver.dwMajorVersion,
                ver.dwMinorVersion, ver.dwBuildNumber, ver.szCSDVersion);
    buffer[STACKWALK_MAX_NAMELEN - 1] = 0;
    OnOutput(buffer);
  }
#else
  OSVERSIONINFOEXA ver;
  ZeroMemory(&ver, sizeof(OSVERSIONINFOEXA));
  ver.dwOSVersionInfoSize = sizeof(ver);
#if _MSC_VER >= 1900
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
  if (GetVersionExA((OSVERSIONINFOA*)&ver) != FALSE)
  {
    _snprintf_s(buffer, maxLen, "OS-Version: %d.%d.%d (%s) 0x%x-0x%x\n", ver.dwMajorVersion,
                ver.dwMinorVersion, ver.dwBuildNumber, ver.szCSDVersion, ver.wSuiteMask,
                ver.wProductType);
    buffer[STACKWALK_MAX_NAMELEN - 1] = 0;
    OnOutput(buffer);
  }
#if _MSC_VER >= 1900
#pragma warning(pop)
#endif
#endif
}

void StackWalker::OnOutput(LPCSTR buffer)
{
  OutputDebugStringA(buffer);
}



void StackWalker::print_windows_version(std::ostream& st) {

    st << std::endl;
    st << "--------------------------Windows version-----------------------------" << std::endl;
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

    //TCHAR --> char* ��Ҫunicode�ַ������ɶ��ֽ��ַ���
    //strncat(c_kernel32_path, "\\kernel32.dll", MAX_PATH - ret);

    //����windows�⺯��
    lstrcat(kernel32_path, _T("\\kernel32.dll"));

    DWORD version_size = GetFileVersionInfoSize(kernel32_path, NULL);
    if (version_size == 0) {
        st << "Call to GetFileVersionInfoSize failed\n";
        return;
    }
    //��javaԭ����ȣ����������ڴ淽ʽ�������Դ��ɡ�����
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

void StackWalker::get_sys_info(std::ostream& st)
{
    st << std::endl;
    st << "--------------------------CPU Info-----------------------------\n";
    SYSTEM_INFO  sysInfo;    //�ýṹ������˵�ǰ���������Ϣ�����������ϵ�ṹ�����봦���������͡�ϵͳ�����봦������������ҳ��Ĵ�С�Լ�������Ϣ��
    GetSystemInfo(&sysInfo);
    if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        st << "System Architecture: X64(AMD or Intel)" << std::endl;
    }
    else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM) {
        st << "System Architecture: ARM" << std::endl;
    }
    else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) {
        st << "System Architecture: Intel Itanium-based " << std::endl;
    }
    else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
        st << "System Architecture: X86\n" << std::endl;
    }
    else {
        st << "System Architecture: Unknown architecture.\n" << std::endl;
    }

    st << "CPU level :  " << sysInfo.wProcessorLevel << std::endl;
    st << "CPU revision :  " << std::hex << sysInfo.wProcessorRevision << std::dec << std::endl;
    st << "type of processor :  ";
    switch (sysInfo.dwProcessorType)
    {
    case 386:
        st << "intel 386\n";
        break;
    case 486:
        st << "intel 486\n";
        break;
    case 586:
        st << "intel Pentium\n";
        break;
    case 2200:
        st << "intel IA64\n";
        break;
    case 8664:
        st << "AMD X8664\n";
        break;
    default:
        st << "Unknown processor\n";
        break;
    }
    st << "page size :  " << sysInfo.dwPageSize << std::endl;
    st << "number of logical processors in the current group : " << sysInfo.dwNumberOfProcessors << std::endl;
    st << "the lowest memory address accessible to applications and DLLs :  " << sysInfo.lpMinimumApplicationAddress << std::endl;
    st << "the highest memory accessible to applications and DLLs :  " << sysInfo.lpMaximumApplicationAddress << std::endl;
    st << "The granularity for the starting address :  " << sysInfo.dwAllocationGranularity << std::endl;
}

void StackWalker::print_environment_variables(std::ostream& st) {
    st << std::endl;
    
    st << "--------------------------Environment Variables-----------------------------" << std::endl;
    // List of environment variables that should be reported in error log file.
    const char* env_list[] = {
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
    if (env_list) {
        st << "Environment Variables:" << std::endl;

        for (int i = 0; env_list[i] != NULL; i++) {
            //char* envvar = ::getenv(env_list[i]);
            //��getenv�滻��_dupenv_s����
            char* envvar = nullptr;
            size_t sz = 0;
            if (_dupenv_s(&envvar, &sz, env_list[i]) == 0 && envvar != NULL) {
                st << env_list[i] << "=" << envvar;
                // Use separate cr() printing to avoid unnecessary buffer operations that might cause truncation.
                st << std::endl;
            }
        }
    }
}

int StackWalker::get_loaded_modules_info(LoadedModulesCallbackFunc callback, void* param)
{
    HANDLE hProcess;

#define MAX_NUM_MODULES 128
    HMODULE modules[MAX_NUM_MODULES];
    static char filename[MAX_PATH];
    int result = 0;
    int pid = _getpid();   //�޸� ----�õ���ǰ����ID
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

        if (!GetModuleFileNameExA(hProcess, modules[i], filename, sizeof(filename)))
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
            (address)((uint64_t)modinfo.lpBaseOfDll + (uint64_t)modinfo.SizeOfImage), param);
        if (result)
            break;
    }

    CloseHandle(hProcess);
    return result;
}

int StackWalker::print_module(const char* fname, address base_address, address top_address, void* param) {
//#define PTR_FORMAT "0x%08" PRIxPTR
    if (!param)       return -1;
    std::ostream* st = (std::ostream*)param;

    //std::cout << fmt::format("{:#08x} - {:#08x} \t{:s}", base_address, top_address, fname) << "\t";
    
    (*st) << "0x" << std::hex << std::setw(8) << std::setfill('0') << (intptr_t)base_address << " - "  //setwֻ��Чһ��  
        << "0x" << std::setw(8) << (intptr_t)top_address << "  \t" << fname << std::hex << std::endl;
    
    /*
    ʹ��cout�Ƚϸ��ӣ���ȷ���Ƿ�������Ӱ�죬����ʹ��snprintf���ຯ�����Ȱ���Щ�������������Ȼ����������ļ�  �����ƺ�Ҳ�鷳��������
    char buf[1024];
    snprintf(buf, sizeof(buf), "0x%08llx", base_address);
    std::cout << buf << std::endl;
    */

    //printf(PTR_FORMAT " - " PTR_FORMAT " \t%s\n", base_address, top_address, fname);
    return 0;
  };

void StackWalker::print_dll_info(std::ostream* st)
{
    (*st) << std::endl;
    (*st) << "--------------------------Dynamic libraries-----------------------------" << std::endl;
    get_loaded_modules_info(StackWalker::print_module, (void*)st);
}

u_char* StackWalker::current_stack_base() {
    MEMORY_BASIC_INFORMATION minfo;
    address stack_bottom;
    size_t stack_size;

    VirtualQuery(&minfo, &minfo, sizeof(minfo));
    stack_bottom = (address)minfo.AllocationBase;
    stack_size = minfo.RegionSize;

    // Add up the sizes of all the regions with the same
    // AllocationBase.
    while (1){
        VirtualQuery(stack_bottom + stack_size, &minfo, sizeof(minfo));
        if (stack_bottom == (address)minfo.AllocationBase){
            stack_size += minfo.RegionSize;
        }
        else{
            break;
        }
    }
    return stack_bottom + stack_size;
}

//���ص�ǰջ�Ĵ�С
size_t StackWalker::current_stack_size(){
    size_t sz;
    MEMORY_BASIC_INFORMATION minfo;
    VirtualQuery(&minfo, &minfo, sizeof(minfo));
    sz = (size_t)current_stack_base() - (size_t)minfo.AllocationBase;
    return sz;
}

//��ӡ��ջ�߽�
void StackWalker::print_stack_bound(std::ostream& st) {
    st << std::endl;
    st << "stack:   ";
    address stack_top = current_stack_base();
    size_t stack_size = current_stack_size();
    address stack_bottom = stack_top - stack_size;

    st << "0x"<<std::hex << std::setw(8) << (intptr_t)stack_bottom << " - 0x"  //setwֻ��Чһ��
        << std::setw(8) << (intptr_t)stack_top << std::dec;

    //printf("[" PTR_FORMAT "," PTR_FORMAT "]", (intptr_t)(stack_bottom), (intptr_t)(stack_top));
    st << std::endl;
}

int StackWalker::_locate_module_by_addr(const char* mod_fname, address base_addr,
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

bool StackWalker::dll_address_to_library_name(address addr, char* buf,
    int buflen, int* offset)
{
    // NOTE: the reason we don't use SymGetModuleInfo() is it doesn't always
    //       return the full path to the DLL file, sometimes it returns path
    //       to the corresponding PDB file (debug info); sometimes it only
    //       returns partial path, which makes life painful.

    struct _modinfo mi;
    mi.addr = addr;
    mi.full_path = buf;
    mi.buflen = buflen;
    if (get_loaded_modules_info(StackWalker::_locate_module_by_addr, (void*)&mi))
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

bool StackWalker::dll_address_to_function_name(address addr, char* buf,
    int buflen, int* offset, bool demangle)
{

    if (decode(addr, buf, buflen, offset, demangle))  //decode
    {
        return true;
    }
    if (offset != NULL)
        *offset = -1;
    buf[0] = '\0';
    return false;
}

bool StackWalker::decode(const void* addr, char* buf, int buflen, int* offset, bool do_demangle) {   
    buf[0] = '\0';
    *offset = -1;

    if (addr == NULL) {
        return false;
    }

    // Try decoding the symbol once. If we fail, attempt to rebuild the
    // symbol search path - maybe the pc points to a dll whose pdb file is
    // outside our search path. Then do attempt the decode again.
    bool success = decode_locked(addr, buf, buflen, offset, do_demangle);

    return success;

}

bool StackWalker::decode_locked(const void* addr, char* buf, int buflen, int* offset, bool do_demangle) {

    DWORD64 displacement;
    PIMAGEHLP_SYMBOL64 pSymbol = NULL;
    bool success = false;

    pSymbol = (IMAGEHLP_SYMBOL64*)malloc(sizeof(IMAGEHLP_SYMBOL64) + STACKWALK_MAX_NAMELEN);
    if (!pSymbol) {
        RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, 0);
        //printf("not enough memory....");
        return false;
    }
    ::memset(pSymbol, 0, sizeof(IMAGEHLP_SYMBOL64) + STACKWALK_MAX_NAMELEN);
    pSymbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
    pSymbol->MaxNameLength = STACKWALK_MAX_NAMELEN;

    // It is unclear how SymGetSymFromAddr64 handles truncation. Experiments
    // show it will return TRUE but not zero terminate (which is a really bad
    // combination). Lets be super careful.
    ::memset(pSymbol->Name, 0, pSymbol->MaxNameLength); // To catch truncation.

    if (success = this->m_sw->pSGSFA(::GetCurrentProcess(), (DWORD64)addr, &displacement, pSymbol)) {
        //success = true;
        if (pSymbol->Name[pSymbol->MaxNameLength - 1] != '\0') {
            // Symbol was truncated. Do not attempt to demangle. Instead, zero terminate the
            // truncated string. We still return success - the truncated string may still
            // be usable for the caller.
            pSymbol->Name[pSymbol->MaxNameLength - 1] = '\0';
            do_demangle = false;
        }

        // Attempt to demangle. 
        if (do_demangle && this->m_sw->pUDSN(pSymbol->Name, buf, buflen, UNDNAME_COMPLETE)) {
            // ok.
        }
        else {
            strncpy_s(buf, buflen - 1, pSymbol->Name, buflen - 1);
        }
        buf[buflen - 1] = '\0';

        *offset = (int)displacement;
    }

#if 0
    if (success == false) {
        DWORD error_code = GetLastError();
        std::cout << "symGetSymFromAddr64 returned error,error code: " << error_code << std::endl;
    }
#endif

    //DEBUG_ONLY(g_buffers.decode_buffer.check();)

    return success;
}

void  StackWalker::print_C_frame(std::ostream& st, char* buf, int buflen, address pc) {
    // C/C++ frame
    //bool in_vm = address_is_in_vm(pc);  //check if addr is inside jvm.dll  
    //st<<in_vm ? "V" : "C";
    //Windows���ƺ����ü�� ����
    //st << "C ";

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
        st << "  [" << p1 << "+0x" << std::hex << offset
            << "]" << std::dec;

        if(console_count) printf("  [%s+0x%x]", p1, offset);
    }
    else {
        st << std::hex << std::setw(8) << (intptr_t)(pc)   //setwֻ��Чһ��
            <<std::dec;

        if (console_count) printf("  0x%08llx", (intptr_t)(pc));
        
    }

    found = dll_address_to_function_name(pc, buf, buflen, &offset,/*default true*/true);
    if (found) {
        st << "  " << buf << "+0x" << std::hex << offset
            << std::dec;
        if (console_count) printf("  %s+0x%x", buf, offset);
    }
}

bool StackWalker::get_source_info(const void* addr, char* buf, size_t buflen,
    int* line_no)
{
    buf[0] = '\0';
    *line_no = -1;

    if (addr == NULL) {
        return false;
    }

    IMAGEHLP_LINE64 lineinfo;
    memset(&lineinfo, 0, sizeof(lineinfo));
    lineinfo.SizeOfStruct = sizeof(lineinfo);
    DWORD displacement;
    if (this->m_sw->pSGLFA(::GetCurrentProcess(), (DWORD64)addr,
        &displacement, &lineinfo)) {
        if (buf != NULL && buflen > 0 && lineinfo.FileName != NULL) {
            // We only return the file name, not the whole path.
            char* p = lineinfo.FileName;
            char* q = strrchr(lineinfo.FileName, '\\');
            if (q) {
                p = q + 1;
            }
            strncpy_s(buf, buflen - 1, p, buflen - 1);
            buf[buflen - 1] = '\0';
        }
        if (line_no != 0) {
            *line_no = lineinfo.LineNumber;
        }
        return true;
    }
    return false;
}


bool StackWalker::platform_print_native_stack(std::ostream& st, const void* context, char* buf, int buf_size) {

    CONTEXT ctx;
    if (context != NULL) {
        memcpy(&ctx, context, sizeof(ctx));
    }
    else {
        memset(&ctx, 0, sizeof(CONTEXT));
        ctx.ContextFlags = USED_CONTEXT_FLAGS;
        RtlCaptureContext(&ctx);
    }

    st << "--------------------------Native Stack-----------------------------" << std::endl;
    std::cout << "--------------------------Native Stack-----------------------------" << std::endl;
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

    intptr_t StackPrintLimit = 128;  //�ֶ�����

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
                if (get_source_info(pc, buf, sizeof(buf), &line_no)) {
                    //st->print("  (%s:%d)", buf, line_no);
                    st << "  (" << buf << ":" << line_no << ")";
                    if(console_count) std::cout << "  (" << buf << ":" << line_no << ")";
                }
                if (console_count) {
                    std::cout << std::endl;
                    console_count--;
                }
                st << std::endl;
            }
            lastpc = pc;
        }
#if 0
        StackWalkerInternal::IMAGEHLP_MODULE64_V3 Module;
        LPCSTR symTypeString;
        memset(&Module, 0, sizeof(Module));
        Module.SizeOfStruct = sizeof(Module);
        if (this->m_sw->GetModuleInfo(GetCurrentProcess(), stk.AddrPC.Offset, &Module) != FALSE) { // got module info OK
            switch (Module.SymType) {
            case SymNone:
                symTypeString = "-nosymbols-";
                break;
            case SymCoff:
                symTypeString = "COFF";
                break;
            case SymCv:
                symTypeString = "CV";
                break;
            case SymPdb:
                symTypeString = "PDB";
                break;
            case SymExport:
                symTypeString = "-exported-";
                break;
            case SymDeferred:
                symTypeString = "-deferred-";
                break;
            case SymSym:
                symTypeString = "SYM";
                break;
#if API_VERSION_NUMBER >= 9
            case SymDia:
                symTypeString = "DIA";
                break;
#endif
            case 8: // SymVirtual:
                symTypeString = "Virtual";
                break;
            default:
                //_snprintf( ty, sizeof(ty), "symtype=%ld", (long) Module.SymType );
                symTypeString = nullptr;
                break;
            }
            st << "************" << "SymType:" << symTypeString << "\tModuleName:" << Module.ModuleName << "*************" << std::endl;
        }
#endif

#if 0

    //PVOID p = this->m_sw->pSFTA(GetCurrentProcess(), stk.AddrPC.Offset);
    //if (!p) {
    //    // StackWalk64() can't handle this PC. Calling StackWalk64 again may cause crash.
    //    break;
    //}
#endif // 0

        BOOL result = this->m_sw->pSW(
            IMAGE_FILE_MACHINE_AMD64,  // __in      DWORD MachineType,
            GetCurrentProcess(),       // __in      HANDLE hProcess,
            GetCurrentThread(),        // __in      HANDLE hThread,
            &stk,                      // __inout   LP STACKFRAME64 StackFrame,
            &ctx,                      // __inout   PVOID ContextRecord,
            NULL,                                // ReadMemoryRoutine
            this->m_sw->pSFTA,      // FunctionTableAccessRoutine,
            this->m_sw->pSGMB,            // GetModuleBaseRoutine
            NULL                               // TranslateAddressRoutine
        );                     

        if (!result) {
            break;
        }
    }
    if (count > StackPrintLimit) {
        st << "...<more frames>..." << std::endl;
    }
    st << std::endl;

    return true;
}

void StackWalker::show_callstack(std::ostream& os, const void* context) {

    if (m_modulesLoaded == FALSE)
        this->LoadModules(); // ignore the result...

    if (this->m_sw->m_hDbhHelp == NULL)
    {
        SetLastError(ERROR_DLL_INIT_FAILED);
        return;
    }
    print_windows_version(os);
    get_sys_info(os);
    print_environment_variables(os);
    print_dll_info(&os);
    print_stack_bound(os);

    static char buf[2000];
    platform_print_native_stack(os, context, buf, sizeof(buf));



}


/// Scan the loaded modules.
////
//// For each loaded module, add the directory it is located in to the pdb search
//// path, but avoid duplicates. Prior search path content is preserved.
////
//// If p_search_path_was_updated is not NULL, points to a bool which, upon
//// successful return from the function, contains true if the search path
//// was updated, false if no update was needed because no new DLLs were
//// loaded or unloaded.
////
//// Returns true for success, false for error.
//static bool recalc_search_path_locked(bool* p_search_path_was_updated) {
//
//    if (p_search_path_was_updated) {
//        *p_search_path_was_updated = false;
//    }
//
//    HANDLE hProcess = ::GetCurrentProcess();
//
//    BOOL success = false;
//
//    // 1) Retrieve current set search path.
//    //    (PDB search path is a global setting and someone might have modified
//    //     it, so take care not to remove directories, just to add our own).
//    TCHAR* t_buffer = nullptr;
//    Char2TCHAR(g_buffers.search_path.ptr(), t_buffer);    //symGetSearchPath�ڶ�������Ϊ�������������޸ġ�������
//
//    if (!WindowsDbgHelp::symGetSearchPath(hProcess, t_buffer,
//        (int)g_buffers.search_path.capacity())) {
//        return false;
//    }
//    TCHAR2Char(t_buffer, g_buffers.search_path.ptr());   //���޸ġ�������
//    //DEBUG_ONLY(g_buffers.search_path.check();)
//
//    // 2) Retrieve list of modules handles of all currently loaded modules.
//    DWORD bytes_needed = 0;
//    const DWORD buffer_capacity_bytes = (DWORD)g_buffers.loaded_modules.capacity() * sizeof(HMODULE);
//    success = ::EnumProcessModules(hProcess, g_buffers.loaded_modules.ptr(),
//        buffer_capacity_bytes, &bytes_needed);
//    //DEBUG_ONLY(g_buffers.loaded_modules.check();)
//
//        // Note: EnumProcessModules is sloppily defined in terms of whether a
//        // too-small output buffer counts as error. Will it truncate but still
//        // return TRUE? Nobody knows and the manpage is not telling. So we count
//        // truncation it as error, disregarding the return value.
//    if (!success || bytes_needed > buffer_capacity_bytes) {
//        return false;
//    }
//    else {
//        const int num_modules = bytes_needed / sizeof(HMODULE);
//        g_buffers.loaded_modules.set_num(num_modules);
//    }
//
//    // Compare the list of module handles with the last list. If the lists are
//    // identical, no additional dlls were loaded and we can stop.
//    if (g_buffers.loaded_modules.equals(g_buffers.last_loaded_modules)) {
//        return true;
//    }
//    else {
//        // Remember the new set of module handles and continue.
//        g_buffers.last_loaded_modules.copy_content_from(g_buffers.loaded_modules);
//    }
//
//    // 3) For each loaded module: retrieve directory from which it was loaded.
//    //    Add directory to search path (but avoid duplicates).
//
//    bool did_modify_searchpath = false;
//
//    for (int i = 0; i < (int)g_buffers.loaded_modules.num(); i++) {
//
//        const HMODULE hMod = g_buffers.loaded_modules.ptr()[i];
//        char* const filebuffer = g_buffers.dir_name.ptr();
//        const int file_buffer_capacity = g_buffers.dir_name.capacity();
//
//        const int len_returned = (int)::GetModuleFileNameA(hMod, filebuffer, (DWORD)file_buffer_capacity);
//
//        //DEBUG_ONLY(g_buffers.dir_name.check();)
//        if (len_returned == 0) {
//            // This may happen when a module gets unloaded after our call to EnumProcessModules.
//            // It should be rare but may sporadically happen. Just ignore and continue with the
//            // next module.
//            continue;
//        }
//        else if (len_returned == file_buffer_capacity) {
//            // Truncation. Just skip this module and continue with the next module.
//            continue;
//        }
//
//        // Cut file name part off.
//        char* last_slash = ::strrchr(filebuffer, '\\');
//        if (last_slash == NULL) {
//            last_slash = ::strrchr(filebuffer, '/');
//        }
//        if (last_slash) {
//            *last_slash = '\0';
//        }
//
//        // If this is already part of the search path, ignore it, otherwise
//        // append to search path.
//        if (!g_buffers.search_path.contains_directory(filebuffer)) {
//            if (!g_buffers.search_path.append_directory(filebuffer)) {
//                return false; // oom
//            }
//            //DEBUG_ONLY(g_buffers.search_path.check();)
//            did_modify_searchpath = true;
//        }
//
//    } // for each loaded module.
//
//    // If we did not modify the search path, nothing further needs to be done.
//    if (!did_modify_searchpath) {
//        return true;
//    }
//
//    // Set the search path to its new value.
//
//
//    Char2TCHAR(g_buffers.search_path.ptr(), t_buffer);  //  symSetSearchPath�ڶ�������Ϊ�������
//    if (!WindowsDbgHelp::symSetSearchPath(hProcess, t_buffer)) {
//        return false;
//    }
//
//    if (p_search_path_was_updated) {
//        *p_search_path_was_updated = true;
//    }
//
//    return true;
//
//}