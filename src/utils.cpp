#include "utils.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <wchar.h>

#pragma comment(lib,"ntdll.lib")

#ifndef UNICODE
#define UNICODE
#endif

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

HANDLE _out = nullptr, _old_out = nullptr;
HANDLE _err = nullptr, _old_err = nullptr;
HANDLE _in = nullptr, _old_in = nullptr;

static int num = 0;

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );

typedef NTSTATUS(NTAPI* _NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG                   NextEntryOffset;
    ULONG                   NumberOfThreads;
    LARGE_INTEGER           Reserved[3];
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           KernelTime;
    UNICODE_STRING          ImageName;
    ULONG                   BasePriority;
    HANDLE                  ProcessId;
    HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

static PVOID GetLibraryProcAddress(LPCSTR LibraryName, LPCSTR ProcName)
{
    auto hModule = GetModuleHandleA(LibraryName);
    if (hModule == NULL)
        return nullptr;
    return GetProcAddress(hModule, ProcName);
}

// got this somewhere. can't remember where
uintptr_t Scan(uintptr_t address, const char* signature)
{
    static auto patternToByte = [](const char* pattern)
    {
        auto       bytes = std::vector<int>{};
        const auto start = const_cast<char*>(pattern);
        const auto end = const_cast<char*>(pattern) + strlen(pattern);

        for (auto current = start; current < end; ++current)
        {
            if (*current == '?')
            {
                ++current;
                if (*current == '?')
                    ++current;
                bytes.push_back(-1);
            }
            else
            {
                bytes.push_back(strtoul(current, &current, 16));
            }
        }
        return bytes;
    };

    const auto dosHeader = (PIMAGE_DOS_HEADER)address;
    const auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)address + dosHeader->e_lfanew);

    const auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    auto       patternBytes = patternToByte(signature);
    const auto scanBytes = reinterpret_cast<std::uint8_t*>(address);

    const auto s = patternBytes.size();
    const auto d = patternBytes.data();

    for (auto i = 0ul; i < sizeOfImage - s; ++i)
    {
        bool found = true;
        for (auto j = 0ul; j < s; ++j)
        {
            if (scanBytes[i + j] != d[j] && d[j] != -1)
            {
                found = false;
                break;
            }
        }
        if (found)
        {
            return reinterpret_cast<uintptr_t>(&scanBytes[i]);
        }
    }
    return NULL;
}

namespace Utils
{
    void AttachConsole()
    {
        _old_out = GetStdHandle(STD_OUTPUT_HANDLE);
        _old_err = GetStdHandle(STD_ERROR_HANDLE);
        _old_in = GetStdHandle(STD_INPUT_HANDLE);

        ::AllocConsole() && ::AttachConsole(GetCurrentProcessId());

        _out = GetStdHandle(STD_OUTPUT_HANDLE);
        _err = GetStdHandle(STD_ERROR_HANDLE);
        _in = GetStdHandle(STD_INPUT_HANDLE);

        SetConsoleMode(_out,
            ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);

        SetConsoleMode(_in,
            ENABLE_INSERT_MODE | ENABLE_EXTENDED_FLAGS |
            ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE);
    }
    void DetachConsole()
    {
        if (_out && _err && _in) {
            FreeConsole();

            if (_old_out)
                SetStdHandle(STD_OUTPUT_HANDLE, _old_out);

            if (_old_err)
                SetStdHandle(STD_ERROR_HANDLE, _old_err);

            if (_old_in)
                SetStdHandle(STD_INPUT_HANDLE, _old_in);
        }
    }
    bool ConsolePrint(const char* fmt, ...)
    {
        if (!_out)
            return false;

        char buf[1024];
        va_list va;

        va_start(va, fmt);
        _vsnprintf_s(buf, 1024, fmt, va);
        va_end(va);

        return !!WriteConsoleA(_out, buf, static_cast<DWORD>(strlen(buf)), nullptr, nullptr);
    }
    void ClearConsole()
    {
        DWORD n;                         /* Number of characters written */
        DWORD size;                      /* number of visible characters */
        COORD coord = { 0 };               /* Top left screen position */
        CONSOLE_SCREEN_BUFFER_INFO csbi;

        /* Get a handle to the console */
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);

        GetConsoleScreenBufferInfo(h, &csbi);

        /* Find the number of characters to overwrite */
        size = csbi.dwSize.X * csbi.dwSize.Y;

        /* Overwrite the screen buffer with whitespace */
        FillConsoleOutputCharacter(h, TEXT(' '), size, coord, &n);
        GetConsoleScreenBufferInfo(h, &csbi);
        FillConsoleOutputAttribute(h, csbi.wAttributes, size, coord, &n);

        /* Reset the cursor to the top left position */
        SetConsoleCursorPosition(h, coord);
    }
    char ConsoleReadKey()
    {
        if (!_in)
            return false;

        auto key = char{ 0 };
        auto keysread = DWORD{ 0 };

        ReadConsoleA(_in, &key, 1, &keysread, nullptr);
        return key;
    }

    uintptr_t PatternScan(uintptr_t module, const char* pattern)
    {
        auto offset = Scan(module, pattern);
        offset -= module;

        return module + offset;
    }
    std::string GetLastErrorAsString()
    {
        DWORD code = GetLastError();
        LPSTR buf = nullptr;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buf, 0, NULL);
        std::string ret = buf;
        LocalFree(buf);
        return ret;
    }
    // https://github.com/Akebi-Group/Akebi-GC/blob/master/cheat-library/src/user/cheat/native.cpp
    bool CloseDriverHandleName(const wchar_t* name)
    {
        _NtQuerySystemInformation NtQuerySystemInformation =
            (_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
        _NtDuplicateObject NtDuplicateObject =
            (_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
        _NtQueryObject NtQueryObject =
            (_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");
        NTSTATUS status;

        ULONG handleInfoSize = 0x10000;
        PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

        ULONG pid = 0;
        HANDLE processHandle = GetCurrentProcess();
        ULONG i;

        /* NtQuerySystemInformation won't give us the correct buffer size,
           so we guess by doubling the buffer size. */
        while ((status = NtQuerySystemInformation(
            SystemHandleInformation,
            handleInfo,
            handleInfoSize,
            NULL
        )) == STATUS_INFO_LENGTH_MISMATCH)
            handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

        /* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */
        if (!NT_SUCCESS(status))
        {
            ConsolePrint("NtQuerySystemInformation failed!\n");
            return false;
        }

        bool closed = false;
        for (i = 0; i < handleInfo->HandleCount; i++)
        {
            if (closed)
                break;

            SYSTEM_HANDLE handle = handleInfo->Handles[i];
            HANDLE dupHandle = NULL;
            POBJECT_TYPE_INFORMATION objectTypeInfo;
            PVOID objectNameInfo;
            UNICODE_STRING objectName;
            ULONG returnLength;

            /* Duplicate the handle so we can query it. */
            if (!NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0)))
                continue;

            /* Query the object type. */
            objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
            if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL)))
            {
                CloseHandle(dupHandle);
                continue;
            }

            /* Query the object name (unless it has an access of
               0x0012019f, on which NtQueryObject could hang. */
            if (handle.GrantedAccess == 0x0012019f)
            {
                free(objectTypeInfo);
                CloseHandle(dupHandle);
                continue;
            }

            objectNameInfo = malloc(0x1000);
            if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength)))
            {
                /* Reallocate the buffer and try again. */
                objectNameInfo = realloc(objectNameInfo, returnLength);
                if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL)))
                {
                    free(objectTypeInfo);
                    free(objectNameInfo);
                    CloseHandle(dupHandle);
                    continue;
                }
            }

            /* Cast our buffer into an UNICODE_STRING. */
            objectName = *(PUNICODE_STRING)objectNameInfo;

            /* Print the information! */
            if (objectName.Length && lstrcmpiW(objectName.Buffer, name) == 0)
            {
                CloseHandle((HANDLE)handle.Handle);
                closed = true;
            }

            free(objectTypeInfo);
            free(objectNameInfo);
            CloseHandle(dupHandle);

        }

        free(handleInfo);
        CloseHandle(processHandle);
        return closed;
    }
}

namespace Resolve
{
    uintptr_t RelativeJMP(uintptr_t address)
    {
        BYTE* code = (BYTE*)address;
        if (code[0] != 0xE9 || code[0] != 0xE8)
            return address;

        return address + *(int32_t*)&code[1] + 5;
    }
    uintptr_t RelativeMOV32(uintptr_t address)
    {
        BYTE* code = (BYTE*)address;
        if (code[0] != 0x8b && (code[1] != 0x05 || code[1] != 0x0D || code[1] != 0x15 || code[1] != 0x1D))
            return address;

        return address + *(int32_t*)&code[2] + 6;
    }
    uintptr_t RelativeMOV(uintptr_t address)
    {
        BYTE* code = (BYTE*)address;
        if (code[0] != 0x48 && (code[2] != 0x05 || code[2] != 0x0D || code[2] != 0x15 || code[2] != 0x1D))
            return address;

        return address + *(int32_t*)&code[3] + 7;
    }
    uintptr_t RelativeXMM128(uintptr_t address)
    {
        //xmm0-7 registers
        BYTE* code = (BYTE*)address;
        if (code[1] != 0x0F && (code[2] != 0x10 || code[2] != 0x11))
            return address;

        return address + *(int32_t*)&code[4] + 8;
    }

    uintptr_t JMP(uintptr_t module, uintptr_t address)
    {
        uintptr_t m_address = Resolve::RelativeJMP(address);
        m_address -= module;

        return m_address + module;
    }
    uintptr_t MOV32(uintptr_t module, uintptr_t address)
    {
        uintptr_t m_address = Resolve::RelativeMOV32(address);
        m_address -= module;

        return m_address + module;
    }
    uintptr_t MOV(uintptr_t module, uintptr_t address)
    {
        uintptr_t m_address = Resolve::RelativeMOV(address);
        m_address -= module;

        return m_address + module;
    }
    uintptr_t XMM128(uintptr_t module, uintptr_t address)
    {
        uintptr_t m_address = Resolve::RelativeXMM128(address);
        m_address -= module;

        return m_address + module;
    }
}