
#include "BeaconApi.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

COFFAPIFUNC BeaconApi[] = {

        { .NameHash = COFFAPI_BEACONDATAPARSER,             .Pointer = BeaconDataParse              },
        { .NameHash = COFFAPI_BEACONDATAINT,                .Pointer = BeaconDataInt                },
        { .NameHash = COFFAPI_BEACONDATASHORT,              .Pointer = BeaconDataShort              },
        { .NameHash = COFFAPI_BEACONDATALENGTH,             .Pointer = BeaconDataLength             },
        { .NameHash = COFFAPI_BEACONDATAEXTRACT,            .Pointer = BeaconDataExtract            },
        { .NameHash = COFFAPI_BEACONFORMATALLOC,            .Pointer = BeaconFormatAlloc            },
        { .NameHash = COFFAPI_BEACONFORMATRESET,            .Pointer = BeaconFormatReset            },
        { .NameHash = COFFAPI_BEACONFORMATFREE,             .Pointer = BeaconFormatFree             },
        { .NameHash = COFFAPI_BEACONFORMATAPPEND,           .Pointer = BeaconFormatAppend           },
        { .NameHash = COFFAPI_BEACONFORMATPRINTF,           .Pointer = BeaconFormatPrintf           },
        { .NameHash = COFFAPI_BEACONFORMATTOSTRING,         .Pointer = BeaconFormatToString         },
        { .NameHash = COFFAPI_BEACONFORMATINT,              .Pointer = BeaconFormatInt              },
        { .NameHash = COFFAPI_BEACONPRINTF,                 .Pointer = BeaconPrintf                 },
        { .NameHash = COFFAPI_BEACONOUTPUT,                 .Pointer = BeaconOutput                 },
        { .NameHash = COFFAPI_BEACONUSETOKEN,               .Pointer = BeaconUseToken               },
        { .NameHash = COFFAPI_BEACONREVERTTOKEN,            .Pointer = BeaconRevertToken            },
        { .NameHash = COFFAPI_BEACONISADMIN,                .Pointer = BeaconIsAdmin                },
        { .NameHash = COFFAPI_BEACONGETSPAWNTO,             .Pointer = BeaconGetSpawnTo             },
        { .NameHash = COFFAPI_BEACONINJECTPROCESS,          .Pointer = BeaconInjectProcess          },
        { .NameHash = COFFAPI_BEACONINJECTTEMPORARYPROCESS, .Pointer = BeaconInjectTemporaryProcess },
        { .NameHash = COFFAPI_BEACONCLEANUPPROCESS,         .Pointer = BeaconCleanupProcess         },
        { .NameHash = COFFAPI_TOWIDECHAR,                   .Pointer = toWideChar                   },
        { .NameHash = COFFAPI_LOADLIBRARYA,                 .Pointer = LoadLibraryA                 },
        { .NameHash = COFFAPI_GETPROCADDRESS,               .Pointer = GetProcAddress               },
        { .NameHash = COFFAPI_GETMODULEHANDLE,              .Pointer = GetModuleHandleA             },
        { .NameHash = COFFAPI_FREELIBRARY,                  .Pointer = FreeLibrary                  },
        { .NameHash = COFFAPI_BEACONADDVALUE,               .Pointer = BeaconAddValue               },
        { .NameHash = COFFAPI_BEACONGETVALUE,               .Pointer = BeaconGetValue               },
        { .NameHash = COFFAPI_BEACONREMOVEVALUE,            .Pointer = BeaconRemoveValue            },
        { .NameHash = COFFAPI_BEACONINFORMATION,            .Pointer = BeaconInformation            },
        { .NameHash = COFFAPI_BEACONGETCUSTOMUSERDATA,      .Pointer = BeaconGetCustomUserData      },
        { .NameHash = COFFAPI_BEACONDATASTOREGETITEM,       .Pointer = BeaconDataStoreGetItem       },
        { .NameHash = COFFAPI_BEACONDATASTOREPROTECTITEM,   .Pointer = BeaconDataStoreProtectItem   },
        { .NameHash = COFFAPI_BEACONDATASTOREUNPROTECTITEM, .Pointer = BeaconDataStoreUnprotectItem },
        { .NameHash = COFFAPI_BEACONDATASTOREMAXENTRIES,    .Pointer = BeaconDataStoreMaxEntries    },
        { .NameHash = COFFAPI_BEACONGETSYSCALLINFORMATION,  .Pointer = BeaconGetSyscallInformation  },
        { .NameHash = COFFAPI_BEACONVIRTUALALLOC,           .Pointer = BeaconVirtualAlloc           },
        { .NameHash = COFFAPI_BEACONVIRTUALALLOCEX,         .Pointer = BeaconVirtualAllocEx         },
        { .NameHash = COFFAPI_BEACONVIRTUALPROTECT,         .Pointer = BeaconVirtualProtect         },
        { .NameHash = COFFAPI_BEACONVIRTUALPROTECTEX,       .Pointer = BeaconVirtualProtectEx       },
        { .NameHash = COFFAPI_BEACONVIRTUALFREE,            .Pointer = BeaconVirtualFree            },
        { .NameHash = COFFAPI_BEACONGETTHREADCONTEXT,       .Pointer = BeaconGetThreadContext       },
        { .NameHash = COFFAPI_BEACONSETTHREADCONTEXT,       .Pointer = BeaconSetThreadContext       },
        { .NameHash = COFFAPI_BEACONRESUMETHREAD,           .Pointer = BeaconResumeThread           },
        { .NameHash = COFFAPI_BEACONOPENPROCESS,            .Pointer = BeaconOpenProcess            },
        { .NameHash = COFFAPI_BEACONOPENTHREAD,             .Pointer = BeaconOpenThread             },
        { .NameHash = COFFAPI_BEACONCLOSEHANDLE,            .Pointer = BeaconCloseHandle            },
        { .NameHash = COFFAPI_BEACONUNMAPVIEWOFFILE,        .Pointer = BeaconUnmapViewOfFile        },
        { .NameHash = COFFAPI_BEACONVIRTUALQUERY,           .Pointer = BeaconVirtualQuery           },
        { .NameHash = COFFAPI_BEACONDUPLICATEHANDLE,        .Pointer = BeaconDuplicateHandle        },
        { .NameHash = COFFAPI_BEACONREADPROCESSMEMORY,      .Pointer = BeaconReadProcessMemory      },
        { .NameHash = COFFAPI_BEACONWRITEPROCESSMEMORY,     .Pointer = BeaconWriteProcessMemory     },

};

DWORD BeaconApiCounter = 52;

// the rest was taken from https://github.com/trustedsec/COFFLoader/blob/main/beacon_compatibility.c. credit goes to them
UINT32 swap_endianess( UINT32 indata )
{
    UINT32 testint = 0xaabbccdd;
    UINT32 outint  = indata;

    if (((unsigned char*)&testint)[0] == 0xdd)
    {
        ((unsigned char*)&outint)[0] = ((unsigned char*)&indata)[3];
        ((unsigned char*)&outint)[1] = ((unsigned char*)&indata)[2];
        ((unsigned char*)&outint)[2] = ((unsigned char*)&indata)[1];
        ((unsigned char*)&outint)[3] = ((unsigned char*)&indata)[0];
    }
    return outint;
}

char* beacon_compatibility_output = NULL;
int beacon_compatibility_size = 0;
int beacon_compatibility_offset = 0;


void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (parser == NULL) {
        return;
    }
    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size;
    return;
}



int BeaconDataInt(datap* parser) {
    UINT32 fourbyteint = 0;
    if (parser->length < 4) {
        return 0;
    }
    memcpy(&fourbyteint, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return (int)fourbyteint;
}

short BeaconDataShort(datap* parser) {
    UINT16 retvalue = 0;
    if (parser->length < 2) {
        return 0;
    }
    memcpy(&retvalue, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return (short)retvalue;
}

int BeaconDataLength(datap* parser) {
    return parser->length;
}
LPWSTR charToLPWSTR(char* charStr) {
    // 获取转换后的宽字符所需的缓冲区大小
    int bufferSize = MultiByteToWideChar(CP_UTF8, 0, charStr, -1, NULL, 0);
    if (bufferSize == 0) {
        // 转换失败，返回 NULL
        return NULL;
    }

    // 分配缓冲区
    LPWSTR wideStr = (LPWSTR)malloc(bufferSize * sizeof(WCHAR));
    if (wideStr == NULL) {
        // 内存分配失败，返回 NULL
        return NULL;
    }

    // 进行转换
    int result = MultiByteToWideChar(CP_UTF8, 0, charStr, -1, wideStr, bufferSize);
    if (result == 0) {
        // 转换失败，释放缓冲区并返回 NULL
        free(wideStr);
        return NULL;
    }

    return wideStr;
}

// 修改 BeaconApi.c 中的 BeaconDataExtract 函数

char* BeaconDataExtract(datap* parser, int* size) {
    int length = 0;


    if (parser->length < 4) {
        return NULL;
    }

    memcpy(&length, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;

    if (length < 0 || length > parser->length) {
        return NULL;
    }

    char* outData = parser->buffer;

    if (size != NULL) {
        *size = length;
    }

  
    parser->buffer += length;
    parser->length -= length;


    return outData; 
}

/* format API */

void BeaconFormatAlloc(formatp* format, int maxsz) {
    if (format == NULL) {
        return;
    }
    format->original = calloc(maxsz, 1);
    format->buffer = format->original;
    format->length = 0;
    format->size = maxsz;
    return;
}

void BeaconFormatReset(formatp* format) {
    memset(format->original, 0, format->size);
    format->buffer = format->original;
    format->length = format->size;
    return;
}

void BeaconFormatFree(formatp* format) {
    if (format == NULL) {
        return;
    }
    if (format->original) {
        free(format->original);
        format->original = NULL;
    }
    format->buffer = NULL;
    format->length = 0;
    format->size = 0;
    return;
}

void BeaconFormatAppend(formatp* format, char* text, int len) {
    memcpy(format->buffer, text, len);
    format->buffer += len;
    format->length += len;
    return;
}

void BeaconFormatPrintf(formatp* format, char* fmt, ...) {
    /*Take format string, and sprintf it into here*/
    va_list args;
    int length = 0;

    va_start(args, fmt);
    length = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (format->length + length > format->size) {
        return;
    }

    va_start(args, fmt);
    (void)vsnprintf(format->buffer, length, fmt, args);
    va_end(args);
    format->length += length;
    format->buffer += length;
    return;
}


char* BeaconFormatToString(formatp* format, int* size) {
    *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp* format, int value) {
    UINT32 indata = value;
    UINT32 outdata = 0;
    if (format->length + 4 > format->size) {
        return;
    }
    outdata = swap_endianess(indata);
    memcpy(format->buffer, &outdata, 4);
    format->length += 4;
    format->buffer += 4;
    return;
}

/* Main output functions */

void BeaconPrintf(int type, char* fmt, ...) {
    /* Change to maintain internal buffer, and return after done running. */
    int length = 0;
    char* tempptr = NULL;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    va_start(args, fmt);
    length = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    tempptr = realloc(beacon_compatibility_output, beacon_compatibility_size + length + 1);
    if (tempptr == NULL) {
        return;
    }
    beacon_compatibility_output = tempptr;
    memset(beacon_compatibility_output + beacon_compatibility_offset, 0, length + 1);
    va_start(args, fmt);
    length = vsnprintf(beacon_compatibility_output + beacon_compatibility_offset, length +1, fmt, args);
    beacon_compatibility_size += length;
    beacon_compatibility_offset += length;
    va_end(args);
    return;
}

void BeaconOutput(int type, char* data, int len)
{
    char* tempptr = NULL;
    tempptr = realloc(beacon_compatibility_output, beacon_compatibility_size + len + 1);
    beacon_compatibility_output = tempptr;
    if (tempptr == NULL) {
        return;
    }
    memset(beacon_compatibility_output + beacon_compatibility_offset, 0, len + 1);
    memcpy(beacon_compatibility_output + beacon_compatibility_offset, data, len);
    beacon_compatibility_size += len;
    beacon_compatibility_offset += len;
    return;
}

/* Token Functions */

BOOL BeaconUseToken(HANDLE token) {
    /* Leaving this to be implemented by people needing/wanting it */
    return TRUE;
}

void BeaconRevertToken(void) {
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

BOOL BeaconIsAdmin(void) {
    /* Leaving this to be implemented by people needing it */
    return FALSE;
}

/* Injection/spawning related stuffs
 *
 * These functions are basic place holders, and if implemented into something
 * real should be just calling internal functions for your tools. */
void BeaconGetSpawnTo(BOOL x86, char* buffer, int length) {
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * sInfo, PROCESS_INFORMATION * pInfo) {
    /* Leaving this to be implemented by people needing/wanting it */
    return FALSE;
}

void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char * arg, int a_len)
{
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len)
{
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo)
{
    (void)CloseHandle(pInfo->hThread);
    (void)CloseHandle(pInfo->hProcess);
    return;
}

BOOL toWideChar(char* src, wchar_t* dst, int max)
{
    /* Leaving this to be implemented by people needing/wanting it */
    return FALSE;
}

char* BeaconGetOutputData(int *outsize)
{
    char* outdata = beacon_compatibility_output;

    if ( outsize )
        *outsize = beacon_compatibility_size;

    beacon_compatibility_output = NULL;
    beacon_compatibility_size = 0;
    beacon_compatibility_offset = 0;

    return outdata;
}

// Windows API proxy functions for COFF loader
HMODULE proxy_LoadLibraryA(LPCSTR lpLibFileName)
{
    return LoadLibraryA(lpLibFileName);
}

HMODULE proxy_GetModuleHandleA(LPCSTR lpModuleName)
{
    return GetModuleHandleA(lpModuleName);
}

FARPROC proxy_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    return GetProcAddress(hModule, lpProcName);
}

BOOL proxy_FreeLibrary(HMODULE hLibModule)
{
    return FreeLibrary(hLibModule);
}

// =================== Beacon API 实现 ===================

// 全局变量用于存储Beacon值
static void* g_beaconValues[256] = {0};  // 简单的键值存储
static int g_beaconValueCount = 0;

// Key/Value store functions - 真正实现
BOOL BeaconAddValue(const char* key, void* ptr)
{
    if (!key || !ptr || g_beaconValueCount >= 256)
        return FALSE;
    
    // 简单的哈希映射（这里简化处理）
    int hash = 0;
    for (const char* p = key; *p; p++) {
        hash = (hash * 31 + *p) % 256;
    }
    
    g_beaconValues[hash] = ptr;
    g_beaconValueCount++;
    return TRUE;
}

void* BeaconGetValue(const char* key)
{
    if (!key)
        return NULL;
    
    // 简单的哈希映射
    int hash = 0;
    for (const char* p = key; *p; p++) {
        hash = (hash * 31 + *p) % 256;
    }
    
    return g_beaconValues[hash];
}

BOOL BeaconRemoveValue(const char* key)
{
    if (!key)
        return FALSE;
    
    // 简单的哈希映射
    int hash = 0;
    for (const char* p = key; *p; p++) {
        hash = (hash * 31 + *p) % 256;
    }
    
    g_beaconValues[hash] = NULL;
    g_beaconValueCount--;
    return TRUE;
}

// Beacon Information - 简化实现
BOOL BeaconInformation(PBEACON_INFO info)
{
    if (!info)
        return FALSE;
    
    // 填充基本信息
    // info->version = 0x041000; // 版本 4.10
    info->sleep_mask_ptr = NULL;
    info->sleep_mask_text_size = 0;
    info->sleep_mask_total_size = 0;
    info->beacon_ptr = NULL;
    info->heap_records = NULL;
    memset(info->mask, 0, sizeof(info->mask));
    
    return TRUE;
}

// Beacon Custom User Data
char* BeaconGetCustomUserData()
{
    return NULL; // 简化实现
}

// Data Store functions - 简化实现
PDATA_STORE_OBJECT BeaconDataStoreGetItem(size_t index)
{
    return NULL; // 简化实现
}

void BeaconDataStoreProtectItem(size_t index)
{
    // 简化实现
}

void BeaconDataStoreUnprotectItem(size_t index)
{
    // 简化实现
}

ULONG BeaconDataStoreMaxEntries()
{
    return 0; // 简化实现
}

// Syscall Information - 简化实现
BOOL BeaconGetSyscallInformation(PBEACON_SYSCALLS info, BOOL resolveIfNotInitialized)
{
    return FALSE; // 简化实现
}

// Virtual Memory functions - 简化实现
LPVOID BeaconVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

LPVOID BeaconVirtualAllocEx(HANDLE processHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    return VirtualAllocEx(processHandle, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL BeaconVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    return VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

BOOL BeaconVirtualProtectEx(HANDLE processHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    return VirtualProtectEx(processHandle, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

BOOL BeaconVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    return VirtualFree(lpAddress, dwSize, dwFreeType);
}

// Thread functions - 简化实现
BOOL BeaconGetThreadContext(HANDLE threadHandle, PCONTEXT threadContext)
{
    return GetThreadContext(threadHandle, threadContext);
}

BOOL BeaconSetThreadContext(HANDLE threadHandle, const CONTEXT * threadContext)
{
    return SetThreadContext(threadHandle, threadContext);
}

DWORD BeaconResumeThread(HANDLE threadHandle)
{
    return ResumeThread(threadHandle);
}

// Process functions - 简化实现
HANDLE BeaconOpenProcess(DWORD desiredAccess, BOOL inheritHandle, DWORD processId)
{
    return OpenProcess(desiredAccess, inheritHandle, processId);
}

HANDLE BeaconOpenThread(DWORD desiredAccess, BOOL inheritHandle, DWORD threadId)
{
    return OpenThread(desiredAccess, inheritHandle, threadId);
}

BOOL BeaconCloseHandle(HANDLE object)
{
    return CloseHandle(object);
}

BOOL BeaconUnmapViewOfFile(LPCVOID baseAddress)
{
    return UnmapViewOfFile(baseAddress);
}

SIZE_T BeaconVirtualQuery(LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length)
{
    return VirtualQuery(address, buffer, length);
}

BOOL BeaconDuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions)
{
    return DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
}

BOOL BeaconReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    return ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

BOOL BeaconWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}