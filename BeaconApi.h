#ifndef COFFEELDR_BEACONAPI_H
#define COFFEELDR_BEACONAPI_H

#include <windows.h>

#define COFFAPI_BEACONDATAPARSER                0xd0d30e22
#define COFFAPI_BEACONDATAINT                   0xff041492
#define COFFAPI_BEACONDATASHORT                 0xd10d2177
#define COFFAPI_BEACONDATALENGTH                0xe2262f89
#define COFFAPI_BEACONDATAEXTRACT               0x38d8c562

#define COFFAPI_BEACONFORMATALLOC               0x67aab721
#define COFFAPI_BEACONFORMATRESET               0x68da9d99
#define COFFAPI_BEACONFORMATFREE                0xf3a32998
#define COFFAPI_BEACONFORMATAPPEND              0x5d4c05ee
#define COFFAPI_BEACONFORMATPRINTF              0x8069e8c9
#define COFFAPI_BEACONFORMATTOSTRING            0x245f03f0
#define COFFAPI_BEACONFORMATINT                 0x2669d741

#define COFFAPI_BEACONPRINTF                    0x89bf3d20
#define COFFAPI_BEACONOUTPUT                    0x87a66ede
#define COFFAPI_BEACONUSETOKEN                  0xd7dbbb5b
#define COFFAPI_BEACONREVERTTOKEN               0xd7421e6
#define COFFAPI_BEACONISADMIN                   0xa88e0392
#define COFFAPI_BEACONGETSPAWNTO                0x32e13a39
#define COFFAPI_BEACONSPAWNTEMPORARYPROCESS     0xad80158
#define COFFAPI_BEACONINJECTPROCESS             0xe8f5bd09
#define COFFAPI_BEACONINJECTTEMPORARYPROCESS    0x96fbf28c
#define COFFAPI_BEACONCLEANUPPROCESS            0xa0dc954

#define COFFAPI_TOWIDECHAR                      0x5cec66cf
#define COFFAPI_LOADLIBRARYA                    0xb7072fdb
#define COFFAPI_GETPROCADDRESS                  0xdecfc1bf
#define COFFAPI_GETMODULEHANDLE                 0xd908e1d8
#define COFFAPI_FREELIBRARY                     0x4ad9b11c

// Beacon Value Store APIs
#define COFFAPI_BEACONADDVALUE                  0x7f8a2c1b
#define COFFAPI_BEACONGETVALUE                  0x9d3f7e2c  
#define COFFAPI_BEACONREMOVEVALUE               0x5b8e4a9d

// Additional Beacon API hashes for full implementation
#define COFFAPI_BEACONINFORMATION               0x3a1c9f5e
#define COFFAPI_BEACONGETCUSTOMUSERDATA         0x8b2d7c1a
#define COFFAPI_BEACONDATASTOREGETITEM          0x9c7e3d2b
#define COFFAPI_BEACONDATASTOREPROTECTITEM      0x5d4c8e2f
#define COFFAPI_BEACONDATASTOREUNPROTECTITEM    0x7f9a6c5e
#define COFFAPI_BEACONDATASTOREMAXENTRIES       0x6e3d8c1a
#define COFFAPI_BEACONGETSYSCALLINFORMATION     0x8f2d7c5b
#define COFFAPI_BEACONVIRTUALALLOC              0x9d3e6c2a
#define COFFAPI_BEACONVIRTUALALLOCEX            0x5f8d7e3b
#define COFFAPI_BEACONVIRTUALPROTECT            0x7e4c9d2f
#define COFFAPI_BEACONVIRTUALPROTECTEX          0x9f6d8e4a
#define COFFAPI_BEACONVIRTUALFREE               0x6d3c7f2b
#define COFFAPI_BEACONGETTHREADCONTEXT          0x8c4d9e3a
#define COFFAPI_BEACONSETTHREADCONTEXT          0x5e7d4c2f
#define COFFAPI_BEACONRESUMETHREAD              0x9c6f8d4b
#define COFFAPI_BEACONOPENPROCESS               0x7d4e9c3a
#define COFFAPI_BEACONOPENTHREAD                0x5f8c7d2e
#define COFFAPI_BEACONCLOSEHANDLE               0x9e6d4f3b
#define COFFAPI_BEACONUNMAPVIEWOFFILE           0x6c8d9e4f
#define COFFAPI_BEACONVIRTUALQUERY              0x8f4d7c2e
#define COFFAPI_BEACONDUPLICATEHANDLE           0x5e9c6d3f
#define COFFAPI_BEACONREADPROCESSMEMORY         0x9d4f8c2e
#define COFFAPI_BEACONWRITEPROCESSMEMORY        0x6e8d4f3c

typedef struct
{
    UINT_PTR    NameHash;
    PVOID       Pointer;
} COFFAPIFUNC;

extern COFFAPIFUNC BeaconApi[ ];
extern DWORD       BeaconApiCounter;

typedef struct {
    char * original; /* the original buffer [so we can free it] */
    char * buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} datap;

typedef struct {
    char * original; /* the original buffer [so we can free it] */
    char * buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} formatp;

void    BeaconDataParse(datap * parser, char * buffer, int size);
int     BeaconDataInt(datap * parser);
short   BeaconDataShort(datap * parser);
int     BeaconDataLength(datap * parser);
char *  BeaconDataExtract(datap * parser, int * size);
void    BeaconFormatAlloc(formatp * format, int maxsz);
void    BeaconFormatReset(formatp * format);
void    BeaconFormatFree(formatp * format);
void    BeaconFormatAppend(formatp * format, char * text, int len);
void    BeaconFormatPrintf(formatp * format, char * fmt, ...);
char *  BeaconFormatToString(formatp * format, int * size);
void    BeaconFormatInt(formatp * format, int value);

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20


void   BeaconPrintf(int type, char * fmt, ...);
void   BeaconOutput(int type, char * data, int len);

/* Token Functions */
BOOL   BeaconUseToken(HANDLE token);
void   BeaconRevertToken();
BOOL   BeaconIsAdmin();

/* Spawn+Inject Functions */
void   BeaconGetSpawnTo(BOOL x86, char * buffer, int length);
BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * sInfo, PROCESS_INFORMATION * pInfo);
void   BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

/* Utility Functions */
BOOL   toWideChar(char * src, wchar_t * dst, int max);
UINT32 swap_endianess(UINT32 indata);

char* BeaconGetOutputData(int *outsize);

/* =================== Beacon API Extension =================== */

typedef struct {
    char * ptr;
    size_t size;
} HEAP_RECORD;

#define MASK_SIZE 13

typedef struct {
    char  * sleep_mask_ptr;
    DWORD   sleep_mask_text_size;
    DWORD   sleep_mask_total_size;

    char  * beacon_ptr;
    DWORD * sections;
    HEAP_RECORD * heap_records;
    char    mask[MASK_SIZE];
} BEACON_INFO, *PBEACON_INFO;

typedef struct {
    int type;
    DWORD64 hash;
    BOOL masked;
    char* buffer;
    size_t length;
} DATA_STORE_OBJECT, *PDATA_STORE_OBJECT;

typedef void* PBEACON_SYSCALLS;

BOOL BeaconAddValue(const char* key, void* ptr);
void* BeaconGetValue(const char* key);
BOOL BeaconRemoveValue(const char* key);
BOOL BeaconInformation(PBEACON_INFO info);
char* BeaconGetCustomUserData();
PDATA_STORE_OBJECT BeaconDataStoreGetItem(size_t index);
void BeaconDataStoreProtectItem(size_t index);
void BeaconDataStoreUnprotectItem(size_t index);
ULONG BeaconDataStoreMaxEntries();
BOOL BeaconGetSyscallInformation(PBEACON_SYSCALLS info, BOOL resolveIfNotInitialized);

/* Memory / Thread / Process APIs */
LPVOID BeaconVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
LPVOID BeaconVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL BeaconVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
BOOL BeaconVirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
BOOL BeaconVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
BOOL BeaconGetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
BOOL BeaconSetThreadContext(HANDLE hThread, const CONTEXT *lpContext);
DWORD BeaconResumeThread(HANDLE hThread);
HANDLE BeaconOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
HANDLE BeaconOpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
BOOL BeaconCloseHandle(HANDLE hObject);
BOOL BeaconUnmapViewOfFile(LPCVOID lpBaseAddress);
SIZE_T BeaconVirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
BOOL BeaconDuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
BOOL BeaconReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
BOOL BeaconWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);

#endif