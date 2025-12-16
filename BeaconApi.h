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
#define COFFAPI_BEACONADDVALUE                  0xddd4ebd3
#define COFFAPI_BEACONGETVALUE                  0xd9acafea  
#define COFFAPI_BEACONREMOVEVALUE               0x40ae9538

// Additional Beacon API hashes for full implementation
#define COFFAPI_BEACONINFORMATION               0x62b2e633
#define COFFAPI_BEACONGETCUSTOMUSERDATA         0x44b8c6a1
#define COFFAPI_BEACONDATASTOREGETITEM          0x386948e3
#define COFFAPI_BEACONDATASTOREPROTECTITEM      0xaa5ef224
#define COFFAPI_BEACONDATASTOREUNPROTECTITEM    0xb0ceba87
#define COFFAPI_BEACONDATASTOREMAXENTRIES       0xaa413eb4
#define COFFAPI_BEACONGETSYSCALLINFORMATION     0xa6e0332e
#define COFFAPI_BEACONVIRTUALALLOC              0x52e60e7f
#define COFFAPI_BEACONVIRTUALALLOCEX            0xa4a3b37c
#define COFFAPI_BEACONVIRTUALPROTECT            0x35854635
#define COFFAPI_BEACONVIRTUALPROTECTEX          0xabefb0b2
#define COFFAPI_BEACONVIRTUALFREE               0xf3020d36
#define COFFAPI_BEACONGETTHREADCONTEXT          0xbb1a924a
#define COFFAPI_BEACONSETTHREADCONTEXT          0x4d9858d6
#define COFFAPI_BEACONRESUMETHREAD              0xd7322d56
#define COFFAPI_BEACONOPENPROCESS               0x9cdf47de
#define COFFAPI_BEACONOPENTHREAD                0x05a05cb7
#define COFFAPI_BEACONCLOSEHANDLE               0x0f76900f
#define COFFAPI_BEACONUNMAPVIEWOFFILE           0xf1e8041e
#define COFFAPI_BEACONVIRTUALQUERY              0x540c68aa
#define COFFAPI_BEACONDUPLICATEHANDLE           0x88e11594
#define COFFAPI_BEACONREADPROCESSMEMORY         0xbd47abc1
#define COFFAPI_BEACONWRITEPROCESSMEMORY        0x399fd510

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