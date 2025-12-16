#include "CoffeeLdr.h" 
#include "BeaconApi.h"

#if defined( __x86_64__ ) || defined( _WIN64 )
#define COFF_PREP_SYMBOL      0xec598a48
#define COFF_PREP_SYMBOL_SIZE 6
#define COFF_PREP_BEACON      0x353400b0
#define COFF_PREP_BEACON_SIZE ( COFF_PREP_SYMBOL_SIZE + 6 )
#endif

#define INITIAL_DLL_CACHE_SIZE 16

PVOID CoffeeProcessSymbol( PCOFFEE Coffee, LPSTR Symbol )
{
    CHAR      Bak[ 1024 ] = { 0 };
    PVOID     FuncAddr    = NULL;
    PCHAR     SymLibrary  = NULL;
    PCHAR     SymFunction = NULL;
    HMODULE   hLibrary    = NULL;
    DWORD     SymHash     = HashString( Symbol + COFF_PREP_SYMBOL_SIZE, 0 );
    DWORD     SymBeacon   = HashString( Symbol, COFF_PREP_BEACON_SIZE );

    memcpy( Bak, Symbol, strlen( Symbol ) + 1 );

    if ( SymBeacon == COFF_PREP_BEACON      ||
         SymHash   == COFFAPI_GETPROCADDRESS   ||
         SymHash   == COFFAPI_LOADLIBRARYA     ||
         SymHash   == COFFAPI_GETMODULEHANDLE  ||
         SymHash   == COFFAPI_FREELIBRARY
    )
    {
        SymFunction = Symbol + COFF_PREP_SYMBOL_SIZE;
        for ( DWORD i = 0; i < BeaconApiCounter; i++ )
        {
            if ( HashString( SymFunction, 0 ) == BeaconApi[ i ].NameHash )
                return BeaconApi[ i ].Pointer;
        }
    }
    else if ( HashString( Symbol, COFF_PREP_SYMBOL_SIZE ) == COFF_PREP_SYMBOL )
    {
        SymLibrary  = Bak + COFF_PREP_SYMBOL_SIZE;
        SymLibrary  = strtok( SymLibrary, "$" );
        SymFunction = SymLibrary + strlen( SymLibrary ) + 1;

        DWORD dllHash = HashString(SymLibrary, 0);
        BOOL inCache = FALSE;
        for (DWORD i = 0; i < Coffee->DllCacheCount; ++i) {
            if (Coffee->DllCache[i].DllNameHash == dllHash) {
                hLibrary = Coffee->DllCache[i].hModule;
                inCache = TRUE;
                break;
            }
        }

        if (!inCache) {
            hLibrary = LoadLibraryA( SymLibrary );
            if (hLibrary && Coffee->DllCacheCount < INITIAL_DLL_CACHE_SIZE) {
                 Coffee->DllCache[Coffee->DllCacheCount].DllNameHash = dllHash;
                 Coffee->DllCache[Coffee->DllCacheCount].hModule = hLibrary;
                 Coffee->DllCacheCount++;
            }
        }

        if ( !hLibrary )
        {
            DEBUG_PRINT( "[!] LoadLibraryA failed for '%s' with error code: %lu\n", SymLibrary, GetLastError() );
            return NULL;
        }
        FuncAddr = GetProcAddress( hLibrary, SymFunction );
    }
    else
    {
        DEBUG_PRINT( "[!] Unknown symbol format: %s\n", Symbol );
        return NULL;
    }

    if ( !FuncAddr )
    {
        DEBUG_PRINT( "[!] Failed to resolve symbol: %s\n", Symbol );
        return NULL;
    }

    return FuncAddr;
}

BOOL CoffeeExecuteFunction( PCOFFEE Coffee, PCHAR Function, PVOID Argument, SIZE_T Size )
{
    typedef VOID ( *COFFEEMAIN ) ( PCHAR , ULONG );
    COFFEEMAIN CoffeeMain    = NULL;
    DWORD      OldProtection = 0;
    BOOL       Success       = FALSE;

    // 参数验证
    if (!Coffee || !Function) {
        DEBUG_PRINT("[!] Invalid parameters: Coffee=%p, Function=%p\n", Coffee, Function);
        return FALSE;
    }

    if (Coffee->dwCodeSection == (DWORD)-1) {
        DEBUG_PRINT("[!] Code section not found in COFF object.\n");
        return FALSE;
    }

    // 验证函数地址是否在有效范围内
    if (!Coffee->SecMap || !Coffee->Header) {
        DEBUG_PRINT("[!] Coffee structure is incomplete\n");
        return FALSE;
    }

    for ( DWORD SymCounter = 0; SymCounter < Coffee->Header->NumberOfSymbols; SymCounter++ )
    {
        if ( strcmp( Coffee->Symbol[ SymCounter ].First.Name, Function ) == 0 )
        {
            // 验证节号是否有效
            if (Coffee->Symbol[ SymCounter ].SectionNumber == 0 || 
                Coffee->Symbol[ SymCounter ].SectionNumber > Coffee->Header->NumberOfSections) {
                DEBUG_PRINT("[!] Invalid section number: %d\n", Coffee->Symbol[ SymCounter ].SectionNumber);
                return FALSE;
            }

            CoffeeMain = ( COFFEEMAIN ) ( Coffee->SecMap[ Coffee->Symbol[ SymCounter ].SectionNumber - 1 ].Ptr + Coffee->Symbol[ SymCounter ].Value );
            
            // 验证函数地址
            if (!CoffeeMain || (UINT_PTR)CoffeeMain < 0x10000) {
                DEBUG_PRINT("[!] Invalid function address: %p\n", CoffeeMain);
                return FALSE;
            }

            // 计算函数相对于代码段基址的偏移
            UINT_PTR codeSectionBase = (UINT_PTR)Coffee->SecMap[Coffee->dwCodeSection].Ptr;
            UINT_PTR functionOffset = (UINT_PTR)CoffeeMain - codeSectionBase;
            
            DEBUG_PRINT("[*] Executing function '%s' at address %p\n", Function, CoffeeMain);
            DEBUG_PRINT("[*] Function offset in code section: 0x%llx (base: %p)\n", functionOffset, (PVOID)codeSectionBase);
            DEBUG_PRINT("[*] Function arguments: %p (size: %lu)\n", Argument, (ULONG)Size);
            DEBUG_PRINT("[*] Code section info: ptr=%p, size=%llu\n", 
                       Coffee->SecMap[Coffee->dwCodeSection].Ptr, 
                       Coffee->SecMap[Coffee->dwCodeSection].Size);

            // 验证参数缓冲区
            if (Argument && Size > 0) {
                DEBUG_PRINT("[*] Validating argument buffer (size: %lu)...\n", (ULONG)Size);
                
                // 检查缓冲区大小是否合理
                if (Size > 1024 * 1024) { // 1MB 限制
                    DEBUG_PRINT("[!] Warning: Argument size is very large (%lu bytes)\n", (ULONG)Size);
                }
                
                // 检查参数是否为有效指针
                if (IsBadReadPtr(Argument, Size)) {
                    DEBUG_PRINT("[!] Argument buffer is not readable or invalid\n");
                    DEBUG_PRINT("[!] This may cause BeaconDataParse to crash\n");
                    DEBUG_PRINT("[!] Buffer address: %p, size: %lu\n", Argument, (ULONG)Size);
                } else {
                    DEBUG_PRINT("[*] Argument buffer validation passed\n");
                    
                    // 显示前几个字节的内容（用于调试）
                    if (Size >= 4) {
                        DWORD* firstDword = (DWORD*)Argument;
                        DEBUG_PRINT("[*] First 4 bytes: 0x%08lx\n", *firstDword);
                    }
                }
            } else {
                DEBUG_PRINT("[*] No argument buffer provided (this is normal for some functions)\n");
            }

            if (!VirtualProtect(Coffee->SecMap[Coffee->dwCodeSection].Ptr, 
                               Coffee->SecMap[Coffee->dwCodeSection].Size, 
                               PAGE_EXECUTE_READ, &OldProtection)) {
                DEBUG_PRINT("[!] VirtualProtect to RX failed with error: %lu\n", GetLastError());
                return FALSE;
            }

            // 执行前的最后检查
            DEBUG_PRINT("[*] Pre-execution checks:\n");
            DEBUG_PRINT("  - Code section base: %p\n", Coffee->SecMap[Coffee->dwCodeSection].Ptr);
            DEBUG_PRINT("  - Function address: %p\n", CoffeeMain);
            DEBUG_PRINT("  - Arguments: %p, %lu\n", Argument, (ULONG)Size);
            DEBUG_PRINT("  - Old protection: 0x%lx\n", OldProtection);
            
            // 调用函数 - 如果这里崩溃，调试器会捕获到
            DEBUG_PRINT("[*] Calling function '%s'...\n", Function);
            DEBUG_PRINT("[*] Function will be called with:\n");
            DEBUG_PRINT("    Buffer: %p\n", Argument);
            DEBUG_PRINT("    Length: %lu\n", (ULONG)Size);
            
            CoffeeMain( (PCHAR)Argument, (ULONG)Size );
            
            DEBUG_PRINT("[*] Function '%s' completed successfully\n", Function);
            
            VirtualProtect(Coffee->SecMap[Coffee->dwCodeSection].Ptr, 
                          Coffee->SecMap[Coffee->dwCodeSection].Size, 
                          OldProtection, &OldProtection);
            
            Success = TRUE;
            break;
        }
    }

    if ( !Success )
        DEBUG_PRINT( "[!] Could not find entry function '%s'\n", Function );

    return Success;
}

BOOL CoffeeCleanup( PCOFFEE Coffee )
{
    for ( DWORD SecCnt = 0; SecCnt < Coffee->Header->NumberOfSections; SecCnt++ )
    {
        if ( Coffee->SecMap && Coffee->SecMap[ SecCnt ].Ptr )
        {
            memset( Coffee->SecMap[ SecCnt ].Ptr, 0, Coffee->SecMap[ SecCnt ].Size );
            if ( !VirtualFree( Coffee->SecMap[ SecCnt ].Ptr, 0, MEM_RELEASE ) ) {
                DEBUG_PRINT( "[!] Failed to free memory for section %lu: %p, error: %lu\n", SecCnt, Coffee->SecMap[ SecCnt ].Ptr, GetLastError() );
            }
            Coffee->SecMap[ SecCnt ].Ptr = NULL;
        }
    }

    if ( Coffee->SecMap ) LocalFree( Coffee->SecMap );
    if ( Coffee->FunMap ) VirtualFree( Coffee->FunMap, 0, MEM_RELEASE );
    if (Coffee->DllCache) LocalFree(Coffee->DllCache);

    Coffee->SecMap = NULL;
    Coffee->FunMap = NULL;
    Coffee->DllCache = NULL;
    
    return TRUE;
}

BOOL CoffeeProcessSections( PCOFFEE Coffee )
{
    PVOID  SymString  = NULL;
    PCHAR  FuncPtr    = NULL;
    DWORD  FuncCount  = 0;
    UINT64 OffsetLong = 0;
    UINT32 Offset     = 0;
    
    for ( DWORD SectionCnt = 0; SectionCnt < Coffee->Header->NumberOfSections; SectionCnt++ )
    {
        Coffee->Section = (PCOFF_SECTION)(U_PTR(Coffee->Data) + sizeof(COFF_FILE_HEADER) + (sizeof(COFF_SECTION) * SectionCnt));
        
        if (Coffee->Section->PointerToRelocations == 0 || Coffee->Section->NumberOfRelocations == 0) {
            continue;
        }
        
        PCOFF_RELOC Reloc = (PCOFF_RELOC)(U_PTR(Coffee->Data) + Coffee->Section->PointerToRelocations);

        for ( DWORD RelocCnt = 0; RelocCnt < Coffee->Section->NumberOfRelocations; RelocCnt++, Reloc++ )
        {
            PCOFF_SYMBOL CurrentSymbol = &Coffee->Symbol[ Reloc->SymbolTableIndex ];
            
            if ( CurrentSymbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL )
            {
                if (CurrentSymbol->First.Value[0] == 0) {
                    SymString = ( ( PCHAR ) ( Coffee->Symbol + Coffee->Header->NumberOfSymbols ) ) + CurrentSymbol->First.Value[1];
                } else {
                    SymString = CurrentSymbol->First.Name;
                }

                FuncPtr = CoffeeProcessSymbol( Coffee, (LPSTR)SymString );
                if ( !FuncPtr )
                {
                    DEBUG_PRINT("[!] Failed to process external symbol: %s\n", (LPSTR)SymString);
                    return FALSE;
                }

                if ( Reloc->Type == IMAGE_REL_AMD64_REL32 )
                {
                    if ((FuncCount * sizeof(UINT64)) >= Coffee->dwFunMapSize) {
                        DEBUG_PRINT("[!] FunMap is too small!\n");
                        return FALSE;
                    }
                    memcpy( Coffee->FunMap + ( FuncCount * sizeof(UINT64) ), &FuncPtr, sizeof( UINT64 ) );
                    Offset = ( UINT32 ) ( (UINT_PTR)( Coffee->FunMap + ( FuncCount * sizeof(UINT64) ) ) - ( (UINT_PTR)Coffee->SecMap[ SectionCnt ].Ptr + Reloc->VirtualAddress + 4 ) );
                    memcpy( Coffee->SecMap[ SectionCnt ].Ptr + Reloc->VirtualAddress, &Offset, sizeof( UINT32 ) );
                    FuncCount++;
                } else {
                     DEBUG_PRINT("[!] Unsupported relocation type %d for external symbol %s\n", Reloc->Type, (LPSTR)SymString);
                }
            }
            else 
            {
                PCHAR TargetSectionPtr = Coffee->SecMap[ CurrentSymbol->SectionNumber - 1 ].Ptr;
                PCHAR SourceSectionPtr = Coffee->SecMap[ SectionCnt ].Ptr;

                switch (Reloc->Type) {
                    case IMAGE_REL_AMD64_ADDR64: {
                        UINT64 OriginalValue;
                        memcpy(&OriginalValue, SourceSectionPtr + Reloc->VirtualAddress, sizeof(UINT64));
                        OffsetLong = (UINT64)TargetSectionPtr + OriginalValue;
                        memcpy(SourceSectionPtr + Reloc->VirtualAddress, &OffsetLong, sizeof(UINT64));
                        break;
                    }

                    case IMAGE_REL_AMD64_ADDR32NB: {
                        UINT32 OriginalValue;
                        memcpy(&OriginalValue, SourceSectionPtr + Reloc->VirtualAddress, sizeof(UINT32));
                        Offset = (UINT32)((UINT_PTR)TargetSectionPtr + OriginalValue - (UINT_PTR)Coffee->Data);
                        memcpy(SourceSectionPtr + Reloc->VirtualAddress, &Offset, sizeof(UINT32));
                        break;
                    }
                    
                    case IMAGE_REL_AMD64_REL32:
                    case IMAGE_REL_AMD64_REL32_1:
                    case IMAGE_REL_AMD64_REL32_2:
                    case IMAGE_REL_AMD64_REL32_3:
                    case IMAGE_REL_AMD64_REL32_4:
                    case IMAGE_REL_AMD64_REL32_5: {
                         UINT32 OriginalValue;
                         memcpy(&OriginalValue, SourceSectionPtr + Reloc->VirtualAddress, sizeof(UINT32));
                         
                         UINT_PTR TargetAddress = (UINT_PTR)TargetSectionPtr + CurrentSymbol->Value + OriginalValue;
                         UINT_PTR SourceAddress = (UINT_PTR)SourceSectionPtr + Reloc->VirtualAddress;
                         
                         Offset = (UINT32)(TargetAddress - (SourceAddress + 4));
                         memcpy(SourceSectionPtr + Reloc->VirtualAddress, &Offset, sizeof(UINT32));
                         break;
                    }
                         
                    default:
                        DEBUG_PRINT("[!] Unsupported relocation type %d for internal symbol\n", Reloc->Type);
                        return FALSE;
                }
            }
        }
    }

    return TRUE;
}


DWORD CoffeeLdr( PCHAR EntryName, PVOID CoffeeData, PVOID ArgData, SIZE_T ArgSize )
{
    COFFEE Coffee = { 0 };

    if ( !CoffeeData ) {
        DEBUG_PRINT("[!] CoffeeData is NULL.\n");
        return 1;
    }

    Coffee.Data   = CoffeeData;
    Coffee.Header = (PCOFF_FILE_HEADER)Coffee.Data;
    Coffee.dwCodeSection = (DWORD)-1;

    if (Coffee.Header->Machine != MACHINETYPE_AMD64) {
        DEBUG_PRINT("[!] Invalid machine type: 0x%x. Only AMD64 is supported.\n", Coffee.Header->Machine);
        return 1;
    }

    Coffee.SecMap = LocalAlloc( LPTR, Coffee.Header->NumberOfSections * sizeof( SECTION_MAP ) );
    if (!Coffee.SecMap) return 1;
    
    Coffee.DllCache = LocalAlloc(LPTR, INITIAL_DLL_CACHE_SIZE * sizeof(DLL_CACHE_ENTRY));
    if (!Coffee.DllCache) { LocalFree(Coffee.SecMap); return 1; }
    Coffee.DllCacheCount = 0;


    DEBUG_PRINT( "[*] Loading sections into memory...\n" );
    DWORD externalRelocCount = 0;
    for ( DWORD SecCnt = 0 ; SecCnt < Coffee.Header->NumberOfSections; SecCnt++ )
    {
        Coffee.Section = (PCOFF_SECTION)(U_PTR(Coffee.Data) + sizeof(COFF_FILE_HEADER) + (sizeof(COFF_SECTION) * SecCnt));
        
        DWORD sizeToAlloc = Coffee.Section->VirtualSize;
        DWORD sizeToCopy = Coffee.Section->SizeOfRawData;

        if (sizeToAlloc == 0) sizeToAlloc = sizeToCopy;
        
        Coffee.SecMap[SecCnt].Ptr = NULL;
        Coffee.SecMap[SecCnt].Size = 0;
        
        if (sizeToAlloc > 0) {
            Coffee.SecMap[SecCnt].Size = sizeToAlloc;
            Coffee.SecMap[SecCnt].Ptr  = VirtualAlloc( NULL, sizeToAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
            if (!Coffee.SecMap[SecCnt].Ptr) { CoffeeCleanup(&Coffee); return 1; }
            memset(Coffee.SecMap[SecCnt].Ptr, 0, sizeToAlloc);
            if (sizeToCopy > 0) {
                memcpy(Coffee.SecMap[SecCnt].Ptr, (void *)(U_PTR(CoffeeData) + Coffee.Section->PointerToRawData), sizeToCopy);
            }
        }
        DEBUG_PRINT("    - Section %lu ('%.8s') loaded at %p (Allocated: %lu, Copied: %lu)\n", SecCnt, Coffee.Section->Name, Coffee.SecMap[SecCnt].Ptr, sizeToAlloc, sizeToCopy);

        if ( (Coffee.Section->Characteristics & IMAGE_SCN_CNT_CODE) && Coffee.dwCodeSection == (DWORD)-1 ) {
            Coffee.dwCodeSection = SecCnt;
            DEBUG_PRINT("[*] Code section identified as section %lu\n", SecCnt);
        }

        if (Coffee.Section->PointerToRelocations != 0) {
             PCOFF_RELOC relocs = (PCOFF_RELOC)(U_PTR(Coffee.Data) + Coffee.Section->PointerToRelocations);
             PCOFF_SYMBOL symbols = (PCOFF_SYMBOL)(U_PTR(Coffee.Data) + Coffee.Header->PointerToSymbolTable);
             for (int i = 0; i < Coffee.Section->NumberOfRelocations; ++i) {
                 if (symbols[relocs[i].SymbolTableIndex].StorageClass == IMAGE_SYM_CLASS_EXTERNAL) {
                     externalRelocCount++;
                 }
             }
        }
    }
    
    Coffee.dwFunMapSize = externalRelocCount * sizeof(UINT64);
    if (Coffee.dwFunMapSize > 0) {
        Coffee.FunMap = VirtualAlloc(NULL, Coffee.dwFunMapSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!Coffee.FunMap) { CoffeeCleanup(&Coffee); return 1; }
    }

    Coffee.Symbol = (PCOFF_SYMBOL)(U_PTR(Coffee.Data) + Coffee.Header->PointerToSymbolTable);

    DEBUG_PRINT( "[*] Processing relocations...\n" );
    if ( !CoffeeProcessSections( &Coffee ) )
    {
        DEBUG_PRINT( "[!] Failed to process COFF sections and relocations.\n" );
        CoffeeCleanup( &Coffee );
        return 1;
    }

    DEBUG_PRINT( "[*] Executing entry point '%s'...\n", EntryName );
    CoffeeExecuteFunction( &Coffee, EntryName, ArgData, ArgSize );

    DEBUG_PRINT( "[*] Cleaning up allocated resources...\n" );
    CoffeeCleanup( &Coffee );

    DEBUG_PRINT( "[*] CoffeeLdr finished.\n" );
    return 0;
}


LPVOID LoadFileIntoMemory( LPSTR Path, PDWORD MemorySize )
{
    HANDLE  hFile       = NULL;
    LPVOID  ImageBuffer = NULL;
    DWORD   dwBytesRead = 0;
    DWORD   fileSize    = 0;

    hFile = CreateFileA( Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if ( hFile == INVALID_HANDLE_VALUE )
    {
        DEBUG_PRINT("[!] CreateFileA failed for '%s', error: %lu\n", Path, GetLastError());
        return NULL;
    }

    fileSize = GetFileSize( hFile, NULL );
    if (fileSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return NULL; }

    if (MemorySize) *MemorySize = fileSize;

    ImageBuffer = LocalAlloc( LPTR, fileSize );
    if (!ImageBuffer) { CloseHandle(hFile); return NULL; }

    if (!ReadFile( hFile, ImageBuffer, fileSize, &dwBytesRead, NULL ) || dwBytesRead != fileSize) {
        LocalFree(ImageBuffer); ImageBuffer = NULL;
    }
    
    CloseHandle(hFile);
    return ImageBuffer;
}

DWORD HashString( PVOID String, SIZE_T Length )
{
    ULONG  Hash = HASH_KEY;
    PUCHAR Ptr  = (PUCHAR)String;
    BOOL   useLen = (Length != 0);

    while (TRUE)
    {
        if (useLen) {
            if ((ULONG)(Ptr - (PUCHAR)String) >= Length) break;
        } else {
            if (*Ptr == '\0') break;
        }
        
        UCHAR character = *Ptr;
        if (character >= 'a' && character <= 'z')
            character -= 0x20;

        Hash = ((Hash << 5) + Hash) + character;
        Ptr++;
    }

    return Hash;
}

unsigned char* unhexlify(unsigned char* value, int *outlen) {
    unsigned char* retval = NULL;
    char byteval[3] = { 0 };
    unsigned int counter = 0;
    int counter2 = 0;
    char character = 0;
    if (value == NULL) {
        return NULL;
    }
    DEBUG_PRINT("Unhexlify Strlen: %lu\n", (long unsigned int)strlen((char*)value));
    if (strlen((char*)value) % 2 != 0) {
        DEBUG_PRINT("Either value is NULL, or the hexlified string isn't valid\n");
        goto errcase;
    }

    retval = (unsigned char*) calloc(strlen((char*)value) + 1, 1);
    if (retval == NULL) {
        goto errcase;
    }

    counter2 = 0;
    for (counter = 0; counter < strlen((char*)value); counter += 2) {
        memcpy(byteval, value + counter, 2);
        character = (char)strtol(byteval, NULL, 16);
        memcpy(retval + counter2, &character, 1);
        counter2++;
    }
    *outlen = counter2;

errcase:
    return retval;
}

unsigned char* getArgData(int argc, char* argv[]) {
    if (argc <= 3) return NULL;

    unsigned char* arg_data = (unsigned char*)malloc(strlen(argv[3]) + 1);
    if (!arg_data) return NULL;

    strcpy((char*)arg_data, argv[3]);
    return arg_data;
}