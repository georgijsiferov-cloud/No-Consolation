# 修改日志

## 修复 BOF 执行崩溃问题 (2024-12-16)

### 问题描述
BOF在执行 `CoffeeMain( (PCHAR)Argument, (ULONG)Size );` 时直接崩溃，没有提供足够的调试信息来定位崩溃原因。原始崩溃日志：
```
[*] Executing function 'go' at address 000001eb201ddfb4
[*] Function arguments: 000001eb20217760 (size: 27855)
[*] Calling function 'go'...
[*] Function will be called with:
    Buffer: 000001eb20217760
    Length: 27855
PS C:\Users\user\Desktop\Zv0.1.1\server.beacon>  // 崩溃
```

### 根本原因分析
崩溃发生在两个可能的位置：
1. **CoffeeLdr 调用 BOF 函数时**: `CoffeeMain( (PCHAR)Argument, (ULONG)Size );` 
2. **BOF 内部执行时**: `BeaconDataParse(&parser, Buffer, Length);`

### 修改内容

#### 1. `CoffeeLdr.c` - 增强异常处理和调试
```c
// 添加异常处理包装器
__try {
    DEBUG_PRINT("[*] Entering try block...\n");
    CoffeeMain( (PCHAR)Argument, (ULONG)Size );
    DEBUG_PRINT("[*] Function '%s' completed successfully\n", Function);
} __except(EXCEPTION_EXECUTE_HANDLER) {
    DWORD exceptionCode = GetExceptionCode();
    PEXCEPTION_POINTERS exceptionInfo = GetExceptionInformation();
    DEBUG_PRINT("[!] Exception occurred during function call!\n");
    DEBUG_PRINT("[!] Exception code: 0x%08lx\n", exceptionCode);
    if (exceptionInfo) {
        DEBUG_PRINT("[!] Exception address: %p\n", exceptionInfo->ExceptionRecord->ExceptionAddress);
        DEBUG_PRINT("[!] Exception flags: 0x%08lx\n", exceptionInfo->ExceptionRecord->ExceptionFlags);
    }
    DEBUG_PRINT("[!] This indicates the BOF function '%s' crashed internally\n", Function);
    DEBUG_PRINT("[!] The crash is NOT in CoffeeLdr but in the BOF code itself\n");
    return FALSE;
}
```

#### 2. `entry.c` - BOF 函数参数验证
```c
int go(IN PCHAR Buffer, IN ULONG Length)
{
    datap parser = { 0 };
    
    // 调试信息：检查函数参数
    PRINT_DEBUG("[DEBUG] go() function called with Buffer=%p, Length=%lu", Buffer, Length);
    
    // 验证参数
    if (!Buffer) {
        PRINT_ERR("Buffer is NULL - this will cause BeaconDataParse to crash");
        return 1;
    }
    
    if (Length == 0) {
        PRINT_ERR("Length is 0 - no data to parse");
        return 1;
    }
    
    // 验证Buffer是否可读
    if (IsBadReadPtr(Buffer, Length >= 16 ? 16 : Length)) {
        PRINT_ERR("Buffer is not readable - this will cause BeaconDataParse to crash");
        PRINT_ERR("Buffer: %p, Length: %lu", Buffer, Length);
        return 1;
    }
    
    // 初始化parser
    memset(&parser, 0, sizeof(datap));
    
    // 调用BeaconDataParse - 这里崩溃表明参数有问题
    BeaconDataParse(&parser, Buffer, Length);
    
    PRINT_DEBUG("[DEBUG] BeaconDataParse completed successfully");
    
    // 验证parser是否正确初始化
    if (parser.original == NULL || parser.size == 0) {
        PRINT_ERR("BeaconDataParse failed - parser not properly initialized");
        PRINT_ERR("Parser.original: %p, Parser.size: %lu", parser.original, parser.size);
        return 1;
    }
}
```

#### 3. `include/output.h` - 添加调试宏
```c
#if defined(DEBUG)
 #define PRINT_DEBUG(...) { \
     BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__); \
 }
#else
 #define PRINT_DEBUG(...)
#endif
```

### 调试信息增强

#### 函数调用前验证
```c
// 添加额外的参数验证
DEBUG_PRINT("[*] Final validation before call:\n");
DEBUG_PRINT("    CoffeeMain: %p\n", CoffeeMain);
DEBUG_PRINT("    Argument buffer readable: %s\n", 
           !IsBadReadPtr(Argument, Size >= 4 ? 4 : Size) ? "YES" : "NO");
DEBUG_PRINT("    Size range check: %s\n", 
           (Size > 0 && Size <= 1024*1024*10) ? "VALID" : "INVALID");
```

#### 参数内容预览
```c
// 显示前几个字节的内容
if (Length >= 4) {
    DWORD firstBytes = *(DWORD*)Buffer;
    PRINT_DEBUG("[DEBUG] Buffer first 4 bytes: 0x%08lx", firstBytes);
}
```

### 异常类型诊断
通过异常处理，现在可以区分：
1. **CoffeeLdr 内部崩溃**: 参数验证失败、内存访问错误等
2. **BOF 函数崩溃**: BOF代码执行时的段错误、访问违规等
3. **BeaconDataParse 崩溃**: 参数格式错误、数据损坏等

### 预期调试输出
修复后，崩溃时将输出：
```
[DEBUG] go() function called with Buffer=000001eb20217760, Length=27855
[DEBUG] Buffer first 4 bytes: 0x00000012
[DEBUG] About to call BeaconDataParse...
[DEBUG] BeaconDataParse completed successfully
[DEBUG] Parser initialized: original=000001eb20217760, size=27855, offset=0
[*] Calling function 'go'...
[*] Final validation before call:
    CoffeeMain: 000001eb201ddfb4
    Argument buffer readable: YES
    Size range check: VALID
[*] Entering try block...
[!] Exception occurred during function call!
[!] Exception code: 0xc0000005  // ACCESS_VIOLATION
[!] Exception address: 000001eb201dxxxx  // BOF内部地址
[!] This indicates the BOF function 'go' crashed internally
```

这将明确显示：
- 参数验证通过
- 崩溃发生在BOF函数内部
- 具体的异常类型和地址

---

## 修复 CoffeeLoad 崩溃问题

### 问题描述
1.  **程序崩溃**: 在成功加载sections和处理重定位后，执行入口函数 'go' 时程序崩溃。
   ```
   [*] Executing entry point 'go'...
   [*] Executing function 'go' at address 0000022449ebdfb4
   PS C:\Users\user\Desktop\Zv0.1.1\server.beacon>  // 崩溃
   ```

2. **缺少调试信息**: 崩溃时没有足够的调试信息来诊断崩溃原因。

3. **参数验证不足**: 缺少对函数地址、参数和内存区域的验证。

### 修改内容

#### 1. `CoffeeLdr.c`
*   **增强参数验证**: 
    - 添加了对 `Coffee` 和 `Function` 参数的 NULL 检查
    - 验证 `Coffee` 结构体的完整性（`SecMap` 和 `Header`）
    - 检查符号表中的节号是否有效
    - 验证计算出的函数地址是否在有效范围内
*   **详细的内存缓冲区检查**:
    - 使用 `IsBadReadPtr` 验证参数缓冲区是否可读
    - 检查缓冲区大小是否合理（设置1MB限制）
    - 显示参数缓冲区的内容（前4字节）用于调试
    - 特别关注可能导致 `BeaconDataParse` 崩溃的问题
*   **改进调试输出**: 
    - 计算并显示函数在代码段中的偏移地址
    - 添加执行前的详细状态检查
    - 分步骤显示函数调用的参数
    - 成功执行后输出确认信息
*   **增强的地址验证**:
    - 验证函数地址是否在代码段范围内
    - 显示代码段基址和大小信息

#### 2. `CoffeeLdr.h`
*   **添加异常处理头文件**: 包含 `<excpt.h>` 头文件以支持 Windows 异常处理机制。

#### 3. `Makefile`
*   **启用异常处理**: 添加 `-fexceptions` 编译器选项
*   **添加 CoffeeLdr 编译目标**: 方便单独编译测试 CoffeeLdr 模块

### 修复细节

#### 内存缓冲区验证
```c
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
}
```

#### 函数地址验证和偏移计算
```c
// 验证函数地址
if (!CoffeeMain || (UINT_PTR)CoffeeMain < 0x10000) {
    DEBUG_PRINT("[!] Invalid function address: %p\n", CoffeeMain);
    return FALSE;
}

// 计算函数相对于代码段基址的偏移
UINT_PTR codeSectionBase = (UINT_PTR)Coffee->SecMap[Coffee->dwCodeSection].Ptr;
UINT_PTR functionOffset = (UINT_PTR)CoffeeMain - codeSectionBase;

DEBUG_PRINT("[*] Function offset in code section: 0x%llx (base: %p)\n", functionOffset, (PVOID)codeSectionBase);
```

#### 执行前状态检查
```c
// 执行前的最后检查
DEBUG_PRINT("[*] Pre-execution checks:\n");
DEBUG_PRINT("  - Code section base: %p\n", Coffee->SecMap[Coffee->dwCodeSection].Ptr);
DEBUG_PRINT("  - Function address: %p\n", CoffeeMain);
DEBUG_PRINT("  - Arguments: %p, %lu\n", Argument, (ULONG)Size);
DEBUG_PRINT("  - Old protection: 0x%lx\n", OldProtection);

// 调用函数
DEBUG_PRINT("[*] Calling function '%s'...\n", Function);
CoffeeMain( (PCHAR)Argument, (ULONG)Size );
```

### 修复编译问题
在修复过程中还发现并解决了一个编译错误：
- **缺少头文件**: `source/utils.c` 中使用了 `LONG_MAX` 但没有包含 `<limits.h>` 头文件
- **解决方案**: 在 `source/utils.c` 开头添加了 `#include <limits.h>`

### 验证编译
所有修改完成后，成功编译了：
- `dist/NoConsolation.x64.o` - x64 版本
- `dist/NoConsolation.x86.o` - x86 版本

### 预期效果
通过以上修改，当程序再次崩溃时，调试输出将包含：
1. **详细的函数信息**: 函数地址、代码段偏移、基址等
2. **完整的参数验证**: 缓冲区可读性检查、大小验证、内容预览
3. **执行前状态**: 代码段状态、权限设置、参数值等
4. **崩溃定位**: 通过调试输出逐步定位崩溃发生的位置

这些修改将显著提高调试能力，帮助快速定位崩溃的具体原因。
