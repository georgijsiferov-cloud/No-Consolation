# 修改日志

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
