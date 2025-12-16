# 修改日志

## 修复 BeaconApi 崩溃问题

### 问题描述
1.  **编译错误**: `BeaconApi.c` 中使用了未声明的函数和宏，例如 `BeaconAddValue`, `BeaconGetValue` 等，导致 `x86_64-w64-mingw32-gcc` 编译失败。此外，`BEACON_INFO` 结构体和相关类型定义缺失。
2.  **运行时错误**: 即使修复了编译错误，运行 `beacon.exe` 加载 BOF 时报错 `[!] Failed to resolve symbol: __imp_BeaconGetValue`。这是因为 `BeaconApi.h` 中定义的 API 哈希值与 `CoffeeLdr.c` 中使用的哈希算法（djb2, HASH_KEY=5381）计算出的值不匹配。
3.  **程序崩溃**: 修复符号解析错误后，程序在执行时崩溃，提示"BeaconGetValue实现不正确导致程序crash"。

### 修改内容

#### 1. `BeaconApi.h`
*   **添加缺失的类型定义**: 添加了 `HEAP_RECORD`, `BEACON_INFO`, `DATA_STORE_OBJECT`, `PBEACON_SYSCALLS` 等结构体定义。
*   **添加缺失的函数原型**: 添加了所有新增 Beacon API 的函数原型声明，如 `BeaconAddValue`, `BeaconInformation`, `BeaconVirtualAlloc` 等。
*   **修正 API 哈希值**: 使用 `CoffeeLdr.c` 中的 `HashString` 算法重新计算了所有新增 API 的哈希值，确保符号解析能够正确匹配。
    *   例如：`COFFAPI_BEACONGETVALUE` 从 `0x9d3f7e2c` 修正为 `0xd9acafea`。

#### 2. `BeaconApi.c`
*   **修正 `BeaconInformation` 实现**: 移除了对不存在的 `version` 成员的赋值操作。
*   **修正 `BeaconSetThreadContext` 签名**: 将第二个参数类型从 `PCONTEXT` 修改为 `const CONTEXT *` 以匹配头文件声明和 Windows API 标准。
*   **修复 `BeaconGetValue` 崩溃问题**: 重写了键值存储系统的实现：
    *   使用更稳定的 djb2 哈希算法（与 CoffeeLdr.c 一致）
    *   添加了 `g_beaconKeys` 数组来存储实际的键字符串
    *   实现了开放寻址法来处理哈希冲突
    *   在查找时使用 `strcmp` 确保找到正确的键
    *   改进了错误检查和边界检查

### 修复细节

#### BeaconGetValue 崩溃修复
原来的实现存在以下问题：
- 哈希算法过于简单，容易产生冲突
- 没有存储实际的键，无法验证键的匹配
- 缺少哈希冲突处理机制

修复后的实现：
```c
// 使用改进的 djb2 哈希算法
unsigned long hash = 5381;
for (const char* p = key; *p; p++) {
    hash = ((hash << 5) + hash) + *p; // hash * 33 + c
}
int index = hash % 256;

// 使用开放寻址法处理冲突
do {
    if (g_beaconKeys[index] == NULL) {
        return NULL; // 键不存在
    }
    if (strcmp(g_beaconKeys[index], key) == 0) {
        return g_beaconValues[index];
    }
    index = (index + 1) % 256;
} while (index != original_index);
```

### 验证
*   编写了 `hash_test_linux.c` 工具验证哈希算法，确认了旧的哈希值是不正确的，并生成了正确的哈希值。
*   确认 `BeaconApiCounter` (52) 与 `BeaconApi` 数组中的条目数量一致。
*   测试了修复后的键值存储功能，确保不会因为哈希冲突导致程序崩溃。

通过以上修改，`beacon.exe` 应该能够成功编译，并且能够正确解析 `__imp_BeaconGetValue` 等符号，同时避免因哈希冲突导致的程序崩溃，从而成功加载并运行 `no-consolation.x64.o`。
