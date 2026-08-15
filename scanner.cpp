#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

void ScanMemory(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    LPCVOID pAddress = sysInfo.lpMinimumApplicationAddress;
    LPCVOID pMaxAddress = sysInfo.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION memInfo;
    std::vector<BYTE> buffer;
    
    int currentAmmo = 44;
    int reserveAmmo = 346;

    size_t matchCount = 0;

    std::cout << "Scanning memory for " << currentAmmo << " and " << reserveAmmo << " nearby..." << std::endl;

    while (pAddress < pMaxAddress) {
        if (VirtualQueryEx(hProcess, pAddress, &memInfo, sizeof(memInfo)) == sizeof(memInfo)) {
            if (memInfo.State == MEM_COMMIT && 
                (memInfo.Protect == PAGE_READWRITE || memInfo.Protect == PAGE_EXECUTE_READWRITE)) {
                
                buffer.resize(memInfo.RegionSize);
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, pAddress, buffer.data(), memInfo.RegionSize, &bytesRead)) {
                    // Search through the buffer
                    for (size_t i = 0; i < bytesRead - sizeof(int); i += 4) { // Assuming 4-byte alignment
                        int val = *reinterpret_cast<int*>(&buffer[i]);
                        if (val == currentAmmo) {
                            // Look for reserve ammo within +/- 64 bytes
                            for (intptr_t j = -64; j <= 64; j += 4) {
                                if (j == 0) continue;
                                if ((i + j) >= 0 && (i + j) <= bytesRead - sizeof(int)) {
                                    int nearVal = *reinterpret_cast<int*>(&buffer[i + j]);
                                    if (nearVal == reserveAmmo) {
                                        std::cout << "Match found! Current Ammo at: 0x" 
                                                  << std::hex << (uintptr_t)pAddress + i 
                                                  << " (Reserve at offset " << std::dec << j << ")" << std::endl;
                                        matchCount++;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            pAddress = (LPBYTE)memInfo.BaseAddress + memInfo.RegionSize;
        } else {
            break;
        }
    }

    std::cout << "Total matches found: " << std::dec << matchCount << std::endl;
    CloseHandle(hProcess);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: scanner.exe <pid>" << std::endl;
        return 1;
    }
    DWORD pid = std::stoul(argv[1]);
    ScanMemory(pid);
    return 0;
}
