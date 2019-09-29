// A small C program to flip import names in a PE (reverses effect of obfuscation technique
// used by Mugatu challenge binary)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winnt.h>

#include <stdio.h>
#include <stdlib.h>

// From https://stackoverflow.com/a/17387176/756104
void LogError(LPCWSTR msg)
{
    //Get the error message, if any.
    DWORD errorMessageID = GetLastError();
    if (errorMessageID == 0)
        return; //No error message has been recorded

    LPWSTR messageBuffer = nullptr;
    DWORD dwSize = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);
    wprintf(L"%s : GLE %d: %s\n", msg ? msg : L"(no message)", errorMessageID, messageBuffer ? messageBuffer : L"(no error string)");

    if (messageBuffer)
    {
        LocalFree(messageBuffer);
    }
}

PBYTE RVAInFile(const PBYTE pbFileData,
    PIMAGE_SECTION_HEADER pSectionHeader,
    size_t nSections,
    UINT_PTR rva)
{
    UINT_PTR sectionBaseRVA = 0;
    UINT_PTR sectionFileOffset = 0;
    for (int i = 0; i < nSections; ++i)
    {
        if (pSectionHeader[i].VirtualAddress <= rva
            && rva < (pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize))
        {
            sectionBaseRVA = pSectionHeader[i].VirtualAddress;
            sectionFileOffset = pSectionHeader[i].PointerToRawData;
            break;
        }
    }

    if (!sectionFileOffset)
    {
        fprintf(stderr, "Failed to locate file pointer for RVA!\n");
        abort();
    }

    return (pbFileData + sectionFileOffset + (rva - sectionBaseRVA));
}

void FlipImportNames(const LPVOID lpvData, const DWORD dwSize)
{
    const PBYTE pbData = (PBYTE)lpvData;
    const PBYTE pbDend = pbData + dwSize;

    if (dwSize < sizeof(IMAGE_DOS_HEADER))
    {
        wprintf(L"Buffer too small to contain DOS header!\n");
        return;
    }

    PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)lpvData;
    DWORD dwNTOffset = pDOS->e_lfanew;

    if (dwSize < dwNTOffset + sizeof(IMAGE_NT_HEADERS))
    {
        wprintf(L"Buffer too small to contain NT header!\n");
        return;
    }

    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)(pbData + dwNTOffset);
    if (pNT->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
    {
        wprintf(L"Expecting to parse an x86 header!\n");
        return;
    }

    if (pNT->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER)
        || ((uintptr_t)(&pNT->OptionalHeader) + pNT->FileHeader.SizeOfOptionalHeader) >= (uintptr_t)pbDend)
    {
        wprintf(L"Buffer too small to contain entire OptionalHeader!");
        return;
    }

    const size_t nSections = pNT->FileHeader.NumberOfSections;
    const PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(pbData + dwNTOffset + sizeof(IMAGE_NT_HEADERS));

    UINT_PTR importDescriptorRVA = pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    const size_t nImpDesc = pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    PIMAGE_IMPORT_DESCRIPTOR pImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)RVAInFile(pbData, pSectionHeader, nSections, importDescriptorRVA);

    for (int i = 0; i < nImpDesc && pImpDesc[i].Name; ++i)
    {
        const char *modName = (const char *)RVAInFile(pbData, pSectionHeader, nSections, pImpDesc[i].Name);
        wprintf(L"Processing %S\n", modName);

        const PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)RVAInFile(pbData, pSectionHeader, nSections, pImpDesc[i].OriginalFirstThunk);

        // Calculate number of functions imported from this module
        size_t nThunks = 0;
        for (PIMAGE_THUNK_DATA pThunk = pOriginalFirstThunk;
            pThunk->u1.AddressOfData; ++pThunk, ++nThunks);

        if (nThunks < 3)
        {
            continue;
        }

        // Maintain two pointers walking Import Name Table from front to back (pThunk) and
        // back to front (pEnd). March them along, swapping their values as we go.
        for (PIMAGE_THUNK_DATA pThunk = pOriginalFirstThunk, pEnd = pOriginalFirstThunk + nThunks - 1;
            (UINT_PTR)pThunk < (UINT_PTR)(pEnd - 1);
            ++pThunk, --pEnd)
        {
            DWORD tmp = pEnd->u1.AddressOfData;
            pEnd->u1.AddressOfData = pThunk->u1.AddressOfData;
            pThunk->u1.AddressOfData = tmp;
        }
    }

    printf("Done\n");
}

int wmain(int argc, wchar_t **argv)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hFileOut = INVALID_HANDLE_VALUE;
    HANDLE hMappingIn = NULL;
    HANDLE hMappingOut = NULL;
    LPVOID pMapIn = NULL;
    LPVOID pMapOut = NULL;
    DWORD dwFileSize = 0;

    if (argc < 2)
    {
        wprintf(L"Usage: %s <path to PE> \n", argv[0]);
        return 1;
    }

    const wchar_t *fnameIn = argv[1];
    const wchar_t *fnameOut = argv[2];

    hFile = CreateFileW(
        fnameIn,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        LogError(L"Opening File");
        goto done;
    }

    dwFileSize = GetFileSize(hFile, NULL);

    hMappingIn = CreateFileMappingW(
        hFile,
        NULL,
        PAGE_READONLY,
        0,
        0,
        NULL
    );
    if (!hMappingIn)
    {
        LogError(L"Error creating input file mapping");
        goto done;
    }

    pMapIn = MapViewOfFile(hMappingIn, FILE_MAP_READ, 0, 0, 0);
    if (!pMapIn)
    {
        LogError(L"Mapping view of file");
        goto done;
    }

    hFileOut = CreateFileW(
        fnameOut,
        GENERIC_ALL,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFileOut == INVALID_HANDLE_VALUE)
    {
        LogError(L"Error creating output file");
        goto done;
    }

    hMappingOut = CreateFileMappingW(
        hFileOut,
        NULL,
        PAGE_READWRITE,
        0,
        dwFileSize,
        NULL
    );
    if (!hMappingOut)
    {
        LogError(L"Mapping view of output file");
        goto done;
    }

    pMapOut = MapViewOfFile(hMappingOut, FILE_MAP_ALL_ACCESS, 0, 0, 0);

    CopyMemory(pMapOut, pMapIn, dwFileSize);

    FlipImportNames(pMapOut, dwFileSize);

done:

    if (pMapOut)
    {
        UnmapViewOfFile(pMapOut);
    }

    if (hMappingOut)
    {
        CloseHandle(hMappingOut);
    }

    if (hFileOut != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFileOut);
    }

    if (pMapIn)
    {
        UnmapViewOfFile(pMapIn);
    }

    if (hMappingIn)
    {
        CloseHandle(hMappingIn);
    }

    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
    }

    return 0;
}
