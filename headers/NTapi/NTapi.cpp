#include "./NTapi.h"
#include <filesystem>

PEB NTapi::Peb;
TEB NTapi::Teb;
NTapi::__temp_process__ NTapi::temp_process;
bool NTapi::initied = false;
PSYSTEM_PROCESS_INFORMATION NTapi::selected_process_info = new SYSTEM_PROCESS_INFORMATION;

PSYSTEM_PROCESS_INFORMATION NTapi::GetCurrentProcess()
{
   return GetProcessInfo((DWORD)NTapi::Teb.ClientId.UniqueProcess);
}

void NTapi::Init()
{
    if (NTapi::initied)
        return;

    #ifdef _WIN64
        NTapi::Peb = *(PEB*)__readgsqword(0x60);
        NTapi::Teb = *(TEB*)__readgsqword(0x30);
    #elif _WIN32
        NTapi::Peb = *(PEB*)__readfsdword(0x30);
        NTapi::Teb = *(TEB*)__readfsdword(0x18);
    #endif

    NTapi::initied = true;
}

bool NTapi::IsInitied()
{
    return NTapi::initied;
}

BOOL WINAPI NTapi::__window_callback__(HWND hwnd, LPARAM lParam)
{
    NTapi::__window_callback_arg_* a = (NTapi::__window_callback_arg_*)lParam;
    DWORD hwnd_pid = 0;

    GetWindowThreadProcessId(hwnd, &hwnd_pid);
    if (a->pid != hwnd_pid)
        return TRUE;

    a->hwnd = hwnd;

    return FALSE;

}

HWND NTapi::GetWindowProcess(const char* ProcessName)
{
    PSYSTEM_PROCESS_INFORMATION  pri = NTapi::GetProcessInfo(ProcessName);
    if (!pri->UniqueProcessId)
        return NULL;

    return GetWindowProcess((DWORD)pri->UniqueProcessId);
}

HWND NTapi::GetWindowProcess(DWORD pid)
{
    NTapi::__window_callback_arg_ a{ 0,0 };

    a.pid = pid;

    EnumWindows(__window_callback__, (LPARAM)&a);

    return a.hwnd;
}

void NTapi::SetWindowFocus(const char* ProcessName)
{
    return SetWindowFocus((DWORD)NTapi::GetProcessInfo(ProcessName)->UniqueProcessId);
}

void NTapi::SetWindowFocus(DWORD Pid)
{
    if (Pid <= 0)
        return;

    HWND hwnd = NTapi::GetWindowProcess(Pid);
    if (!hwnd)
        return;

    SetFocus(hwnd);
    PostMessage(hwnd, WM_SETFOCUS, 0, 0);
    SendMessage(hwnd, WM_SETFOCUS, 0, 0);
    PostMessage(hwnd, WM_APP, 0, 0);
    SendMessage(hwnd, WM_APP, 0, 0);

}

EnumObj<SYSTEM_HANDLE_TABLE_ENTRY_INFO>* NTapi::GetHandlesProcess(const char* ProcessName)
{
    return GetHandlesProcess((DWORD)NTapi::GetProcessInfo(ProcessName)->UniqueProcessId);
}

EnumObj<SYSTEM_HANDLE_TABLE_ENTRY_INFO>* NTapi::GetHandlesProcess(DWORD Pid)
{
    if (Pid <= 0)
        return nullptr;

    EnumObj<SYSTEM_HANDLE_TABLE_ENTRY_INFO> * handle_ex = nullptr;

    ULONG SysBufLength = 0;
    SYSTEM_HANDLE_INFORMATION* ppi = new SYSTEM_HANDLE_INFORMATION;
   
    if (NT_SUCCESS(NtQuerySystemInformation(SystemHandleInformation, ppi, sizeof(SYSTEM_HANDLE_INFORMATION),
 &SysBufLength)))
    {
        ULONG nOh = ppi->NumberOfHandles;
        delete ppi;
        ppi = (SYSTEM_HANDLE_INFORMATION*)std::calloc(1, SysBufLength);

        if (NT_SUCCESS(NtQuerySystemInformation(SystemHandleInformation, ppi, SysBufLength, nullptr)))
        {

            for (int x = 0; x <= nOh; x++)
            {
                if ((DWORD)ppi->Handles[x].UniqueProcessId == Pid)
                    handle_ex = new  EnumObj<SYSTEM_HANDLE_TABLE_ENTRY_INFO>(SYSTEM_HANDLE_TABLE_ENTRY_INFO{
                    ppi->Handles[x].UniqueProcessId,
                    ppi->Handles[x].CreatorBackTraceIndex,
                    ppi->Handles[x].ObjectTypeIndex,
                    ppi->Handles[x].HandleAttributes,
                    ppi->Handles[x].HandleValue,
                    ppi->Handles[x].Object,
                    ppi->Handles[x].GrantedAccess
                        }, handle_ex);
            }

            EnumObj<SYSTEM_HANDLE_TABLE_ENTRY_INFO>* base_entry = handle_ex;

            while (true)
            {
                if (handle_ex == nullptr)
                    break;

                handle_ex->Base = base_entry;

                handle_ex = handle_ex->Next;

            }

            handle_ex = base_entry;
        }

        free(ppi);
    }
 
    return handle_ex;
}

EnumObj<SYSTEM_HANDLE_TABLE_ENTRY_INFO>* NTapi::GetAllHandles()
{
    EnumObj<SYSTEM_HANDLE_TABLE_ENTRY_INFO> * handle_ex = nullptr;

    ULONG SysBufLength = 0;
    SYSTEM_HANDLE_INFORMATION * ppi = nullptr;

    if (NT_SUCCESS(NtQuerySystemInformation(SystemHandleInformation, ppi, sizeof(SYSTEM_HANDLE_INFORMATION), &SysBufLength)))
    {
        ULONG nOh = ppi->NumberOfHandles;
        delete ppi;
        ppi = (SYSTEM_HANDLE_INFORMATION*)std::calloc(1, SysBufLength);

        if (NT_SUCCESS(NtQuerySystemInformation(SystemHandleInformation, ppi, SysBufLength, nullptr)))
        {

            for (int x = 0; x <= nOh; x++)
                handle_ex = new  EnumObj<SYSTEM_HANDLE_TABLE_ENTRY_INFO>(ppi->Handles[x], handle_ex);

            EnumObj<SYSTEM_HANDLE_TABLE_ENTRY_INFO>* base_entry = handle_ex;

            while (true)
            {
                if (handle_ex == nullptr)
                    break;

                handle_ex->Base = base_entry;

                handle_ex = handle_ex->Next;

            }

            handle_ex = base_entry;
        }

       free(ppi);
    }

    return handle_ex;
}

TEB NTapi::GetCurrentTeb()
{
    #ifdef _WIN64
      return *(TEB*)__readgsqword(0x30);
    #elif _WIN32
    return *(TEB*)__readfsdword(0x18);
    #endif
}


BOOL NTapi::SetPrivilege(HANDLE hToken, LPCSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueA(NULL, lpszPrivilege, &luid))        // receives LUID of privilege
        return FALSE;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    return AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        nullptr,
        (PDWORD)NULL);
}

HANDLE NTapi::OpenProcess(DWORD Pid, ACCESS_MASK Mask)
{
    if (Pid <= 0)
        return NULL;

    HANDLE handle = INVALID_HANDLE_VALUE;

    OBJECT_ATTRIBUTES objectAttributes{};
    NtInitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);
    CLIENT_ID ClientId = { 0 };
    ClientId.UniqueProcess = (HANDLE)Pid;

    NtOpenProcess(&handle, Mask, (POBJECT_ATTRIBUTES)&objectAttributes, &ClientId);

    return handle;
}

HANDLE NTapi::OpenProcess(const char* ProcessName, ACCESS_MASK Mask)
{
    return OpenProcess((DWORD)GetProcessInfo(ProcessName)->UniqueProcessId, Mask);
}

std::string  NTapi::GetProcessPath(std::string ProcessName)
{
    return NTapi::GetProcessPath((DWORD)NTapi::GetProcessInfo(ProcessName)->UniqueProcessId);
}

BYTE NTapi::IsWow64(std::string ProcessName)
{
    return NTapi::IsWow64((DWORD)NTapi::GetProcessInfo(ProcessName)->UniqueProcessId);
}

BYTE NTapi::IsWow64(DWORD ProcessId)
{
    if (ProcessId <= 0)
        return 3;

    BOOL bIsWow64 = FALSE;

    HANDLE hprocess = NTapi::OpenProcess(ProcessId, PROCESS_QUERY_INFORMATION);

    if (IsWow64Process(hprocess, &bIsWow64) == 0)
    {
        NtClose(hprocess);
        return 3;
    }

    NtClose(hprocess);

    return (BYTE)bIsWow64;
}

std::string NTapi::GetProcessPath(DWORD pid)
{
    if (pid <= 0)
        return "";

    HANDLE hauth = NTapi::OpenProcess(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);

    ULONG pathsize = 0;

    NtQueryInformationProcess(hauth, ProcessImageFileNameWin32, NULL,NULL,&pathsize);

    CUNICODE_STRING * pi = (CUNICODE_STRING*)std::calloc(1, pathsize);
   
    NtQueryInformationProcess(hauth, ProcessImageFileNameWin32, pi, pathsize, nullptr);

    NtClose(hauth);

    if (pi->Buffer)
    {
        if(pid == (DWORD)NTapi::Teb.ClientId.UniqueProcess || (pid != (DWORD)NTapi::Teb.ClientId.UniqueProcess && wcscmp(pi->Buffer, NTapi::Peb.ProcessParameters->ImagePathName.Buffer)))
                return UTF16toUTF8(pi->Buffer);
    }

    return "";
}

PSID NTapi::GetCurrentPSID()
{
    DWORD dwSize;

    HANDLE cToken = GetCurrentProcessToken();

    NtQueryInformationToken(cToken, TokenUser, NULL, NULL, &dwSize);
     
    PTOKEN_USER tokensid = (PTOKEN_USER)std::calloc(1, dwSize);

    NtQueryInformationToken(cToken, TokenUser, tokensid, dwSize, &dwSize);

    dwSize = GetLengthSid(tokensid->User.Sid);
    PSID sid = (PSID)std::calloc(1, dwSize);
    NTapi::NtMemCpy((PBYTE)sid, (PBYTE)tokensid->User.Sid, dwSize);

    NtClose(cToken);

    free(tokensid);

    return sid;
}

std::string NTapi::UTF16toUTF8(std::wstring ws)
{
    if (ws == L"")
        return "";

    std::string utf8{};

    const wchar_t * utf16 = ws.c_str();
    const size_t utf16_size = ws.size();

    utf8.resize(utf16_size);

    for (size_t s = 0; s < utf16_size; s++)
        utf8[s] = utf16[s];

    return utf8;
}

LPSTR NTapi::PSIDToStringA(PSID psid)
{
    LPSTR sdistr{};
    ConvertSidToStringSidA(psid, &sdistr);

    return sdistr;
}

LPWSTR NTapi::PSIDToStringW(PSID psid)
{
    LPWSTR sdistr{};
    ConvertSidToStringSidW(psid, &sdistr);

    return sdistr;
}

PUSERA NTapi::GetCurrentUserA()
{
    char  UserName[MAX_USER_NAME_LENGTH];
    char  DomaineName[MAX_USER_NAME_LENGTH];
    SID_NAME_USE  snu;
    DWORD cchName = MAX_PATH;

    LookupAccountSidA(NULL, NTapi::GetCurrentPSID(), UserName, &cchName, DomaineName, &cchName, &snu);

    return new USERA{UserName,DomaineName,snu };
}

PUSERW NTapi::GetCurrentUserW()
{
    wchar_t  UserName[MAX_USER_NAME_LENGTH];
    wchar_t  DomaineName[MAX_USER_NAME_LENGTH];
    SID_NAME_USE  snu;
    DWORD cchName = MAX_PATH;
    LookupAccountSidW(NULL, NTapi::GetCurrentPSID(), UserName,&cchName, DomaineName, &cchName, &snu);

    return new USERW{ UserName,DomaineName,snu };
}

HANDLE NTapi::DublicateHandle(DWORD ProcessId,HANDLE HandleToDuplcate,bool IsInirt, ACCESS_MASK Mask)
{
    HANDLE DublicateHandleReceive = INVALID_HANDLE_VALUE;

    HANDLE HProcessHandle = NTapi::OpenProcess(ProcessId, PROCESS_DUP_HANDLE);

    if(HProcessHandle)
    {
        NtDuplicateObject(HProcessHandle, HandleToDuplcate, NtCurrentProcess(), &DublicateHandleReceive, Mask, NULL, Mask);
        
        NtClose(HProcessHandle);
        
        SetHANDLEProtect(DublicateHandleReceive, false, IsInirt);
       
    }

    return DublicateHandleReceive;

}

HANDLE NTapi::DublicateHandle(const char* ProcessName, HANDLE HandleToDuplcate, bool IsInirt, ACCESS_MASK Mask)
{
    return NTapi::DublicateHandle((DWORD)NTapi::GetProcessInfo(ProcessName)->UniqueProcessId, HandleToDuplcate,IsInirt, Mask);
}

bool  NTapi::ProcessExist(std::string ProcessName)
{
    bool a = false;

    PSYSTEM_PROCESS_INFORMATION ppi = NTapi::GetProcessInfo(ProcessName);

    return !(ppi->UniqueProcessId == INVALID_HANDLE_VALUE);;
}

bool  NTapi::ProcessExist(DWORD Pid)
{
    bool a = false;

    PSYSTEM_PROCESS_INFORMATION ppi = NTapi::GetProcessInfo(Pid);

    return (bool)(ppi->UniqueProcessId!=INVALID_HANDLE_VALUE);
}

DWORD WINAPI NTapi::GetPageAccess(void* base)
{
    MEMORY_BASIC_INFORMATION src_plage_data;
    NtQueryVirtualMemory(NtCurrentProcess(), base, MemoryBasicInformation, &src_plage_data, sizeof(src_plage_data), NULL);

    return src_plage_data.Protect;
}

DWORD WINAPI NTapi::SetPageAccess(void* base, ACCESS_MASK DesiredAccess)
{
    MEMORY_BASIC_INFORMATION src_plage_data;
    DWORD OldProtect;
    NtQueryVirtualMemory(NtCurrentProcess(), base, MemoryBasicInformation, &src_plage_data, sizeof(src_plage_data), NULL);
    NtProtectVirtualMemory(NtCurrentProcess(), &src_plage_data.BaseAddress, &src_plage_data.RegionSize, DesiredAccess, &OldProtect);
    return OldProtect;
}

DWORD WINAPI NTapi::SetPageAccess(HANDLE HandleProcess,void* base, ACCESS_MASK DesiredAccess)
{
    if (HandleProcess == INVALID_HANDLE_VALUE)
        return 0;

    MEMORY_BASIC_INFORMATION src_plage_data;
    DWORD OldProtect;
    NtQueryVirtualMemory(HandleProcess, base, MemoryBasicInformation, &src_plage_data, sizeof(src_plage_data), NULL);
    NtProtectVirtualMemory(HandleProcess, &src_plage_data.BaseAddress, &src_plage_data.RegionSize, DesiredAccess, &OldProtect);
    return OldProtect;
}


void WINAPI NTapi::__enum_process__(std::function<bool(PSYSTEM_PROCESS_INFORMATION)> callback) 
{
    if (temp_process.Base)
        free(temp_process.Base);

    NtQuerySystemInformation(SystemProcessInformation, 0, 0, &temp_process.size);

    temp_process.Entry = (PSYSTEM_PROCESS_INFORMATION)std::calloc(1, temp_process.size);
    temp_process.Base = (PBYTE)temp_process.Entry;

    if (NT_SUCCESS(NtQuerySystemInformation(SystemProcessInformation, temp_process.Entry, temp_process.size, nullptr)))
    {
        while (true)
        {
            if (callback(temp_process.Entry))
                return;

                if (!temp_process.Entry->NextEntryOffset)
                    break;

                temp_process.Entry = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)temp_process.Entry + temp_process.Entry->NextEntryOffset);
        }
    }

    return;
}

[[nodiscard]] EnumObj<PSYSTEM_PROCESS_INFORMATION> * WINAPI NTapi::GetAllProcess()
{
    EnumObj<PSYSTEM_PROCESS_INFORMATION> * AllProcessesInfo(nullptr);

    __enum_process__([&](PSYSTEM_PROCESS_INFORMATION _ppi_) -> bool
        {
            AllProcessesInfo = new EnumObj<PSYSTEM_PROCESS_INFORMATION>(_ppi_, AllProcessesInfo);
            return false;
        });

    EnumObj<PSYSTEM_PROCESS_INFORMATION> * base_entry = AllProcessesInfo;

    while (true)
    {
        if (AllProcessesInfo == nullptr)
            break;

        AllProcessesInfo->Base = base_entry;

        AllProcessesInfo = AllProcessesInfo->Next;

    }

    AllProcessesInfo = base_entry;

    return AllProcessesInfo;
}


[[nodiscard]] PSYSTEM_PROCESS_INFORMATION WINAPI NTapi::GetProcessInfo(std::string appname)
{
    selected_process_info->UniqueProcessId = 0;
    std::wstring n(appname.begin(), appname.end());

    __enum_process__([&](PSYSTEM_PROCESS_INFORMATION _ppi_) -> bool
        {
            if (!_ppi_->ImageName.Buffer)
                return false;

            if (!wcscmp(_ppi_->ImageName.Buffer, n.c_str()))
            {
                selected_process_info = _ppi_;
                return true;
            }
            return false;
        });

    return selected_process_info;
};

[[nodiscard]] PSYSTEM_PROCESS_INFORMATION WINAPI NTapi::GetProcessInfo(DWORD ProcessPid)
{
    selected_process_info->UniqueProcessId = INVALID_HANDLE_VALUE;

    __enum_process__([&](PSYSTEM_PROCESS_INFORMATION _ppi_) -> bool
        {
            if ((DWORD)_ppi_->UniqueProcessId == ProcessPid)
            {
                selected_process_info = _ppi_;
                return true;
            }
            return false;
        });

    return selected_process_info;
}

[[nodiscard]] EnumObj<PSYSTEM_PROCESS_INFORMATION> * WINAPI NTapi::GetAllProcessInfo(std::string ProcessName)
{
    EnumObj<PSYSTEM_PROCESS_INFORMATION> * AllProcessesInfo = nullptr;
    std::wstring n(ProcessName.begin(), ProcessName.end());
    __enum_process__([&](PSYSTEM_PROCESS_INFORMATION _ppi_) -> bool
        {
            if (!_ppi_->ImageName.Buffer)
                return false;

            if (!wcscmp(_ppi_->ImageName.Buffer, n.c_str()))
                AllProcessesInfo = new EnumObj<PSYSTEM_PROCESS_INFORMATION>(_ppi_, AllProcessesInfo);
            return false;
        });


    EnumObj<PSYSTEM_PROCESS_INFORMATION> * base_entry = AllProcessesInfo;

    while (true)
    {
        if (AllProcessesInfo == nullptr)
            break;

        AllProcessesInfo->Base = base_entry;

        AllProcessesInfo = AllProcessesInfo->Next;

    }

    AllProcessesInfo = base_entry;

    return AllProcessesInfo;
}

[[nodiscard]] DEFAULT_SIZE WINAPI  NTapi::GetModuleAddress(std::string ModuleName)
{
    std::wstring n(ModuleName.begin(), ModuleName.end());
    LIST_ENTRY* current = Peb.Ldr->InMemoryOrderModuleList.Flink->Flink;
    do
    {
        PLDR_DATA_TABLE_ENTRY pdte = ((PLDR_DATA_TABLE_ENTRY)(current - 1));    

        if(pdte->BaseDllName.Buffer)

        if (!wcscmp(pdte->BaseDllName.Buffer, n.c_str()))
            return (DEFAULT_SIZE)pdte->DllBase;

        current = current->Flink;

    } while (current->Flink != Peb.Ldr->InMemoryOrderModuleList.Flink);

    return 0;
}


DEFAULT_SIZE WINAPI NTapi::GetFuncAddress(DEFAULT_SIZE module, const char* function_name)
{
    if (function_name == NULL || !module)
         return 0;

    PIMAGE_EXPORT_DIRECTORY ped = (PIMAGE_EXPORT_DIRECTORY)(module + (((PIMAGE_NT_HEADERS)(module + ((PIMAGE_DOS_HEADER)module)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
    DWORD* AddressOfNames = (DWORD*)(module + ped->AddressOfNames);
    DWORD* AddressOfFunctions = (DWORD*)(module + ped->AddressOfFunctions);
    WORD* AddressOfNameOrdinals = (WORD*)(module + ped->AddressOfNameOrdinals);

    for (int i = 0; i < ped->NumberOfNames; i++)
    {
        if (!strcmp(function_name, (const char*)(module + AddressOfNames[i])))
            return  (DEFAULT_SIZE)(module + AddressOfFunctions[AddressOfNameOrdinals[i]]);
    }

    return (DEFAULT_SIZE)0;
}

[[nodiscard]] EnumObj<MODULE_ENTRY> * WINAPI NTapi::GetModules()
{
    LIST_ENTRY * current = Peb.Ldr->InMemoryOrderModuleList.Flink;

    EnumObj<MODULE_ENTRY> * ModuleEntry = nullptr;

    do
    {
        PLDR_DATA_TABLE_ENTRY pdte = ((PLDR_DATA_TABLE_ENTRY)(current - 1));

        ModuleEntry = new EnumObj<MODULE_ENTRY>(MODULE_ENTRY{std::wstring(pdte->BaseDllName.Buffer),std::wstring(pdte->FullDllName.Buffer),(PVOID)pdte->DllBase}, ModuleEntry);

        current = current->Flink;

    } while (current->Flink != Peb.Ldr->InMemoryOrderModuleList.Flink);

    EnumObj<MODULE_ENTRY>* base_entry = ModuleEntry;

    while (true)
    {
        if (ModuleEntry == nullptr)
            break;

        ModuleEntry->Base = base_entry;

        ModuleEntry = ModuleEntry->Next;

    }

    ModuleEntry = base_entry;

    return ModuleEntry;
}

EnumObj<MODULE_ENTRY> * WINAPI NTapi::GetImportModules(DEFAULT_SIZE ModuleAddress)
{
    if (ModuleAddress <= 0)
        return nullptr;

    EnumObj<MODULE_ENTRY>* ModuleEntry = nullptr;

    PIMAGE_IMPORT_DESCRIPTOR ped = (PIMAGE_IMPORT_DESCRIPTOR)(ModuleAddress + (((PIMAGE_NT_HEADERS)(ModuleAddress + ((PIMAGE_DOS_HEADER)ModuleAddress)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));

    while (ped->Name != NULL)
    {
        std::string szName = std::string((PCHAR)((DWORD_PTR)ModuleAddress + ped->Name));

        ModuleEntry = new EnumObj<MODULE_ENTRY>(MODULE_ENTRY{std::wstring(szName.begin(),szName.end()),{}, (PVOID)NTapi::GetModuleAddress(szName) }, ModuleEntry);

        ped++;
    }

    EnumObj<MODULE_ENTRY>* base_entry = ModuleEntry;

    while (true)
    {
        if (ModuleEntry == nullptr)
            break;

        ModuleEntry->Base = base_entry;

        ModuleEntry = ModuleEntry->Next;

    }

    ModuleEntry = base_entry;

    return ModuleEntry;

}

EnumObj<MODULE_ENTRY>* WINAPI NTapi::GetImportModulesEx(std::string ProcessName, DEFAULT_SIZE ModuleAddress)
{
    return NTapi::GetImportModulesEx((DWORD)NTapi::GetProcessInfo(ProcessName)->UniqueProcessId, ModuleAddress);
}
EnumObj<MODULE_ENTRY>* WINAPI NTapi::GetImportModulesEx(DWORD ProcessId, DEFAULT_SIZE ModuleAddress)
{
    if (ProcessId <= 0)
        return nullptr;

    HANDLE h_process = NTapi::OpenProcess(ProcessId, PROCESS_VM_READ);

    EnumObj<MODULE_ENTRY>* ModuleEntry = nullptr;

    IMAGE_DOS_HEADER dosHeader{};

    if (NT_SUCCESS(NtReadVirtualMemory(h_process, (PIMAGE_DOS_HEADER)ModuleAddress, &dosHeader, sizeof(IMAGE_DOS_HEADER), nullptr)))
    {
        IMAGE_NT_HEADERS ntHeaders{};

        NtReadVirtualMemory(h_process, (PIMAGE_DOS_HEADER)(ModuleAddress + dosHeader.e_lfanew), &ntHeaders, sizeof(IMAGE_NT_HEADERS), nullptr);


        DWORD importDirectoryVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;


        IMAGE_IMPORT_DESCRIPTOR importDescriptor{};

        NtReadVirtualMemory(h_process, (PIMAGE_IMPORT_DESCRIPTOR)(ModuleAddress + importDirectoryVA), &importDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), nullptr);

        int i = 1;

        while (importDescriptor.Name != NULL)
        {
            std::string szName = NTapi::ReadUTF8EX(h_process, (PCHAR((DWORD_PTR)ModuleAddress + importDescriptor.Name)));

            ModuleEntry = new EnumObj<MODULE_ENTRY>(MODULE_ENTRY{ std::wstring(szName.begin(),szName.end()),NULL, NULL }, ModuleEntry);

            NtReadVirtualMemory(h_process, ((PIMAGE_IMPORT_DESCRIPTOR)(ModuleAddress + importDirectoryVA)) + i, &importDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), nullptr);
            i++;

        }

        EnumObj<MODULE_ENTRY>* base_entry = ModuleEntry;

        while (true)
        {
            if (ModuleEntry == nullptr)
                break;

            ModuleEntry->Base = base_entry;

            ModuleEntry = ModuleEntry->Next;

        }

        ModuleEntry = base_entry;
    }

    if(h_process != INVALID_HANDLE_VALUE)
         NtClose(h_process);

    return ModuleEntry;
}

PVOID WINAPI NTapi::ModuleExist(DEFAULT_SIZE base)
{
    LIST_ENTRY* current = Peb.Ldr->InMemoryOrderModuleList.Flink->Flink;
    do
    {
        PLDR_DATA_TABLE_ENTRY pdte = ((PLDR_DATA_TABLE_ENTRY)(current - 1));
        if ((DEFAULT_SIZE)pdte->DllBase == base)
            return pdte->DllBase;

        current = current->Flink;

    } while (current->Flink != &Peb.Ldr->InMemoryOrderModuleList);

    return nullptr;
}

PVOID WINAPI NTapi::ModuleExistEx(EnumObj<MODULE_ENTRY>* Modules, std::string  ModuleName)
{
    std::wstring ws(ModuleName.begin(), ModuleName.end());

    do
    {
        if(!wcscmp(Modules->element.Name.c_str(), ws.c_str()))
            return Modules->element.Address;

    } while ((Modules = Modules->Next)->Next);
            return nullptr;
}

std::wstring WINAPI NTapi::ReadUTF16EX(HANDLE hauth, PWSTR  address, size_t max_size )
{
    std::wstring ws = L"";
    if (!address)
        return ws;

    for (int x = 0;; x++)
    {
        wchar_t c;

        NtReadVirtualMemory(hauth, (address + x), &c, sizeof(wchar_t), nullptr);
        ws += c;
        if (c == '\0' || (x >= max_size))
            break;
    }
    return ws;
}


std::string WINAPI NTapi::ReadUTF8EX(HANDLE hauth, PSTR  address, size_t max_size )
{
    std::string s = "";
    if (!address)
        return s;

    for (int x = 0;; x++)
    {
        char c;

        NtReadVirtualMemory(hauth, (address + x), &c, sizeof(char), nullptr);
        s += c;
        if (c == '\0' || (x >= max_size))
            break;
    }
    return s;
}

[[nodiscard]] EnumObj<MODULE_ENTRY>* WINAPI NTapi::__get_modules_ex__(DWORD pid)
{
    if (pid <= 0)
        return nullptr;

    EnumObj<MODULE_ENTRY>*  ModuleEntry = nullptr;

    HANDLE hauth = NTapi::OpenProcess(pid,PROCESS_QUERY_INFORMATION  | PROCESS_VM_READ);
   
    PROCESS_BASIC_INFORMATION pi{};

    if (NT_SUCCESS(NtQueryInformationProcess(hauth, ProcessBasicInformation, &pi, sizeof(PROCESS_BASIC_INFORMATION), nullptr)))
    {
        PEB Peb{};

        if (NT_SUCCESS(NtReadVirtualMemory(hauth, pi.PebBaseAddress, &Peb, sizeof(PEB), nullptr)))
        {

            PEB_LDR_DATA  ldr{};
            if (NT_SUCCESS(NtReadVirtualMemory(hauth, Peb.Ldr, &ldr, sizeof(PEB_LDR_DATA), nullptr)))
            {
                LIST_ENTRY ListEntry{}, HeadEntry{};

                NtReadVirtualMemory(hauth, ldr.InMemoryOrderModuleList.Blink, &ListEntry, sizeof(LIST_ENTRY), nullptr);
                NtReadVirtualMemory(hauth, ldr.InMemoryOrderModuleList.Flink, &HeadEntry, sizeof(LIST_ENTRY), nullptr);

                do
                {
                    NtReadVirtualMemory(hauth, ListEntry.Blink, &ListEntry, sizeof(LIST_ENTRY), nullptr);
                    LDR_DATA_TABLE_ENTRY pdte;
                    NtReadVirtualMemory(hauth, (ListEntry.Flink - 1), &pdte, sizeof(LDR_DATA_TABLE_ENTRY), nullptr);

                    ModuleEntry = new EnumObj<MODULE_ENTRY>(MODULE_ENTRY{ ReadUTF16EX(hauth, pdte.BaseDllName.Buffer),ReadUTF16EX(hauth, pdte.FullDllName.Buffer),(PVOID)pdte.DllBase }, ModuleEntry);

                } while (memcmp(&ListEntry, &HeadEntry, sizeof(LIST_ENTRY)));

                NtClose(hauth);

                EnumObj<MODULE_ENTRY>* base_entry = ModuleEntry;

                while (true)
                {
                    if (ModuleEntry == nullptr)
                        break;

                    ModuleEntry->Base = base_entry;

                    ModuleEntry = ModuleEntry->Next;

                }

                ModuleEntry = base_entry;
            }
        }
    }

    return ModuleEntry;
}

[[nodiscard]] EnumObj<MODULE_ENTRY>* WINAPI NTapi::GetModulesEx(const char* AppName)
{
    return __get_modules_ex__((DWORD)GetProcessInfo(AppName)->UniqueProcessId);
}

[[nodiscard]] EnumObj<MODULE_ENTRY>* WINAPI NTapi::GetModulesEx(DWORD pid)
{

    return __get_modules_ex__(pid);
}


void NTapi::NtMemCpy(PVOID dst, PVOID src, size_t size)
{

    if (!src || !dst)
        return;

    DWORD srcOldProtect = GetPageAccess(src); 
    DWORD dstOldProtect = GetPageAccess(dst);  
    
    if ((srcOldProtect >> 4) != 0)
        srcOldProtect = SetPageAccess(src, PAGE_EXECUTE_READWRITE);
    else
        srcOldProtect = SetPageAccess(src, PAGE_READWRITE);

    if ((dstOldProtect >> 4) != 0)
        dstOldProtect = SetPageAccess(dst, PAGE_EXECUTE_READWRITE);
    else
        dstOldProtect = SetPageAccess(dst, PAGE_READWRITE);
    

    for (size_t b = 0; b < size; b++)
        *((BYTE*)dst + b) = *((BYTE*)src + b);

    SetPageAccess(src, srcOldProtect);
    SetPageAccess(dst, dstOldProtect);

}


void NTapi::NtZeroMemory(BYTE * src, size_t size,BYTE c)
{
    if (!src || size <= 0)
        return;

    DWORD OldProtect = GetPageAccess(src);  
    
    if ((OldProtect  >> 4) != 0)
        OldProtect = SetPageAccess(src, PAGE_EXECUTE_READWRITE);
    else
        OldProtect = SetPageAccess(src, PAGE_READWRITE);

    for (size_t b = 0; b < size; b++)
        *(src + b) = c;

    SetPageAccess(src, OldProtect);
}

bool NTapi::NtMemCcmp(BYTE* src, BYTE c, size_t size)  // Mem Cmp Same
{
    for (size_t x = 0; x < size; x++)
    {
        if (src[x] != c)
            return false;
    }

    return true;
}

PBYTE NTapi::AllocEx(std::string ProcessName, size_t size, ACCESS_MASK flProtect)
{
    return NTapi::AllocEx((DWORD)NTapi::GetProcessInfo(ProcessName)->UniqueProcessId, size, flProtect);
}

PBYTE NTapi::AllocEx(DWORD Pid, size_t size, ACCESS_MASK flProtect)
{
    PBYTE BaseAddress = nullptr;

    HANDLE _proces_handle = INVALID_HANDLE_VALUE;                                                     

    if (Pid == -1)
        _proces_handle = NtCurrentProcess();
    else if (Pid >= 0)
    {
        _proces_handle = NTapi::OpenProcess(Pid, PROCESS_VM_OPERATION);

        if (_proces_handle == INVALID_HANDLE_VALUE)
            return nullptr;
    }

    NtAllocateVirtualMemory(_proces_handle, (PVOID*)&BaseAddress, 0, (PSIZE_T)&size, MEM_RESERVE | MEM_COMMIT, flProtect);

    return BaseAddress;
}

NTSTATUS NTapi::SetHANDLEProtect(HANDLE Handle,  bool LockedClose, bool IsInirt)
{
    OBJECT_HANDLE_FLAG_INFORMATION  handle_flag{ IsInirt,LockedClose };
    return NtSetInformationObject(Handle, ObjectHandleFlagInformation, &handle_flag, sizeof(OBJECT_HANDLE_FLAG_INFORMATION));
}


std::string NTapi::RandomWordA(WORD Length)
{
    LPCSTR abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopkrstuvwxyz1234567890";
    std::string  RandomWord;
    RandomWord.reserve(Length);
    srand(time(NULL));
    WORD Magic = (rand() % 6);
    srand(time(NULL));
    for (WORD x = 0; x < Length; x++)
    {
        WORD m = ((rand() + Magic) % 63);
        RandomWord += abc[m];
    }

    return RandomWord;
}

std::wstring NTapi::RandomWordW(WORD Length)
{
    LPCWSTR abc = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopkrstuvwxyz1234567890";
    std::wstring  RandomWord;
    RandomWord.reserve(Length);
    srand(time(NULL));
    WORD magic = (rand() % 6);

    for (WORD x = 0; x < Length; x++)
    {
        WORD m = ((rand() + magic) % 62);
        RandomWord += abc[m];
    }

    return RandomWord;
}

bool NTapi::FileExistA(std::string PathFile)
{
    return std::ifstream(PathFile).is_open();
}

bool NTapi::FileExistW(std::string PathFile)
{
    return std::ifstream(PathFile).is_open();
}

bool NTapi::CopyFileA(std::string dst, std::string src)
{
    return std::filesystem::copy_file(src, dst);
}

bool NTapi::CopyFileW(std::wstring dst, std::wstring src)
{
    return std::filesystem::copy_file(src, dst);
}

std::string NTapi::FileExtensionA(std::string path)
{
    return std::filesystem::path(path).extension().string();
}

std::string NTapi::GetFileNamefromPathA(std::string path)
{
    return std::filesystem::path(path).filename().string();
}

std::wstring NTapi::GetFileNamefromPathW(std::wstring path)
{
    return std::filesystem::path(path).filename().wstring();
}

std::string NTapi::GetDirPathFromPathA(std::string path)
{
    return std::filesystem::path(path).parent_path().string();
}

std::wstring NTapi::GetDirPathFromPathW(std::wstring path)
{
    return std::filesystem::path(path).parent_path().wstring();
}

std::wstring NTapi::FileExtensionW(std::wstring path)
{
    return std::filesystem::path(path).extension().wstring();
}

void NTapi::RemoveFromPEBEx(const char* ProcessName, std::string DllName)
{
    return  RemoveFromPEBEx((DWORD)NTapi::GetProcessInfo(ProcessName)->UniqueProcessId, DllName);
}

void NTapi::RemoveFromPEBEx(DWORD pid, std::string DllName)
{ 
    if (pid <= 0)
        return;

    std::wstring wdll_path(DllName.begin(), DllName.end());

    HANDLE hauth = NTapi::OpenProcess(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
    PROCESS_BASIC_INFORMATION pi;
    NtQueryInformationProcess(hauth, ProcessBasicInformation, &pi, sizeof(PROCESS_BASIC_INFORMATION), nullptr);
    PEB Peb = { 0 };
    NtReadVirtualMemory(hauth, pi.PebBaseAddress, &Peb, sizeof(PEB), nullptr);
    PEB_LDR_DATA  ldr;
    NtReadVirtualMemory(hauth, Peb.Ldr, &ldr, sizeof(PEB_LDR_DATA), nullptr);
    LIST_ENTRY ListEntry, HeadEntry;

    NtReadVirtualMemory(hauth, ldr.InMemoryOrderModuleList.Blink, &ListEntry, sizeof(LIST_ENTRY), nullptr);
    NtReadVirtualMemory(hauth, ldr.InMemoryOrderModuleList.Flink, &HeadEntry, sizeof(LIST_ENTRY), nullptr);

    do
    {
        NtReadVirtualMemory(hauth, ListEntry.Blink, &ListEntry, sizeof(LIST_ENTRY), nullptr);
        LDR_DATA_TABLE_ENTRY pdte;
        NtReadVirtualMemory(hauth, (ListEntry.Flink - 1), &pdte, sizeof(LDR_DATA_TABLE_ENTRY), nullptr);

        if (pdte.BaseDllName.Buffer)
        {
            if (!wcscmp(ReadUTF16EX(hauth, pdte.BaseDllName.Buffer).c_str(), wdll_path.c_str()))
            {
                LDR_DATA_TABLE_ENTRY fake_blink_flink_list_entry;
                LDR_DATA_TABLE_ENTRY fake_flink_blink_list_entry;
                
                NtReadVirtualMemory(hauth, (pdte.InMemoryOrderLinks.Blink-1), &fake_blink_flink_list_entry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr);
                NtReadVirtualMemory(hauth, (pdte.InMemoryOrderLinks.Flink - 1), &fake_flink_blink_list_entry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr);

                fake_blink_flink_list_entry.InMemoryOrderLinks.Flink = pdte.InMemoryOrderLinks.Flink;
                fake_flink_blink_list_entry.InMemoryOrderLinks.Blink = pdte.InMemoryOrderLinks.Blink;

                fake_blink_flink_list_entry.InLoadOrderLinks.Flink = pdte.InLoadOrderLinks.Flink;
                fake_flink_blink_list_entry.InLoadOrderLinks.Blink = pdte.InLoadOrderLinks.Blink;

                fake_blink_flink_list_entry.InProgressLinks.Flink = pdte.InProgressLinks.Flink;
                fake_flink_blink_list_entry.InProgressLinks.Blink = pdte.InProgressLinks.Blink;

                fake_blink_flink_list_entry.InInitializationOrderLinks.Flink = pdte.InInitializationOrderLinks.Flink;
                fake_flink_blink_list_entry.InInitializationOrderLinks.Blink = pdte.InInitializationOrderLinks.Blink;

                NtWriteVirtualMemory(hauth, (pdte.InMemoryOrderLinks.Blink - 1), (PVOID)&fake_blink_flink_list_entry, sizeof(fake_blink_flink_list_entry), nullptr);
                NtWriteVirtualMemory(hauth, (pdte.InMemoryOrderLinks.Flink - 1), (PVOID)&fake_flink_blink_list_entry, sizeof(fake_flink_blink_list_entry), nullptr);

                break;
            }
        }
       
    } while (memcmp(&ListEntry, &HeadEntry, sizeof(LIST_ENTRY)));

    NtClose(hauth);

    return;
}

PVOID NTapi::SearchCodeCave(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, size_t NeedSize)
{
    MEMORY_BASIC_INFORMATION src_plage_data{};

    LPVOID BaseMemoryAddress=nullptr;

    while (!NtQueryVirtualMemory(ProcessHandle, BaseMemoryAddress, MemoryBasicInformation, &src_plage_data, sizeof(src_plage_data), NULL))
    {
        if (src_plage_data.Protect >= DesiredAccess && src_plage_data.RegionSize <= MAX_SCAN_MEMORY_REGION_SIZE)
        {
            BYTE * MemData = new BYTE[src_plage_data.RegionSize];
            if (!NtReadVirtualMemory(ProcessHandle, src_plage_data.BaseAddress, MemData, src_plage_data.RegionSize, nullptr))
            {
                for (int i = 0; i < src_plage_data.RegionSize; i++)
                {
                    if (NTapi::NtMemCcmp(MemData,0x00, NeedSize))
                    {
                        delete[] MemData;
                        return  (PBYTE)src_plage_data.BaseAddress + i;
                    }else
                      i += (NeedSize - 1);
                }
            } 

            delete[] MemData;
        }

        BaseMemoryAddress = (PVOID)((PBYTE)src_plage_data.BaseAddress + src_plage_data.RegionSize);
    }
   
    return nullptr;
}


CUNICODE_STRING * NTapi::GetHandleType(HANDLE handle)
{
    ULONG NeedSize = 0;
    
    NtQueryObject((HANDLE)handle, ObjectTypeInformation, NULL, NULL, &NeedSize);

    if (NeedSize > 0)
    {
        PPUBLIC_OBJECT_TYPE_INFORMATION poti = (PPUBLIC_OBJECT_TYPE_INFORMATION)std::calloc(1, NeedSize);
        if (NT_SUCCESS(NtQueryObject((HANDLE)handle, ObjectTypeInformation, poti, NeedSize, &NeedSize)))
        {
            if (poti->TypeName.Buffer)
            {
                PCUNICODE_STRING pcs = new CUNICODE_STRING;
                pcs->Length = poti->TypeName.Length;
                pcs->MaximumLength = poti->TypeName.MaximumLength;
                pcs->Buffer = new wchar_t[poti->TypeName.Length];
                wcscpy(pcs->Buffer, poti->TypeName.Buffer);
                free(poti);
                return pcs;

            }

            free(poti);
        }
        else
            free(poti);
    }
  
    return nullptr;
}