#include <array>
#include <algorithm>
#include <functional>
#include <format>
#include <iostream>
#include <optional>

#include <cstdio>
#include <cinttypes>

#include <windows.h>
#include <tlhelp32.h>

#include <Zydis/Zydis.h>

#define CALLBACK_ASSERT(cond)          \
  if (!(cond))                         \
    return DisassembleStatus::kFailed;

enum class DisassembleStatus
{
    kContinue,
    kFailed,
    kSuccess,
    kFollow,
    kZydisError
};

using DisassembleCallbackT = DisassembleStatus(ZydisDecodedInstruction &, ZydisDecodedOperand *, uint64_t &);

ZydisDecoder decoder;
ZydisFormatter formatter;

void zydis_init()
{
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_IMM_SIGNEDNESS, ZYDIS_SIGNEDNESS_AUTO);
}

void zydis_print_instrn(ZydisDecodedInstruction const &instrn, ZydisDecodedOperand const *operands, uint64_t address) noexcept
{
    printf("  %016" PRIX64 "  ", address);
    char buffer[256];
    ZydisFormatterFormatInstruction(&formatter, &instrn, operands, instrn.operand_count_visible, buffer, sizeof(buffer), address, ZYAN_NULL);
    puts(buffer);
}

DisassembleStatus zydis_disassemble(uint64_t address, const std::function<DisassembleCallbackT> &callback) noexcept
{
    CALLBACK_ASSERT(address != 0);

    ZydisDecodedInstruction instrn{};
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, reinterpret_cast<void const *>(address), 32, &instrn, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY))) {
        if (auto status = callback(instrn, operands, address); status != DisassembleStatus::kContinue) {
            if (status == DisassembleStatus::kFollow) {
                CALLBACK_ASSERT(ZydisCalcAbsoluteAddress(&instrn, operands, address, &address));
                continue;
            }
            return status;
        }
        address += instrn.length;
    }

    return DisassembleStatus::kZydisError;
}

struct desktop_manager_proto
{
    void *unknown0[3];
    uint8_t unknown1[2];
    bool rounded_shadow_enabled;
    bool enable_sharp_corners;
    bool enable_rounded_corners;
};

static_assert(offsetof(desktop_manager_proto, enable_rounded_corners) == 0x1C,
              "alignment issues (wrong arch)");

std::optional<std::ptrdiff_t> locate_udwm_desktop_manager() noexcept
{
    auto const udwm_dll = LoadLibraryExA("udwm.dll", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!udwm_dll)
        return {};

    auto const dwm_client_startup = reinterpret_cast<uint64_t>(GetProcAddress(udwm_dll, MAKEINTRESOURCE(101)));
    if (!dwm_client_startup)
        return {};

    struct Context {
        uint64_t dm_instance;
        bool found_dm_create;
    };

    Context ctx{};
    auto callback = [&ctx](auto const &instrn, auto const operands, auto &address) noexcept -> DisassembleStatus {
        CALLBACK_ASSERT(instrn.mnemonic != ZYDIS_MNEMONIC_RET);
        zydis_print_instrn(instrn, operands, address);

        if (!ctx.found_dm_create && instrn.mnemonic == ZYDIS_MNEMONIC_CALL) {
            ctx.found_dm_create = true;
            return DisassembleStatus::kFollow;
        }

        auto const &lhs = operands[0];
        if (instrn.mnemonic == ZYDIS_MNEMONIC_MOV && lhs.type == ZYDIS_OPERAND_TYPE_MEMORY && lhs.mem.segment == ZYDIS_REGISTER_DS) {
            ZydisCalcAbsoluteAddress(&instrn, operands, address, &ctx.dm_instance);
            return DisassembleStatus::kSuccess;
        }

        return DisassembleStatus::kContinue;
    };

    if (zydis_disassemble(dwm_client_startup, callback) != DisassembleStatus::kSuccess || !ctx.dm_instance)
        return {};

    return { ctx.dm_instance - reinterpret_cast<uint64_t *>(udwm_dll) };
}

std::optional<uint64_t> find_module_base(DWORD pid, std::string_view module_name) noexcept
{
    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot != INVALID_HANDLE_VALUE) {
        auto entry = MODULEENTRY32{ .dwSize = sizeof(MODULEENTRY32) };

        if (Module32First(snapshot, &entry)) {
            do {
                if (module_name == entry.szModule) {
                    CloseHandle(snapshot);
                    return { reinterpret_cast<uint64_t>(entry.modBaseAddr) };
                }
            } while (Module32Next(snapshot, &entry));
        }
    }
    CloseHandle(snapshot);
    return {};
}

bool enable_privilege(LPCTSTR name) noexcept
{
    TOKEN_PRIVILEGES privilege{};
    privilege.PrivilegeCount = 1;
    privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValue(nullptr, name, &privilege.Privileges[0].Luid))
        return false;

    HANDLE token{};
    if (!OpenProcessToken(reinterpret_cast<HANDLE>(-1), TOKEN_ADJUST_PRIVILEGES, &token))
        return false;

    if (!AdjustTokenPrivileges(token, FALSE, &privilege, sizeof privilege, nullptr, nullptr)) {
        CloseHandle(token);
        return false;
    }

    CloseHandle(token);
    return true;
}

int main() try
{
    if (!enable_privilege(SE_DEBUG_NAME))
        throw std::runtime_error(std::format("Failed enable {}!", SE_DEBUG_NAME));

    auto const dwm_hwnd = FindWindowA("Dwm", nullptr);
    DWORD dwm_pid = 0u;
    if (!dwm_hwnd || !GetWindowThreadProcessId(dwm_hwnd, &dwm_pid))
        throw std::runtime_error("Failed to find dwm process.\n");

    std::cout << std::format("Found dwm.exe process [window handle: {}, pid: {}].\n", static_cast<void *>(dwm_hwnd), dwm_pid);

    auto const dwm_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwm_pid);
    if (!dwm_process)
        throw std::runtime_error(std::format("Failed to open dwm.exe process, status: {:#x}!", GetLastError()));

    std::cout << std::format("Opened process handle {:#x} to dwm.exe.\nLocating CDesktopManager *g_pdmInstance:\n", reinterpret_cast<uint64_t>(dwm_process));

    zydis_init();

    auto const desktop_manager_rva = locate_udwm_desktop_manager();
    if (!desktop_manager_rva)
        throw std::runtime_error("Failed to locate g_pdmInstance RVA inside udwm.dll.");

    std::cout << std::format("Found g_pdmInstance at RVA {:#x}.\n", desktop_manager_rva.value());

    auto const dwm_base = find_module_base(dwm_pid, std::string_view{"udwm.dll"});
    if (!dwm_base)
        throw std::runtime_error("Failed to find udwm.dll module inside dwm.exe process!");

    std::cout << std::format("Found udwm.dll mapped at {:#x}.\n", dwm_base.value());

    auto desktop_manager_ptr = reinterpret_cast<void const *>(dwm_base.value() + desktop_manager_rva.value());
    uint64_t desktop_manager_inst{};
    SIZE_T out_size{};
    if (!ReadProcessMemory(dwm_process, desktop_manager_ptr, &desktop_manager_inst, sizeof(void *), &out_size) || !desktop_manager_inst)
        throw std::runtime_error(std::format("Failed to read value of g_pdmInstance from dwm.exe , status: {:#x}.\n", GetLastError()));

    auto desktop_manager = reinterpret_cast<desktop_manager_proto *>(desktop_manager_inst);
    std::cout << std::format("  g_pdmInstance = (CDesktopManager *){:#x};\n\n", desktop_manager_inst);

    bool enable_sharp_corners = true;
    out_size = {};
    if (!ReadProcessMemory(dwm_process, &desktop_manager->enable_sharp_corners, &enable_sharp_corners, 1, &out_size) || out_size != 1)
        std::cerr << std::format("Failed to read 'enable_sharp_corners' from dwm.exe, status: {:#x}.\n", GetLastError());

    constexpr std::array<char const *, 2> boolean_values {
        "disabled",
        "enabled"
    };

    std::cout << std::format("Your rounded corners were '{}', they are now being {}...\n", boolean_values[enable_sharp_corners], boolean_values[(!enable_sharp_corners)]);
    enable_sharp_corners ^= true;

    out_size = {};
    if (!WriteProcessMemory(dwm_process, &desktop_manager->enable_sharp_corners, &enable_sharp_corners, 1, &out_size) || out_size != 1)
        throw std::runtime_error(std::format("Failed to write 'enable_sharp_corners' to dwm.exe, status: {:#x}.\n", GetLastError()));

    std::cout << "Success!";

    if (enable_sharp_corners)
        std::cout << " Your Windows 11 experience is now enhanced!\n";

    return 0;
} catch (std::exception const &e) {
    std::cerr << e.what() << '\n';
    return 1;
}
