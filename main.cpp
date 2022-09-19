#include <array>
#include <algorithm>
#include <functional>
#include <format>
#include <iostream>
#include <optional>
#include <string_view>
#include <ranges>
#include <concepts>
#include <optional>
#include <source_location>

#include <cstdio>
#include <cinttypes>

#include <windows.h>
#include <tlhelp32.h>

#include <Zydis/Zydis.h>

#include <format>
#include <concepts>

struct Option {
  std::wstring_view name;
  std::wstring_view desc;
  bool value;
};

namespace oberrich::detail {
using namespace std::string_view_literals;
static constexpr Option help_option{L"help"sv, L"Shows all available options."sv};

static bool verbose_enabled{};
}

inline void set_verbose(bool enabled) noexcept {
  oberrich::detail::verbose_enabled = enabled;
}

inline bool get_verbose() noexcept {
  return oberrich::detail::verbose_enabled;
}

template <typename... Args>
inline void verbose(Args&&... args) {
  if (get_verbose())
    (std::cout << ... << args);
}

template <std::size_t N>
struct ProgramOptions {
  ProgramOptions(auto&&...opts)
    : argc{0}
    , argv{const_cast<decltype(argv)>(CommandLineToArgvW(GetCommandLineW(), &argc))}
    , command{argv[0]}
    , program_name{command.substr(std::size(command) - std::ranges::distance(command
                     | std::views::reverse
                     | std::views::take_while(
                         [](auto const c) constexpr noexcept { return c != L'/' && c != L'\\'; })))}
    , options{std::array{oberrich::detail::help_option, std::forward<decltype(opts)>(opts)...}}
  {
    using namespace std::string_view_literals;

    constexpr auto trim_and_wrap = [](std::wstring_view str) constexpr noexcept {
      constexpr auto is_dash = [](auto const c) constexpr noexcept { return c == L'-'; };
      return static_cast<std::wstring_view>(str | std::views::drop_while(is_dash));
    };

    for (auto const arg : std::span{argv + 1, argv + argc} | std::views::transform(trim_and_wrap)) {
      for (auto &option : options) {
        if (option.name == arg)
          option.value = true;
      }
    }

    constexpr std::wstring_view program_name_friendly{L"Win11 Toggle Rounded Corners"sv};
    constexpr std::wstring_view author               {L"oberrich"sv};
    constexpr std::wstring_view version              {L"v1.1"sv};
    constexpr std::wstring_view copyright_year       {L"2022"sv};

    std::wcout << std::format(L"{} {}\nCopyright (C) {} {}\n\n"sv, program_name_friendly, version, copyright_year, author);

    if (decltype(auto) self = std::as_const(*this); self[L"help"sv].value)
      print_help();
  }

  template <typename ValT>
  constexpr std::optional<std::reference_wrapper<ValT>> get(std::wstring_view name) const {
    if (auto result = std::ranges::find_if(options, [name](auto const &option) constexpr noexcept {
                        return option.name == name; });
        result != std::end(options))
      return {*result};
    return {};
  }

  constexpr Option       &operator[](std::wstring_view name)       { return get<Option      >(name).value().get(); }
  constexpr Option const &operator[](std::wstring_view name) const { return get<Option const>(name).value().get(); }

  void print_help() const {
    using namespace std::string_view_literals;
    std::wcout << std::format(L"{} [options]\nOptions:\n"sv, program_name);

    for (auto const &option : options)
      std::wcout << std::format(L"  --{: <20}: {}\n"sv, option.name, option.desc);

    std::exit(0);
  }

  int argc;
  wchar_t const **argv;
  std::wstring_view command;
  std::wstring_view program_name;
  std::array<Option, N> options;
};

template <typename... Options>
ProgramOptions(Options...) -> ProgramOptions<sizeof...(Options) + 1>;

namespace detail {
static inline bool enforce_status(ZyanStatus status, const std::source_location location = std::source_location::current()) {
  if (ZYAN_FAILED(status))
    throw std::runtime_error(std::format("{}({}): assertion failed with status {:#x}",
                                         location.file_name(), location.line(), status));
  return true;
}
}

enum struct DecoderStatus : bool {
  kDone = false,
  kNext = true
};

struct Instruction : ZydisDecodedInstruction {
  DecoderStatus follow() {
    if (ZyanU64 target{ calc_abs() })
      address = target - length;
    else
      detail::enforce_status(ZYAN_STATUS_INVALID_ARGUMENT);

    return DecoderStatus::kNext;
  }

  ZyanU64 calc_abs(std::size_t n = 0u) {
    if (n >= ZYDIS_MAX_OPERAND_COUNT_VISIBLE)
      detail::enforce_status(ZYAN_STATUS_INVALID_ARGUMENT);

    ZyanU64 absolute{};
    detail::enforce_status(ZydisCalcAbsoluteAddress(this, &operands[n], address, &absolute));
    return absolute;
  };

  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
  ZyanU64 address;
};

struct Decoder : ZydisDecoder {
  Decoder() {
    detail::enforce_status(ZydisDecoderInit(this, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64));
  }

  template <typename T = void>
  void disassemble(ZyanU64 address, std::invocable<Instruction &> auto &&callback) {
    Instruction instrn{};
    instrn.address = address;

    while (detail::enforce_status(ZydisDecoderDecodeFull(this, reinterpret_cast<ZyanU8 const *>(instrn.address), 32, &instrn, instrn.operands,
                                                         ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY))) {
      if (callback(instrn) == DecoderStatus::kDone)
        return;

      instrn.address += instrn.length;
    }
  }
};

struct Formatter : ZydisFormatter {
  Formatter() noexcept {
    detail::enforce_status(ZydisFormatterInit(this, ZYDIS_FORMATTER_STYLE_INTEL));
    detail::enforce_status(ZydisFormatterSetProperty(this, ZYDIS_FORMATTER_PROP_IMM_SIGNEDNESS, ZYDIS_SIGNEDNESS_AUTO));
  }

  std::string_view operator()(ZydisInstructionCategory const category)  const noexcept { return { ZydisCategoryGetString(category)  }; }
  std::string_view operator()(ZydisRegister            const register_) const noexcept { return { ZydisRegisterGetString(register_) }; }
  std::string_view operator()(ZydisMnemonic            const mnemonic)  const noexcept { return { ZydisMnemonicGetString(mnemonic)  }; }
  std::string_view operator()(ZydisISASet              const isa_set)   const noexcept { return { ZydisISASetGetString(isa_set)     }; }
  std::string_view operator()(ZydisISAExt              const isa_ext)   const noexcept { return { ZydisISAExtGetString(isa_ext)     }; }

  std::string operator()(ZydisDecodedInstruction const &instrn, ZydisDecodedOperand const *operands, ZyanU64 const address) const {
    static auto constexpr kMaxChars = 256;
    auto buffer = std::make_unique<char []>(kMaxChars);
    ZydisFormatterFormatInstruction(this, &instrn, operands, instrn.operand_count_visible, buffer.get(), kMaxChars, address,
                                    ZYAN_NULL);
    return std::format("  {:#x}: {}", address, buffer.get());
  }

  std::string operator()(Instruction const &instrn) const {
    return (*this)(instrn, instrn.operands, instrn.address);
  }
};

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

std::optional<std::ptrdiff_t> locate_udwm_desktop_manager()
{
    auto const udwm_dll = LoadLibraryExA("udwm.dll", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!udwm_dll)
        return {};

    auto const dwm_client_startup = reinterpret_cast<uint64_t>(GetProcAddress(udwm_dll, MAKEINTRESOURCE(101)));
    if (!dwm_client_startup)
        return {};

    struct DynamicData {
      ZyanU64 instance{};
      bool found_create{};
    };
    DynamicData dyn_data{};

    Formatter formatter{};
    Decoder decoder{};
    decoder.disassemble(dwm_client_startup, [&formatter, &dyn_data](Instruction &instrn) {
      if (instrn.mnemonic == ZYDIS_MNEMONIC_RET)
        throw std::out_of_range("Failed to disasm: Reached end of function");

      verbose(formatter(instrn), '\n');

      if (!dyn_data.found_create && instrn.mnemonic == ZYDIS_MNEMONIC_CALL) {
        dyn_data.found_create = true;
        return instrn.follow();
      }

      if (auto const &op0 = instrn.operands[0];
          instrn.mnemonic == ZYDIS_MNEMONIC_MOV && op0.type == ZYDIS_OPERAND_TYPE_MEMORY && op0.mem.segment == ZYDIS_REGISTER_DS) {
        dyn_data.instance = instrn.calc_abs();
        return DecoderStatus::kDone;
      }

      return DecoderStatus::kNext;
    });

    if (!dyn_data.instance || !dyn_data.found_create)
      return {};

    return static_cast<std::ptrdiff_t>(dyn_data.instance - reinterpret_cast<ZyanU64>(udwm_dll));
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
                    return reinterpret_cast<uint64_t>(entry.modBaseAddr) ;
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
  using namespace std::string_view_literals;

  ProgramOptions const options{
      constexpr Option{L"autostart"sv, L"Puts the program into auto-start with the currently specified options. NOT IMPLEMENTED"sv},
      constexpr Option{L"verbose"sv, L"Enables verbose output."sv},
      constexpr Option{L"disable"sv, L"Always disables rounded corners. Has precedence over --enable."sv},
      constexpr Option{L"enable"sv, L"Always enables rounded corners."sv}
  };

  set_verbose(options[L"verbose"sv].value);

  auto should_disable = options[L"disable"sv].value;
  auto should_override_toggle = should_disable || options[L"enable"sv].value;

  if (!enable_privilege(SE_DEBUG_NAME))
    throw std::runtime_error(std::format("Failed enable {}, make sure you are running as admin.", SE_DEBUG_NAME));

  auto const dwm_hwnd = FindWindowA("Dwm", nullptr);
  DWORD dwm_pid = 0u;

  if (!dwm_hwnd || !GetWindowThreadProcessId(dwm_hwnd, &dwm_pid))
    throw std::runtime_error("Failed to find dwm process.\n");

  verbose(std::format("Found dwm.exe process [window handle: {}, pid: {}].\n", static_cast<void *>(dwm_hwnd), dwm_pid));

  auto const dwm_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwm_pid);
  if (!dwm_process)
    throw std::runtime_error(std::format("Failed to open dwm.exe process, status: {:#x}!", GetLastError()));

  verbose(std::format("Opened process handle {:#x} to dwm.exe.\nLocating CDesktopManager *g_pdmInstance:\n", reinterpret_cast<uint64_t>(dwm_process)));

  auto const desktop_manager_rva = locate_udwm_desktop_manager();
  if (!desktop_manager_rva)
    throw std::runtime_error("Failed to locate g_pdmInstance RVA inside udwm.dll.");

  verbose(std::format("Found g_pdmInstance at RVA {:#x}.\n", desktop_manager_rva.value()));

  auto const dwm_base = find_module_base(dwm_pid, std::string_view{"udwm.dll"});
  if (!dwm_base)
    throw std::runtime_error("Failed to find udwm.dll module inside dwm.exe process!");

  verbose(std::format("Found udwm.dll mapped at {:#x}.\n", dwm_base.value()));

  auto desktop_manager_ptr = reinterpret_cast<void const *>(dwm_base.value() + desktop_manager_rva.value());
  uint64_t desktop_manager_inst{};
  SIZE_T out_size{};
  if (!ReadProcessMemory(dwm_process, desktop_manager_ptr, &desktop_manager_inst, sizeof(void *), &out_size) || !desktop_manager_inst)
    throw std::runtime_error(std::format("Failed to read value of g_pdmInstance from dwm.exe , status: {:#x}.\n", GetLastError()));

  auto desktop_manager = reinterpret_cast<desktop_manager_proto *>(desktop_manager_inst);
  verbose(std::format("  g_pdmInstance = (CDesktopManager *){:#x};\n\n", desktop_manager_inst));

  constexpr std::array boolean_values { "enabled"sv, "disabled"sv };

  if (!should_override_toggle) {
    out_size = {};
    if (!ReadProcessMemory(dwm_process, &desktop_manager->enable_sharp_corners, &should_disable, 1, &out_size) || out_size != 1)
      throw std::runtime_error(std::format("Failed to read 'enable_sharp_corners' from dwm.exe, status: {:#x}.\n", GetLastError()));

    std::cout << std::format("Your rounded corners were '{}', they are now being {}... ",
                             boolean_values[should_disable], boolean_values[(!should_disable)]);
    should_disable ^= true;
  } else {
    std::cout << std::format("Your rounded corners are being {}... ", boolean_values[should_disable]);
  }

  out_size = {};
  if (!WriteProcessMemory(dwm_process, &desktop_manager->enable_sharp_corners, &should_disable, 1, &out_size) || out_size != 1)
    throw std::runtime_error(std::format("Failed to write 'enable_sharp_corners' to dwm.exe, status: {:#x}.\n", GetLastError()));

  std::cout << "Success!\n";

  if (should_disable)
    std::cout << "Your Windows 11 experience is now enhanced!\n";

  return 0;
} catch (std::exception const &e) {
    std::cerr << e.what() << '\n';
    return 1;
}
