#ifndef LLVM_56379_WORKAROUND_H
#define LLVM_56379_WORKAROUND_H

#if __has_include(<source_location>)
#include <source_location>
#endif  // __has_include(<source_location>)

#if defined(__clang__) && (!__has_include(<source_location>) || !defined(__cpp_lib_source_location))
// Workaround for llvm/llvm-project#56379
namespace std {
class source_location {
 private:
  struct __impl {
    char const *_M_file_name;
    char const *_M_function_name;
    std::uint_least32_t _M_line;
    std::uint_least32_t _M_column;
  } _M_impl;

 public:
  [[nodiscard]] constexpr source_location() noexcept = default;

  [[nodiscard]] inline static /*HACK! consteval -> */ constexpr source_location current(__impl const *data = __builtin_source_location()) {
    source_location result;
    result._M_impl = *data;
    return result;
  }

  [[nodiscard]] constexpr char const *file_name() const noexcept {
    return _M_impl._M_file_name;
  }

  [[nodiscard]] constexpr char const *function_name() const noexcept {
    return _M_impl._M_function_name;
  }

  [[nodiscard]] constexpr std::uint_least32_t column() const noexcept {
    return _M_impl._M_column;
  }

  [[nodiscard]] constexpr std::uint_least32_t line() const noexcept {
    return _M_impl._M_line;
  }
};
}
#endif  // defined(__clang__) && (!__has_include(<source_location>) || !defined(__cpp_lib_source_location))

#endif  // LLVM_56379_WORKAROUND_H
