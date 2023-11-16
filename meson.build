project('win11-toggle-rounded-corners', ['c', 'cpp'],
  version : '1.2',
  default_options : [
    'cpp_std=c++latest',
    'buildtype=release',
    'prefer_static=true',
    'warning_level=3',
    'werror=true',
    'default_library=static',
    'b_vscrt=static_from_buildtype',
  ],
  subproject_dir : 'deps')

cmake = import('cmake')
zydis_opts = cmake.subproject_options()
zydis_opts.add_cmake_defines({'ZYDIS_BUILD_TOOLS': false, 'ZYDIS_BUILD_EXAMPLES': false})

c_compiler_id = meson.get_compiler('c').get_id()
if c_compiler_id in ['msvc', 'clang-cl']
  add_global_arguments(['/wd5072', '/wd4820', '/wd4455', '/wd4668', '/wd5039'], language: 'c')
  zydis_opts.append_compile_args('c', ['/MT'])
  if c_compiler_id == 'msvc'
    zydis_opts.append_link_args('c', ['/EMITPOGOPHASEINFO', '/DEBUG:NONE', '/ASSEMBLYDEBUG:DISABLE', '/OPT:NOREF', '/LTCG'])
  endif
else
  warning('Unsupported compiler')
endif

cpp_compiler_id = meson.get_compiler('cpp').get_id()
if cpp_compiler_id in ['msvc', 'clang-cl']
  add_global_arguments(['/wd5072', '/wd4820', '/wd4455', '/wd4668', '/wd5039'], language: 'cpp')
endif

zydis_proj = cmake.subproject('zydis', options : zydis_opts)
zydis_depends = zydis_proj.dependency('Zydis')

executable('win11-toggle-rounded-corners',
           'main.cpp',
           dependencies: [zydis_depends],
           cpp_args: ['/W4', '/MT', '/permissive-'],
           link_args: ['/EMITPOGOPHASEINFO', '/DEBUG:NONE', '/ASSEMBLYDEBUG:DISABLE', '/OPT:NOREF', '/LTCG'])
