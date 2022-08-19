project('win11-toggle-rounded-corners', ['c', 'cpp'],
  version : '0.x',
  default_options : [
  	'warning_level=3',
  	'cpp_std=c++latest',
  	'buildtype=release',
  	'prefer_static=true',
    'default_library=static',
    'b_vscrt=static_from_buildtype'
  ],
  subproject_dir : 'deps')

cmake = import('cmake')
zydis_opts = cmake.subproject_options()
zydis_opts.add_cmake_defines({'ZYDIS_BUILD_TOOLS': false, 'ZYDIS_BUILD_EXAMPLES': false})


cc = meson.get_compiler('c')
if cc.get_id() == 'msvc'
  zydis_opts.append_compile_args('c', ['/MT', '/DEBUG:NONE'])
  zydis_opts.append_compile_args('cpp', ['/MT', '/DEBUG:NONE'])
  zydis_opts.append_link_args('c', ['/EMITPOGOPHASEINFO', '/DEBUG:NONE', '/ASSEMBLYDEBUG:DISABLE', '/OPT:NOREF', '/LTCG'])
  zydis_opts.append_link_args('cpp', ['/EMITPOGOPHASEINFO', '/DEBUG:NONE', '/ASSEMBLYDEBUG:DISABLE', '/OPT:NOREF', '/LTCG'])
endif
 
zydis_proj = cmake.subproject('zydis', options : zydis_opts)
zydis_depends = zydis_proj.dependency('Zydis')

executable('win11-toggle-rounded-corners', 'main.cpp', install : true, dependencies: [zydis_depends])
