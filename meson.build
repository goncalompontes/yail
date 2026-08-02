project('yail', 'cpp', default_options : ['cpp_std=c++latest'])

yail_inc = include_directories('include')
omath_shim_inc = include_directories('shim')

yail_sources = files(
    'source/yail.cpp',
    'source/pe.cpp',
    'source/process.cpp',
    'source/native_loader.cpp',
    'source/shellcode.cpp',
    'source/wow64.cpp',
)

cpp = meson.get_compiler('cpp')

yail_args = []
if cpp.get_id() == 'msvc'
    yail_args += ['/DNOMINMAX', '/DWIN32_LEAN_AND_MEAN', '/wd4100', '/wd4189', '/wd4505', '/utf-8']
endif

yail_lib = static_library('yail', yail_sources,
    include_directories : [yail_inc, omath_shim_inc],
    cpp_args : yail_args,
    override_options : ['cpp_std=c++latest'],
)

yail_dep = declare_dependency(
    link_with : yail_lib,
    include_directories : [yail_inc, omath_shim_inc],
)
