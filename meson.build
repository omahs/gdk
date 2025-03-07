project('gdk', ['c', 'cpp'], version: '0.0.56', meson_version : '>= 0.58.0')

# commonly used checks
compiler = meson.get_compiler('cpp')

cross_win_build = meson.get_cross_property('target_os', '') == 'windows'
cross_iphone_build =  meson.get_cross_property('target_os', '').contains('iphone')
cross_android_build = host_machine.system() == 'android'
is_32bit_android_build = cross_android_build and (host_machine.cpu() == 'armv7' or host_machine.cpu() == 'i686')
is_freebsd = host_machine.system().startswith('freebsd')
is_darwin = build_machine.system() == 'darwin'
is_clang = compiler.get_id() == 'clang'
freebsd_requires_gold = is_freebsd and is_clang
use_gold = (build_machine.system() == 'linux' or freebsd_requires_gold) and not cross_win_build and not cross_android_build
debug_optimized = get_option('buildtype') == 'debugoptimized'
debug = debug_optimized or get_option('buildtype') == 'debug'

# header checks (must be architecture independent)
check_headers = [
    'fcntl.h',
    'stddef.h',
    'stdint.h',
    'string.h',
    'sys/epoll.h',
    'sys/stat.h',
    'unistd.h'
]

foreach h : check_headers
    compiler.has_header(h)
endforeach

# language options
add_project_arguments(compiler.first_supported_argument(['-std=c++17', '-std=c++14']), language : 'cpp')
add_project_arguments(['-Wno-deprecated-declarations', '-funsigned-char'], language : 'cpp')

static_libstdc = compiler.has_link_argument('-static-libstdc++')

# language related arguments
if use_gold
    if is_clang and not is_freebsd and compiler.has_link_argument('-fuse-ld=lld')
        add_project_link_arguments(['-fuse-ld=lld', '-ldl'], language : 'cpp')
    else
        add_project_link_arguments(['-fuse-ld=gold', '-ldl'], language : 'cpp')
    endif
elif cross_android_build
    if is_darwin
        add_project_link_arguments(['-fuse-ld=bfd', '-ldl'], language : 'cpp')
    else
        add_project_link_arguments(['-fuse-ld=lld', '-ldl'], language : 'cpp')
    endif
endif

common_compile_options = [
    '-Wno-unknown-warning-option',
    '-Wextra',
    '-D_FORTIFY_SOURCE=2',
    '-fasynchronous-unwind-tables',
    '-fexceptions',
    '-fstack-protector-strong',
    '-fvisibility=hidden',
    '-DGDK_BUILD',
    '-D_HAVE_SQLITE_CONFIG_H'
]

if not is_freebsd and compiler.has_argument('-Wthread-safety')
    common_compile_options += ['-Wthread-safety']
endif

if get_option('time-report') and compiler.has_argument('-ftime-report')
      common_compile_options += ['-ftime-report']
endif

add_project_arguments(common_compile_options, language : ['c', 'cpp'])
add_project_arguments('-fvisibility-inlines-hidden', language : ['cpp'])

common_link_args = [
    '-Wl,-z,now',
    '-Wl,-z,relro',
    '-Wl,-z,noexecstack'
]

if (is_darwin or cross_iphone_build) and not cross_android_build
  # to generate keys in gdk_rust
  add_project_link_arguments(['-Wl,-framework,Security'], language : 'cpp')
endif

if is_darwin and not cross_android_build and not cross_iphone_build
  add_project_arguments(['-mmacosx-version-min=10.13'], language : ['c', 'cpp'])
  add_project_link_arguments(['-mmacosx-version-min=10.13'], language : ['c', 'cpp'])
endif

if cross_iphone_build
  add_project_arguments(['-miphoneos-version-min=11.0'], language : ['c', 'cpp'])
  add_project_link_arguments(['-miphoneos-version-min=11.0'], language : ['c', 'cpp'])
endif

if is_freebsd
    if freebsd_requires_gold
        common_link_args += ['-Wl,--weak-unresolved-symbols']
    else
        common_link_args += ['-Wl,-z,undefs']
    endif
endif

if (not is_darwin and not cross_win_build) or cross_android_build
    add_project_link_arguments(common_link_args, language : ['c', 'cpp'])
endif

# https://developer.android.com/ndk/guides/asan
# https://github.com/android/ndk/issues/988
# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=64234
if get_option('b_sanitize') == 'address'
    if is_clang
        add_project_link_arguments(['-static-libsan'], language : ['c', 'cpp'])
    else
        add_project_link_arguments(['-shared-libasan'], language : ['c', 'cpp'])
    endif
endif

if debug
    add_project_arguments(['-ggdb3', '-fno-omit-frame-pointer', '-D_GLIBCXX_ASSERTIONS', '-D_GLIBCXX_DEBUG', '-D_GLIBCXX_DEBUG_PEDANTIC'], language : ['c', 'cpp'])
    if not is_darwin
      # Not yet supported on Apple Clang compiler
      add_project_arguments(['-D_LIBCPP_DEBUG=1'], language : ['c', 'cpp'])
    endif
    if debug_optimized
        add_project_arguments(['-Og'], language : ['c', 'cpp'])
    endif
else
    add_project_arguments(['-DNDEBUG'], language : ['c', 'cpp'])
endif

if meson.is_cross_build()
    archs = meson.get_cross_property('archs')
    if archs != []
        add_project_arguments(meson.get_cross_property('archs'), language : ['c', 'cpp'])
    endif
endif

if is_32bit_android_build
    add_project_arguments('-U_FILE_OFFSET_BITS', language : ['c', 'cpp'])
endif

swift = add_languages('swift', required : false)
if swift
    add_project_arguments(['-I' + join_paths(meson.source_root(), 'src')], language : 'swift')
    add_project_arguments(['-I' + join_paths(meson.build_root(), 'libwally-core', 'include')], language : 'swift')
    add_project_arguments(['-I' + join_paths(meson.source_root(), 'src', 'swift', 'GreenAddress', '.build', 'debug')], language : 'swift')
    add_project_link_arguments(['-L' + join_paths(meson.build_root(), 'src')], language : 'swift')
    add_project_link_arguments(['-L' + join_paths(meson.source_root(), 'src', 'swift', 'GreenAddress')], language : 'swift')
    add_project_link_arguments(['-lGreenAddress'], language : 'swift')
endif

executable_c_cpp_args = ['-fPIE']
executable_link_args = []
if static_libstdc
    executable_link_args += ['-static-libstdc++']
endif

executable_link_args = []
if compiler.get_id() == 'gcc'
    executable_c_cpp_args += ['-pie']
else
    executable_link_args += ['-pie']
endif

if cross_win_build
    executable_link_args += ['-static', '-static-libgcc']
endif

sed = find_program('gsed', 'sed')
cargo = find_program('cargo')
swig = find_program('swig', required : false)
if swig.found()
    pymodule = import('python')
    python_version = get_option('python-version')
    python_installation = pymodule.find_installation('python' + python_version, required : true)
    python_exe = python_installation.path()

    environment_variables = [
        'JAVA_HOME',
        'JAVA_TARGET'
    ]
    foreach v : environment_variables
        res = run_command(python_exe, '-c', 'import os; print(os.getenv("' + v + '", ""))')
        if res.returncode() == 0
            stdout = res.stdout().strip()
            set_variable(v.to_lower(), stdout)
            message(v + ' set to "' + stdout + '"')
        else
            set_variable(v.to_lower(), '')
        endif
    endforeach

    if python_version != ''
        # FIXME: When making a python module we must avoid linking libpython
        # and allow the interpreter to provide the symbols for manylinux
        # compatibility. Currently we use embed because the gdk shared lib
        # has to be built without unresolved symbols.
        # Workaround for https://github.com/mesonbuild/meson/issues/5629
        python_dep = dependency('python-@0@-embed'.format(python_version), version: '>=3', required: false)
        if not python_dep.found()
            python_dep = python_installation.dependency(embed:true)
            if not python_dep.found()
                error('Python development dependency not be found, please install python(version)-dev and try again.')
            endif
        endif
    else
        # Python only needed for reading 'environment_variables' above
        python_dep = dependency('', required : false)
    endif

    if java_target == ''
        java_target = '1.8'
    endif

    javac = add_languages('java', required : false)
    if not javac
        message('javac not found JNI bindings are disabled.')
    elif java_home == ''
        message('$JAVA_HOME not set. JNI bindings are disabled.')
    else
        java = find_program('java')
    endif
endif

jni_deps  = swig.found() and javac and java_home != ''
jni_disabled = cross_win_build or cross_iphone_build or not jni_deps
build_jni = (jni_deps or cross_android_build) and not jni_disabled
build_swig_python = swig.found() and python_dep.found() and not cross_iphone_build and not cross_android_build

ar = find_program('ar', required : not cross_android_build)
objcopy = find_program('objcopy', required : false)

clang_format = find_program('clang-format', required : false)

clang_tidy_name = 'clang-tidy' + get_option('clang-tidy-version')
clang_tidy = find_program(clang_tidy_name, required : false)

pvs_studio_analyzer = find_program('pvs-studio-analyzer', required : false)
infer = find_program('infer', required : false)
git = find_program('git', required : true)

sphinx_build = find_program('sphinx-build', required : false)
if sphinx_build.found()
    source_docs = join_paths(meson.source_root(), 'docs', 'source')
    custom_target('apidocs', output : 'apidocs', command : [sphinx_build, '-b', 'html', '-a',
                  '-c', source_docs, source_docs, join_paths(meson.source_root(), 'docs', 'build', 'html')])
else
    message('apidocs generation is not available')
endif

# dependencies
library_deps = []

if cross_android_build == false
    library_deps += compiler.find_library('pthread', required : true)
endif
library_deps += compiler.find_library('m', required : false)
library_deps += compiler.find_library('atomic', required : false)
library_deps += compiler.find_library('dl', required : false)
library_deps += compiler.find_library('ws2_32', required : cross_win_build)
library_deps += compiler.find_library('bcrypt', required : cross_win_build)
library_deps += compiler.find_library('crypt32', required : cross_win_build)
library_deps += compiler.find_library('iphlpapi', required : cross_win_build)
library_deps += compiler.find_library('ssp', required : cross_win_build)
library_deps += compiler.find_library('log', required : cross_android_build)
if debug and build_machine.system() == 'linux'
    backtrace_dep = compiler.find_library('backtrace', has_headers : ['backtrace.h'], required : false)
    if backtrace_dep.found()
        library_deps += backtrace_dep
        add_project_arguments(['-DHAVE_BACKTRACE'], language : ['c', 'cpp'])
    endif
endif
library_deps += compiler.find_library('execinfo', required : is_freebsd)


build_dir = meson.global_build_root().split('/').get(-1)
externaldir = 'external_deps'
#wally dependency
wallycore = declare_dependency(
    include_directories:[ externaldir / 'libwally-core/build/include'],
    variables:{
    'wallycore_dir_name': externaldir / 'libwally-core',
    'libdir': externaldir / 'libwally-core/build/lib',
    }
)

subproject_deps = [
    #### wallycore
    wallycore,
    compiler.find_library('wallycore', dirs: meson.global_build_root() / externaldir / 'libwally-core/build/lib'),
    compiler.find_library('secp256k1', dirs: meson.global_build_root() / externaldir / 'libwally-core/build/lib'),
    #### libevent
    declare_dependency( include_directories: externaldir / 'libevent/build/include'),
    compiler.find_library('event', dirs: meson.global_build_root() / externaldir / 'libevent/build/lib'),
    #### boost
    declare_dependency( include_directories: externaldir / 'boost/build/include'),
    compiler.find_library('boost_chrono', dirs: meson.global_build_root() / externaldir / 'boost/build/lib'),
    compiler.find_library('boost_log', dirs: meson.global_build_root() / externaldir / 'boost/build/lib'),
    compiler.find_library('boost_thread', dirs: meson.global_build_root() / externaldir / 'boost/build/lib'),
    #### tor
    declare_dependency( include_directories: externaldir / 'tor/src/feature/api'),
    compiler.find_library('tor-app', dirs: meson.global_build_root() / externaldir / 'tor/src/core'),
    compiler.find_library('curve25519_donna', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-buf', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-compress', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-confmgt', dirs: meson.global_build_root() / externaldir  / 'tor/src/lib'),
    compiler.find_library('tor-container', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-crypt-ops', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-ctime', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-dispatch', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-encoding', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-err', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-evloop', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-fdio', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-fs', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-geoip', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-intmath', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-lock', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-log', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-malloc', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-math', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-memarea', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-meminfo', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-net', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-osinfo', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-process', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-pubsub', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-sandbox', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-smartlist-core', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-string', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-term', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-thread', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-time', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-tls', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-trace', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-version', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('tor-wallclock', dirs: meson.global_build_root() / externaldir / 'tor/src/lib'),
    compiler.find_library('or-trunnel', dirs: meson.global_build_root() / externaldir / 'tor/src/trunnel'),
    compiler.find_library('keccak-tiny', dirs: meson.global_build_root() / externaldir / 'tor/src/ext/keccak-tiny'),
    compiler.find_library('ed25519_ref10', dirs: meson.global_build_root() / externaldir / 'tor/src/ext/ed25519/ref10'),
    compiler.find_library('ed25519_donna', dirs: meson.global_build_root() / externaldir / 'tor/src/ext/ed25519/donna'),
    #### zlib
    declare_dependency( include_directories: externaldir / 'zlib/build/include'),
    compiler.find_library('z', dirs: meson.global_build_root() / externaldir / 'zlib/build/lib'),
    #### openssl
    declare_dependency(include_directories: externaldir / 'openssl/build/include'),
    compiler.find_library('ssl', dirs: meson.global_build_root() / externaldir / 'openssl/build/lib'),
    compiler.find_library('crypto', dirs: meson.global_build_root() / externaldir / 'openssl/build/lib'),
    #### websocketpp
    declare_dependency(include_directories: externaldir / 'websocketpp/include'),
    #### msgpack
    declare_dependency(include_directories: externaldir / 'msgpack/include'),
    #### nlohmann_json
    declare_dependency(include_directories: externaldir / 'nlohmann_json/include'),
    #### autobahn-cpp
    declare_dependency(include_directories: externaldir / 'autobahn-cpp/include'),
    #### ms-gsl
    declare_dependency(include_directories: externaldir / 'ms-gsl/include'),
    #
]

if not cross_win_build
    subproject_deps += compiler.find_library('event_pthreads', dirs: meson.global_build_root() / externaldir / 'libevent/build/lib')
endif

gdkrust = subproject('gdk_rust')
subproject_deps += gdkrust.get_variable('gdk_rust_dep')

# includes
incdir = include_directories(['.', 'subprojects/gdk_rust'])

 #builds
subdirs = ['src']
foreach n : subdirs
    subdir(n)
endforeach

if get_option('enable-tests')
    test('test aes_gcm',
         executable('test_aes_gcm', 'tests/test_aes_gcm.cpp',
                    link_with: libga.get_static_lib(),
                    dependencies: dependencies
        ))

    test('test json',
         executable('test_json', 'tests/test_json.cpp',
                    link_with: libga.get_static_lib(),
                    dependencies: dependencies
        ))

    test('test multisession',
         executable('test_multi_session', 'tests/test_multi_session.cpp',
                    link_with: libga.get_static_lib(),
                    dependencies: dependencies
        ))

    test('test networks',
         executable('test_networks', 'tests/test_networks.cpp',
                    link_with: libga.get_static_lib(),
                    dependencies: dependencies
        ))

    test('test session',
         executable('test_session', 'tests/test_session.cpp',
                    link_with: libga.get_static_lib(),
                    dependencies: dependencies
        ))
endif
