cmake_minimum_required(VERSION 3.12)

project(Scylla)

cmake_policy(PUSH)
if(POLICY CMP0077)
    cmake_policy(SET CMP0077 NEW)
endif()

# Compilation options
option(SCYLLA_USE_MINIDUMP_FOR_CRASH "Use dbghelp.lib to create minidumps on crashs" OFF)
option(SCYLLA_USE_DEBUGGING_LOG "Create a debugging log file" OFF)
option(SCYLLA_BUILD_UNICODE "Builds the unicode version of Scylla" OFF)
set(WDK_LIBPATH "" CACHE FILEPATH "Path to your Windows Kit library folder (usually C:/Program Files (x86)/Windows Kits/10/Debuggers/lib)" )

if(SCYLLA_BUILD_UNICODE)
# compile projects as unicode
ADD_DEFINITIONS(-DUNICODE)
ADD_DEFINITIONS(-D_UNICODE)
endif()

#  Global properties for VS project to use folders
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Testing environment
enable_testing()
if(true)
	set(DUMPBIN_PATH "C:/Program Files (x86)/Microsoft Visual Studio/2017/Enterprise/VC/Tools/MSVC/14.11.25503/bin/HostX64/x64/dumpbin.exe")
elseif(NOT MSVC_VERSION VERSION_LESS 1800 AND MSVC_VERSION VERSION_LESS 1900)
	set(DUMPBIN_PATH "C:/Program Files (x86)/Microsoft Visual Studio 12.0/VC/BIN/dumpbin.exe")
elseif(NOT MSVC_VERSION VERSION_LESS 1900 AND MSVC_VERSION VERSION_LESS 2000)
	set(DUMPBIN_PATH "C:/Program Files (x86)/Microsoft Visual Studio 14.0/VC/BIN/dumpbin.exe")
endif()

### OS level checks
if ( "${CMAKE_SIZEOF_VOID_P}" EQUAL "8" )
	message(STATUS "-- 64 bits compiler detected" )
	set(ARCH "x64")
elseif( "${CMAKE_SIZEOF_VOID_P}" EQUAL "4" )
	message(STATUS "-- 32 bits compiler detected" )
	set(ARCH "x86")
else()
	message(FATAL_ERROR "-- Unknown compiler detected")
	set(ARCH "Unkown")
endif()
message(STATUS "-- Configuring project for arch ${ARCH}.")

get_filename_component(src_dir		"${PROJECT_SOURCE_DIR}" 	REALPATH)
set(vendor_dir "${src_dir}/vendor")
set(tinyxml2_dir	"${vendor_dir}/tinyxml2")
set(diStorm_dir	"${vendor_dir}/distorm")
set(WTL_dir		"${vendor_dir}/WindowsTemplateLibrary")
set(libScylla_dir "${src_dir}/libScylla")
set(libScylla_static_dir "${src_dir}/libScylla_static")
set(Scylla_dir	"${src_dir}/Scylla")
set(ScyllaTest_dir	"${src_dir}/ScyllaDllTest")

message(STATUS "-- Configuring : tinyxml2")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "build as shared library" FORCE)
add_subdirectory(${tinyxml2_dir})

# diStorm static library
message(STATUS "-- Configuring : diStorm")
file (GLOB diStorm_files 
			"${diStorm_dir}/src/*.c"
			"${diStorm_dir}/src/*.h"
)
add_library(diStorm ${diStorm_files})
target_include_directories(diStorm PUBLIC "${diStorm_dir}/include")
set_target_properties (diStorm PROPERTIES FOLDER "vendor")
install(TARGETS diStorm DESTINATION lib)

message(STATUS "-- Configuring : libScylla_static")
file (GLOB libScylla_files "${libScylla_static_dir}/*.cpp")
add_library(libScylla_static ${libScylla_files})
target_link_libraries(libScylla_static tinyxml2 diStorm Psapi Imagehlp)
target_include_directories(libScylla_static PUBLIC "${libScylla_static_dir}/" "${CMAKE_CURRENT_BINARY_DIR}/include" "${WTL_dir}/Include")
set_target_properties(libScylla_static PROPERTIES FOLDER "Scylla"
												  VERSION "${VERSION_TCHAR}")
configure_file("${libScylla_static_dir}/Scylla.h.in" "${CMAKE_CURRENT_BINARY_DIR}/include/Scylla.h")
install(TARGETS libScylla_static DESTINATION lib)
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include/ DESTINATION include)

message(STATUS "-- Configuring : libScylla")
file(GLOB libScylla_files "${libScylla_dir}/*.cpp")
add_library(libScylla SHARED ${libScylla_files})
target_link_libraries(libScylla libScylla_static)
target_include_directories(libScylla_static PUBLIC "${libScylla_dir}/")
set_target_properties(libScylla PROPERTIES FOLDER "Scylla"
										   VERSION "${VERSION_TCHAR}")
install(TARGETS libScylla DESTINATION lib)

#### Scylla targets
# Scylla executable
message(STATUS "-- Configuring : Scylla")
file (GLOB Scylla_files 
			"${Scylla_dir}/*.cpp"
			"${Scylla_dir}/*.ico"
			"${Scylla_dir}/*.rc"
)
add_executable(Scylla ${Scylla_files})
target_include_directories(Scylla PRIVATE "${Scylla_dir}/")
target_link_libraries(Scylla libScylla_static)
set_target_properties(Scylla PROPERTIES FOLDER "Scylla"
										VERSION "${VERSION_TCHAR}"
										LINK_FLAGS "/SUBSYSTEM:WINDOWS  /MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /MANIFESTDEPENDENCY:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df'\" /DYNAMICBASE")
install(TARGETS Scylla DESTINATION bin)

if (SCYLLA_USE_MINIDUMP_FOR_CRASH)
	find_library(dbghelp_lib dbghelp ${WDK_LIBPATH}/${ARCH})
	
	target_link_libraries(Scylla ${dbghelp_lib})
	target_compile_definitions(Scylla PUBLIC "-DSCYLLA_USE_MINIDUMP_FOR_CRASH")
endif()

if (SCYLLA_USE_DEBUGGING_LOG)
	target_compile_definitions(Scylla PUBLIC "-DDEBUG_COMMENTS")
endif()

#### Scylla tests

# ScyllaDllTest
message(STATUS "-- Configuring : ScyllaDllTest")
file (GLOB ScyllaDllTest_files 
			"${ScyllaTest_dir}/ScyllaDllTest/*.cpp"
			"${ScyllaTest_dir}/ScyllaDllTest/*.h"
)
add_executable(ScyllaDllTest ${ScyllaDllTest_files})
set_target_properties (ScyllaDllTest PROPERTIES	FOLDER "tests")

# X86 version of ScyllaDll can only create/open x86 process, and same for x64
if (${ARCH} STREQUAL  "x86")
add_test( NAME TEST_SYSINTERNALS
	COMMAND Powershell.exe "${src_dir}/tests/DumpbinIatDirectoryEntry.ps1" -Dumpbin \"${DUMPBIN_PATH}\" -TestFolder "${src_dir}/tests/x86" -ScyllaExe "$<TARGET_FILE:ScyllaDllTest>"
)
add_test( NAME TEST_SYSWOW64
	COMMAND Powershell.exe "${src_dir}/tests/DumpbinIatDirectoryEntry.ps1" -Dumpbin \"${DUMPBIN_PATH}\" -TestFolder "C:/Windows/SysWOW64" -ScyllaExe "$<TARGET_FILE:ScyllaDllTest>"
)
elseif ("${ARCH}" STREQUAL  "x64")
add_test( NAME TEST_SYS32
	COMMAND Powershell.exe "${src_dir}/tests/DumpbinIatDirectoryEntry.ps1" -Dumpbin \"${DUMPBIN_PATH}\" -TestFolder "C:/Windows/System32" -ScyllaExe "$<TARGET_FILE:ScyllaDllTest>"
)
endif()


# ScyllaExeTest
add_executable(ScyllaExeTest "${ScyllaTest_dir}/ScyllaTestExe/main.cpp")
set_target_properties (ScyllaExeTest PROPERTIES	FOLDER "tests" LINK_FLAGS "/SUBSYSTEM:WINDOWS")

cmake_policy(POP)
