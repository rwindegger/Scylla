cmake_minimum_required(VERSION 3.0)
project(Scylla)

# Compilation options
option(SCYLLA_USE_MINIDUMP_FOR_CRASH "Use dbghelp.lib to create minidumps on crashs" OFF)
option(SCYLLA_USE_DEBUGGING_LOG "Create a debugging log file" OFF)
set(WDK_LIBPATH "" CACHE FILEPATH "Path to your Windows Kit library folder (usually C:/Program Files (x86)/Windows Kits/10/Debuggers/lib)" )


#  Global properties for VS project to use folders
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Testing environment
enable_testing()
if(NOT MSVC_VERSION VERSION_LESS 1800 AND MSVC_VERSION VERSION_LESS 1900)
	set(DUMPBIN_PATH "C:/Program Files (x86)/Microsoft Visual Studio 12.0/VC/BIN/dumpbin.exe")
elseif(NOT MSVC_VERSION VERSION_LESS 1900 AND MSVC_VERSION VERSION_LESS 2000)
	set(DUMPBIN_PATH "C:/Program Files (x86)/Microsoft Visual Studio 14.0/VC/BIN/dumpbin.exe")
endif()

# set the correct defines for projects to compile
# using Unicode strings
function(set_msvc_unicode targets)
	foreach(target IN LISTS ${targets})
		message("-- Configuring Unicode for : ${target}")
		target_compile_definitions(${target} PUBLIC "-DUNICODE" "-D_UNICODE"
		)
	endforeach()
endfunction()

### OS level checks
if ( "${CMAKE_SIZEOF_VOID_P}" EQUAL "8" )
	message( "-- 64 bits compiler detected" )
	set(ARCH "x64")
elseif( "${CMAKE_SIZEOF_VOID_P}" EQUAL "4" )
	message( "-- 32 bits compiler detected" )
	set(ARCH "x86")
else()
	set(ARCH "Unkown")
endif()
message("-- Configuring project for arch ${ARCH}.")

get_filename_component(src_dir		"${PROJECT_SOURCE_DIR}" 	REALPATH)
set(tinyxml_dir	"${src_dir}/tinyxml")
set(diStorm_dir	"${src_dir}/diStorm")
set(Scylla_dir	"${src_dir}/Scylla" )
set(ScyllaTest_dir	"${src_dir}/ScyllaDllTest" )
set(WTL_dir		"${src_dir}/WTL")


#### Dependencies
# tinyxml static library
message("-- Configuring : tinyxml")
file (GLOB tinyxml_files 
		"${tinyxml_dir}/*.cpp"
		"${tinyxml_dir}/*.h"
)
add_library(tinyxml ${tinyxml_files})
set_target_properties (tinyxml PROPERTIES
	FOLDER "contrib"
)

# diStorm static library
message("-- Configuring : diStorm")
file (GLOB diStorm_files 
			"${diStorm_dir}/src/*.c"
			"${diStorm_dir}/src/*.h"
			"${diStorm_dir}/include/*.h"
)
add_library(diStorm ${diStorm_files})
set_target_properties (diStorm PROPERTIES
	FOLDER "contrib"
)

#### Scylla targets
# Scylla executable
message("-- Configuring : Scylla")
file (GLOB Scylla_files 
			"${Scylla_dir}/*.cpp"
			"${Scylla_dir}/*.h"
			"${Scylla_dir}/*.ico"
			"${Scylla_dir}/*.rc"
)
list(REMOVE_ITEM Scylla_files "${Scylla_dir}/MainDll.cpp")
add_executable(Scylla ${Scylla_files})
target_link_libraries(Scylla tinyxml diStorm )
target_include_directories(Scylla PUBLIC 
	"${tinyxml_dir}/"
	"${diStorm_dir}/include"
	"${WTL_dir}/Include"
)
set_target_properties(Scylla PROPERTIES
	LINK_FLAGS "/SUBSYSTEM:WINDOWS /MANIFESTDEPENDENCY:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df'\" /DYNAMICBASE Psapi.lib Imagehlp.lib"
	FOLDER "Scylla"
)

# Scylla dll
message("-- Configuring : ScyllaDll")
file (GLOB ScyllaDll_files 
			"${Scylla_dir}/*.cpp"
			"${Scylla_dir}/*.h"
)
list(REMOVE_ITEM ScyllaDll_files "${Scylla_dir}/main.cpp")
add_library(ScyllaDll SHARED ${ScyllaDll_files})
target_link_libraries(ScyllaDll tinyxml diStorm Psapi)
target_include_directories(ScyllaDll PUBLIC 
	"${tinyxml_dir}/"
	"${diStorm_dir}/include"
	"${WTL_dir}/Include"
)
set_target_properties(ScyllaDll PROPERTIES
	OUTPUT_NAME "ScyllaDll${ARCH}"
	LINK_FLAGS "/DYNAMICBASE Psapi.lib Imagehlp.lib"
	FOLDER "Scylla"
)


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
message("-- Configuring : ScyllaDllTest")
file (GLOB ScyllaDllTest_files 
			"${ScyllaTest_dir}/ScyllaDllTest/*.cpp"
			"${ScyllaTest_dir}/ScyllaDllTest/*.h"
)
add_executable(ScyllaDllTest ${ScyllaDllTest_files})
set_target_properties (ScyllaDllTest PROPERTIES
	FOLDER "tests"
)

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
set_target_properties (ScyllaExeTest PROPERTIES
	FOLDER "tests"
	LINK_FLAGS "/SUBSYSTEM:WINDOWS"
)



# compile projects as unicode
set(unicode_targets Scylla ScyllaDll)
set_msvc_unicode(unicode_targets)