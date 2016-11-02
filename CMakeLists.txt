cmake_minimum_required(VERSION 3.0)
project(Scylla)

#  Global properties for VS project to use folders
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

enable_testing()

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
add_executable(Scylla ${Scylla_files})
target_link_libraries(Scylla tinyxml diStorm)
target_include_directories(Scylla PUBLIC 
	"${tinyxml_dir}/"
	"${diStorm_dir}/include"
	"${WTL_dir}/Include"
)
set_target_properties(Scylla PROPERTIES
	LINK_FLAGS "/SUBSYSTEM:WINDOWS /MANIFESTDEPENDENCY:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df'\""
	FOLDER "Scylla"
)

# Scylla dll
message("-- Configuring : ScyllaDll")
file (GLOB ScyllaDll_files 
			"${Scylla_dir}/*.cpp"
			"${Scylla_dir}/*.h"
)
add_library(ScyllaDll SHARED ${ScyllaDll_files})
target_link_libraries(ScyllaDll tinyxml diStorm)
target_include_directories(ScyllaDll PUBLIC 
	"${tinyxml_dir}/"
	"${diStorm_dir}/include"
	"${WTL_dir}/Include"
)
set_target_properties(ScyllaDll PROPERTIES
	OUTPUT_NAME "ScyllaDll${ARCH}"
	FOLDER "Scylla"
)

#### Scylla tests
# ScyllaDllTest
add_executable(ScyllaDllTest "${ScyllaTest_dir}/ScyllaDllTest/Source.cpp")
set_target_properties (ScyllaDllTest PROPERTIES
	FOLDER "tests"
)

add_test( TestScyllaDllTest ScyllaDllTest)

# ScyllaExeTest
add_executable(ScyllaExeTest "${ScyllaTest_dir}/ScyllaTestExe/main.cpp")
set_target_properties (ScyllaExeTest PROPERTIES
	FOLDER "tests"
	LINK_FLAGS "/SUBSYSTEM:WINDOWS"
)


# compile projects as unicode
set(unicode_targets Scylla ScyllaDll)
set_msvc_unicode(unicode_targets)