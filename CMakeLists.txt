cmake_minimum_required(VERSION 3.0)
project(Scylla)


# set the correct defines for projects to compile
# using Unicode strings
function(set_msvc_unicode targets)
	foreach(target ${targets})
		target_compile_definitions(${target} PUBLIC "-DUNICODE" "-D_UNICODE"
		)
	endforeach()
endfunction()


get_filename_component(src_dir		"${PROJECT_SOURCE_DIR}" 	REALPATH)
set(tinyxml_dir	"${src_dir}/tinyxml")
set(diStorm_dir	"${src_dir}/diStorm")
set(Scylla_dir	"${src_dir}/Scylla" )
set(WTL_dir		"${src_dir}/WTL")

# tinyxml static library
message("-- Configuring : tinyxml")
file (GLOB tinyxml_files 
		"${tinyxml_dir}/*.cpp"
		"${tinyxml_dir}/*.h"
)
add_library(tinyxml ${tinyxml_files})

# diStorm static library
message("-- Configuring : diStorm")
file (GLOB diStorm_files 
			"${diStorm_dir}/src/*.c"
			"${diStorm_dir}/src/*.h"
			"${diStorm_dir}/include/*.h"
)
add_library(diStorm ${diStorm_files})


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
)


# compile projects as unicode
set_msvc_unicode(Scylla)