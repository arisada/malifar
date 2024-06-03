cmake_minimum_required (VERSION 3.8)

if(CMAKE_VERSION VERSION_GREATER 3.13.0)
	cmake_policy(SET CMP0078 NEW)
	cmake_policy(SET CMP0086 NEW)
endif()

# Specify search path for CMake modules to be loaded by include()
# and find_package()
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

project (hap C CXX)

find_package(OpenSSL REQUIRED)
include(DefinePlatformDefaults)
if (BSD OR SOLARIS OR OSX)
    find_package(Argp REQUIRED)
endif (BSD OR SOLARIS OR OSX)

# swig required stuff
find_package(SWIG REQUIRED)
include(UseSWIG)
find_package(Python3 REQUIRED COMPONENTS Interpreter Development.Module)
list(APPEND CMAKE_SWIG_FLAGS "-py3" "-DPY3")

#message ("Directories: " ${Python_FOUND} ${Python_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})
add_library(hap-c libhap.c)
set_property(TARGET hap-c PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(hap-c ${OPENSSL_CRYPTO_LIBRARY})

#add_executable(hap-dump hap-dump.c)
#target_link_libraries(hap-dump hap-c ${ARGP_LIBRARY})

#add_executable(hap-compile hap-compile.c)
#target_link_libraries(hap-compile hap-c ${ARGP_LIBRARY})

#add_executable(hap-search hap-search.c)
#target_link_libraries(hap-search hap-c ${ARGP_LIBRARY})

set_property(SOURCE libhap.i PROPERTY INCLUDE_DIRECTORIES ${Python3_INCLUDE_DIRS})
set_property(SOURCE libhap.i PROPERTY USE_TARGET_INCLUDE_DIRECTORIES TRUE)
set_property(SOURCE libhap.i PROPERTY CPLUSPLUS ON)
swig_add_library(hap LANGUAGE python SOURCES libhap.i)
target_include_directories(hap PRIVATE ${Python3_INCLUDE_DIRS})
set_property(TARGET hap PROPERTY SWIG_INCLUDE_DIRECTORIES ${Python3_INCLUDE_DIRS})
if(APPLE AND ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU"))
  set_target_properties(hap PROPERTIES LINK_FLAGS "-undefined dynamic_lookup")
endif()

target_include_directories(hap PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(hap PRIVATE hap-c)
