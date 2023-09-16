cmake_minimum_required(VERSION 3.22.1)
project(bcrypt-tcl VERSION 1.0.0 LANGUAGES C)

set(TARGET bcrypt-tcl)
set(CMAKE_C_STANDARD   11)
set(CMAKE_C_STANDARD_REQUIRED true)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

#set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_C_FLAGS  "-DTCL_THREADS -DVERSION=${PROJECT_VERSION} ${CMAKE_C_FLAGS}")

enable_testing()
add_test(NAME AllUnitTests COMMAND tclsh ${CMAKE_CURRENT_SOURCE_DIR}/tests/all.tcl ${CMAKE_CURRENT_BINARY_DIR})

add_library(bcrypt-tcl MODULE
        src/library.c
        src/bcrypt/bcrypt.c
        src/bcrypt/crypt_blowfish/crypt_blowfish.c
        src/bcrypt/crypt_blowfish/x86.S
        src/bcrypt/crypt_blowfish/crypt_gensalt.c
        src/bcrypt/crypt_blowfish/wrapper.c
)
set_target_properties(bcrypt-tcl PROPERTIES POSITION_INDEPENDENT_CODE ON)

if (NOT TCL_INCLUDE_PATH OR NOT TCL_LIBRARY)
    include(${CMAKE_CURRENT_LIST_DIR}/FindTCL.cmake)
endif ()

include_directories(${TCL_INCLUDE_PATH})
target_link_libraries(bcrypt-tcl PRIVATE ${TCL_LIBRARY})
get_filename_component(TCL_LIBRARY_PATH "${TCL_LIBRARY}" PATH)

install(TARGETS ${TARGET}
        LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/${TARGET}${PROJECT_VERSION}
)

configure_file(pkgIndex.tcl.in pkgIndex.tcl @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pkgIndex.tcl
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/${TARGET}${PROJECT_VERSION}
)
