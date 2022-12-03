cmake_minimum_required(VERSION 3.15)
project(cmakeTest)

add_executable(main main.cpp)

find_package(libOTe REQUIRED HINTS ${LIBOTE_HINT})


target_compile_options(main PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++14> -lpthread)

#target_link_libraries(main oc::libOTe)

target_link_libraries(main oc::libOTe)

# set any other operties like cpp version
if(APPLE)
    target_compile_options(projTemp PUBLIC
        "-std=c++17"
    )
else()
    set_target_properties(main
        PROPERTIES
            CXX_STANDARD 14
            CXX_STANDARD_REQUIRED YES
            CXX_EXTENSIONS NO
    )
endif()

if(MSVC)
    target_compile_definitions(main PUBLIC "_ENABLE_EXTENDED_ALIGNED_STORAGE")
else()
    target_compile_options(main PUBLIC -mavx)
endif()