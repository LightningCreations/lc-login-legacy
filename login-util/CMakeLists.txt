

add_library(login-util STATIC login-util.c login-util.h)

target_include_directories(login-util PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(login-util OpenSSL::Crypto)

foreach(hash ${LCLOGIN_SUPPORTED_HASH_FNS})
    target_compile_definitions(login-util PRIVATE
            LCLOGIN_HASH_SUPPORTED_${hash})
endforeach()
