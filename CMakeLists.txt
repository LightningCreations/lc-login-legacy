cmake_minimum_required(VERSION 3.15)
project(lc_login C)

set(CMAKE_C_STANDARD 11)

include(GNUInstallDirs)

set(LCLOGIN_USERS_ROOT "users" CACHE PATH "The path to the users information directory. Relative paths are to CMAKE_INSTALL_SYSCONFDIR")
set(LCLOGIN_GROUPS_ROOT "groups" CACHE PATH "The path to the groups information directory. Relative paths are to CMAKE_INSTALL_SYSCONFDIR")

set(LCLOGIN_LEGACY_PASSWD "passwd" CACHE FILEPATH "The path to the legacy passwd file to keep in sync with lc-login. Path is relative to CMAKE_INSTALL_SYSCONFDIR")
set(LCLOGIN_LEGACY_GROUP "group" CACHE FILEPATH "The path to the legacy group file to keep in sync with lc-login. Path is relative to CMAKE_INSTALL_SYSCONFDIR")
set(LCLOGIN_LEGACY_SHADOW "shadow" CACHE FILEPATH "The path to the legacy shadow file to keep in sync with lc-login. Path is relative to CMAKE_INSTALL_SYSCONFDIR")
set(LCLOGIN_LEGACY_GSHADOW "gshadow" CACHE FILEPATH "The path to the legacy gshadow file to keep in sync with lc-login. Path is relative to CMAKE_INSTALL_SYSCONFDIR")
set(LCLOGIN_LEGACY_SUDOERS "sudoers" CACHE FILEPATH "The path to the legacy sudoers file to keep in sync with lc-login. Path is relative to CMAKE_INSTALL_SYSCONFDIR")

if(IS_ABSOLUTE LCLOGIN_LEGACY_PASSWD)
    set(LCLOGIN_FULL_LEGACY_PASSWD ${LCLOGIN_LEGACY_PASSWD})
else()
    set(LCLOGIN_FULL_LEGACY_PASSWD ${CMAKE_INSTALL_FULL_SYSCONFDIR}/${LCLOGIN_LEGACY_PASSWD})
endif()

if(IS_ABSOLUTE LCLOGIN_LEGACY_GROUP)
    set(LCLOGIN_FULL_LEGACY_GROUP ${LCLOGIN_LEGACY_GROUP})
else()
    set(LCLOGIN_FULL_LEGACY_GROUP ${CMAKE_INSTALL_FULL_SYSCONFDIR}/${LCLOGIN_LEGACY_GROUP})
endif()


if(IS_ABSOLUTE LCLOGIN_LEGACY_SHADOW)
    set(LCLOGIN_FULL_LEGACY_SHADOW ${LCLOGIN_LEGACY_SHADOW})
else()
    set(LCLOGIN_FULL_LEGACY_SHADOW ${CMAKE_INSTALL_FULL_SYSCONFDIR}/${LCLOGIN_LEGACY_SHADOW})
endif()


if(IS_ABSOLUTE LCLOGIN_LEGACY_GSHADOW)
    set(LCLOGIN_FULL_LEGACY_GSHADOW ${LCLOGIN_LEGACY_GSHADOW})
else()
    set(LCLOGIN_FULL_LEGACY_GSHADOW ${CMAKE_INSTALL_FULL_SYSCONFDIR}/${LCLOGIN_LEGACY_GSHADOW})
endif()

if(IS_ABSOLUTE LCLOGIN_LEGACY_SUDOERS)
    set(LCLOGIN_FULL_LEGACY_SUDOERS ${LCLOGIN_LEGACY_GROUP})
else()
    set(LCLOGIN_FULL_LEGACY_SUDOERS ${CMAKE_INSTALL_FULL_SYSCONFDIR}/${LCLOGIN_LEGACY_SUDOERS})
endif()


if(IS_ABSOLUTE LCLOGIN_USERS_ROOT)
    set(LCLOGIN_FULL_USERS_ROOT ${LCLOGIN_USERS_ROOT})
else()
    set(LCLOGIN_FULL_USERS_ROOT ${CMAKE_INSTALL_FULL_SYSCONFDIR}/${LCLOGIN_USERS_ROOT})
endif()

if(IS_ABSOLUTE LCLOGIN_GROUPS_ROOT)
    set(LCLOGIN_FULL_GROUPS_ROOT ${LCLOGIN_GROUPS_ROOT})
else()
    set(LCLOGIN_FULL_GROUPS_ROOT ${CMAKE_INSTALL_FULL_SYSCONFDIR}/${LCLOGIN_GROUPS_ROOT})
endif()

install(DIRECTORY DESTINATION ${LCLOGIN_FULL_GROUPS_ROOT})
install(DIRECTORY DESTINATION ${LCLOGIN_FULL_USERS_ROOT})



option(LCNIX_MAN_PAGES "Enable man pages for lcnix projects" ON)

if(TARGET help2man)
    set(HELP2MAN help2man)
elseif(LCNIX_MAN_PAGES)
    message(CHECK_START "Searching for help2man")
    find_program(HELP2MAN help2man HINTS /usr/bin /usr/local/bin)
    if(HELP2MAN STREQUAL "HELP2MAN-NOTFOUND")
        message(CHECK_FAIL "Not Found")
    else()
        message(CHECK_PASS ${HELP2MAN})
    endif()
endif()

function(add_manual prg description section)
    if(NOT TARGET ${prg})
        message(FATAL_ERROR "${prg} is not an executable target")
    endif()
    get_target_property(type ${prg} TYPE)
    if(NOT ${type} STREQUAL "EXECUTABLE")
        message(FATAL_ERROR "${prg} is not an executable target")
    endif()
    if(NOT LCNIX_MAN_PAGES AND NOT ${HELP2MAN} STREQUAL "HELP2MAN-NOTFOUND")
        add_custom_command(
                OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${prg}.${section}
                COMMAND ${HELP2MAN} --section=${section}
                "--source=Lightning Creations"
                --output=${CMAKE_CURRENT_BINARY_DIR}/${prg}.${section}
                --no-info
                "--name=${description}"
                $<TARGET_FILE:${prg}>
                COMMENT "Building Manual in Section ${section} for ${prg}"
                DEPENDS ${prg}
        )
        add_custom_target(man-page-${prg}
                ALL
                DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${prg}.${section})
        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${prg}.${section}
                DESTINATION ${CMAKE_INSTALL_MANDIR}/man${section})
    endif()
endfunction()



message(CHECK_START "Searching for libcrypto")

find_package(OpenSSL REQUIRED)

if(OPENSSL_FOUND)
    message(CHECK_PASS "Found")
else()
    message(CHECK_FAIL "Not Found")
endif()




set(LCLOGIN_KNOWN_HASH_FNS "sha512;sha384;sha256;sha224;sha3_512;sha3_384;sha3_256;sha3_224")

set(_LCLOGIN_SUPPORTED_HASH_FNS "")

macro(check_libcrypto_hashfn hash)
    message(CHECK_START "Checking if libcrypto supports ${hash}")
    try_compile(
            _WORKS ${CMAKE_CURRENT_BINARY_DIR}/tests/${hash}
            ${CMAKE_CURRENT_SOURCE_DIR}/check_libcrypto_hash_fn.c
            COMPILE_DEFINITIONS "-DINIT_HASH_FN=EVP_${hash}"
            LINK_LIBRARIES OpenSSL::Crypto
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
    )
    if(_WORKS)
        message(CHECK_PASS "yes")
        list(APPEND _LCLOGIN_SUPPORTED_HASH_FNS ${hash})
    else()
        message(CHECK_PASS "no")
    endif()
endmacro()

if(OPENSSL_FOUND)
    message(CHECK_START "Checking hash algorithms supported by libcrypto")
    list(APPEND CMAKE_MESSAGE_INDENT "  ")
    if(NOT LCLOGIN_SUPPORTED_HASH_FNS)
        foreach(hash ${LCLOGIN_KNOWN_HASH_FNS})
            check_libcrypto_hashfn(${hash})
        endforeach()
        set(LCLOGIN_SUPPORTED_HASH_FNS ${_LCLOGIN_SUPPORTED_HASH_FNS} CACHE INTERNAL "")
    endif()
    list(POP_BACK CMAKE_MESSAGE_INDENT)
    if(NOT LCLOGIN_SUPPORTED_HASH_FNS)
        message(CHECK_FAIL "None known")
    else()
        list(JOIN LCLOGIN_SUPPORTED_HASH_FNS ", " _LCLOGIN_JOINED_SUPPORTED_HASH_FNS)
        message(CHECK_PASS "${_LCLOGIN_JOINED_SUPPORTED_HASH_FNS}")
    endif()
    if(NOT LCLOGIN_DEFAULT_PASSWD_HASH)
        list(GET LCLOGIN_SUPPORTED_HASH_FNS 0 LCLOGIN_INIT_DEFAULT_PASSWD_HASH)
        set(LCLOGIN_DEFAULT_PASSWD_HASH ${LCLOGIN_INIT_DEFAULT_PASSWD_HASH} CACHE STRING "The default algorithm to use for hashing login passwords")
    endif()
    message(STATUS "Default Hash Algorithm: ${LCLOGIN_DEFAULT_PASSWD_HASH}")
endif()

configure_file(login-variables.h.in login-variables.h)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(login-util)


add_subdirectory(login)



