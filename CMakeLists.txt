cmake_minimum_required(VERSION 3.20)

project(ovpn2ss VERSION 0.1.1 LANGUAGES C CXX)

include(CheckCXXSourceCompiles)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(OVPN2SS_BUILD_APP "Build ovpn2ss executable" ON)
option(OVPN2SS_BUILD_TESTS "Build ovpn2ss unit tests" ON)
option(OVPN2SS_STUB_OPENVPN3 "Use openvpn3 stub headers instead of real openvpn3-core" ON)
set(OVPN2SS_OPENVPN3_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/openvpn3" CACHE PATH "Path to openvpn3-core checkout")
set(OVPN2SS_OPENVPN3_TARGET "openvpn3" CACHE STRING "CMake target or library name for openvpn3-core")

set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip)
set(LWIP_CONTRIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip-contrib/contrib-2.1.0)
set(ASIO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/asio/asio/include)

# --- lwIP library (compiled from source) ---

# Core protocol stack (from lwIP Filelists.cmake)
set(lwipcore_SRCS
    ${LWIP_DIR}/src/core/init.c
    ${LWIP_DIR}/src/core/def.c
    ${LWIP_DIR}/src/core/dns.c
    ${LWIP_DIR}/src/core/inet_chksum.c
    ${LWIP_DIR}/src/core/ip.c
    ${LWIP_DIR}/src/core/mem.c
    ${LWIP_DIR}/src/core/memp.c
    ${LWIP_DIR}/src/core/netif.c
    ${LWIP_DIR}/src/core/pbuf.c
    ${LWIP_DIR}/src/core/raw.c
    ${LWIP_DIR}/src/core/stats.c
    ${LWIP_DIR}/src/core/sys.c
    ${LWIP_DIR}/src/core/altcp.c
    ${LWIP_DIR}/src/core/altcp_alloc.c
    ${LWIP_DIR}/src/core/altcp_tcp.c
    ${LWIP_DIR}/src/core/tcp.c
    ${LWIP_DIR}/src/core/tcp_in.c
    ${LWIP_DIR}/src/core/tcp_out.c
    ${LWIP_DIR}/src/core/timeouts.c
    ${LWIP_DIR}/src/core/udp.c
)

set(lwipcore4_SRCS
    ${LWIP_DIR}/src/core/ipv4/autoip.c
    ${LWIP_DIR}/src/core/ipv4/dhcp.c
    ${LWIP_DIR}/src/core/ipv4/etharp.c
    ${LWIP_DIR}/src/core/ipv4/icmp.c
    ${LWIP_DIR}/src/core/ipv4/igmp.c
    ${LWIP_DIR}/src/core/ipv4/ip4_frag.c
    ${LWIP_DIR}/src/core/ipv4/ip4.c
    ${LWIP_DIR}/src/core/ipv4/ip4_addr.c
)

set(lwipcore6_SRCS
    ${LWIP_DIR}/src/core/ipv6/dhcp6.c
    ${LWIP_DIR}/src/core/ipv6/ethip6.c
    ${LWIP_DIR}/src/core/ipv6/icmp6.c
    ${LWIP_DIR}/src/core/ipv6/inet6.c
    ${LWIP_DIR}/src/core/ipv6/ip6.c
    ${LWIP_DIR}/src/core/ipv6/ip6_addr.c
    ${LWIP_DIR}/src/core/ipv6/ip6_frag.c
    ${LWIP_DIR}/src/core/ipv6/mld6.c
    ${LWIP_DIR}/src/core/ipv6/nd6.c
)

set(lwipapi_SRCS
    ${LWIP_DIR}/src/api/api_lib.c
    ${LWIP_DIR}/src/api/api_msg.c
    ${LWIP_DIR}/src/api/err.c
    ${LWIP_DIR}/src/api/if_api.c
    ${LWIP_DIR}/src/api/netbuf.c
    ${LWIP_DIR}/src/api/netdb.c
    ${LWIP_DIR}/src/api/netifapi.c
    ${LWIP_DIR}/src/api/sockets.c
    ${LWIP_DIR}/src/api/tcpip.c
)

add_library(lwip STATIC
    ${lwipcore_SRCS}
    ${lwipcore4_SRCS}
    ${lwipcore6_SRCS}
    ${lwipapi_SRCS}
    ${LWIP_DIR}/src/netif/ethernet.c
    ${LWIP_CONTRIB_DIR}/ports/unix/port/sys_arch.c
)

target_include_directories(lwip PUBLIC
    ${LWIP_DIR}/src/include
    ${LWIP_CONTRIB_DIR}/ports/unix/port/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

target_compile_definitions(lwip PRIVATE
    LWIP_NO_SYS=1
)

# --- ovpn2ss core library ---
add_library(ovpn2ss STATIC
    src/LwipRuntime.cpp
    src/OpenVpnTunBuilder.cpp
    src/OpenVpnClient.cpp
    src/ShadowsocksAead.cpp
    src/ShadowsocksInbound.cpp
    src/TcpRelaySession.cpp
    src/UdpRelaySession.cpp
    src/MultiInstanceManager.cpp
)

target_compile_definitions(ovpn2ss PUBLIC
    ASIO_STANDALONE
    LWIP_NO_SYS=1
)

target_include_directories(ovpn2ss PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${ASIO_DIR}
    ${LWIP_DIR}/src/include
    ${LWIP_CONTRIB_DIR}/ports/unix/port/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

if(OVPN2SS_STUB_OPENVPN3)
    message(WARNING "Building with openvpn3 stub headers. Set OVPN2SS_STUB_OPENVPN3=OFF and OVPN2SS_OPENVPN3_DIR to build against real openvpn3-core.")
    target_include_directories(ovpn2ss PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/openvpn3-stub
    )
else()
    if(NOT EXISTS "${OVPN2SS_OPENVPN3_DIR}/openvpn")
        message(FATAL_ERROR "openvpn3-core headers not found under ${OVPN2SS_OPENVPN3_DIR}. Provide OVPN2SS_OPENVPN3_DIR or enable OVPN2SS_STUB_OPENVPN3.")
    endif()
    target_sources(ovpn2ss PRIVATE
        ${OVPN2SS_OPENVPN3_DIR}/client/ovpncli.cpp
        ${OVPN2SS_OPENVPN3_DIR}/openvpn/crypto/data_epoch.cpp
    )
    target_compile_definitions(ovpn2ss PUBLIC
        OVPN2SS_REAL_OPENVPN3
        OPENVPN_EXTERNAL_TUN_FACTORY
        USE_MBEDTLS
        USE_ASIO
    )
    target_include_directories(ovpn2ss PUBLIC
        ${OVPN2SS_OPENVPN3_DIR}
        ${OVPN2SS_OPENVPN3_DIR}/client
    )
endif()

# --- mbedTLS detection (config → pkg-config → find_library fallback) ---
find_package(MbedTLS QUIET)
if(MbedTLS_FOUND)
    set(MBEDTLS_FOUND TRUE)
else()
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(MBEDTLS QUIET mbedtls)
        pkg_check_modules(MBEDCRYPTO QUIET mbedcrypto)
        pkg_check_modules(MBEDX509 QUIET mbedx509)
        if(MBEDTLS_FOUND AND MBEDCRYPTO_FOUND AND MBEDX509_FOUND)
            add_library(MbedTLS::mbedtls INTERFACE IMPORTED)
            target_link_libraries(MbedTLS::mbedtls INTERFACE PkgConfig::MBEDTLS)
            target_include_directories(MbedTLS::mbedtls INTERFACE ${MBEDTLS_INCLUDE_DIRS})
            add_library(MbedTLS::mbedcrypto INTERFACE IMPORTED)
            target_link_libraries(MbedTLS::mbedcrypto INTERFACE PkgConfig::MBEDCRYPTO)
            target_include_directories(MbedTLS::mbedcrypto INTERFACE ${MBEDCRYPTO_INCLUDE_DIRS})
            add_library(MbedTLS::mbedx509 INTERFACE IMPORTED)
            target_link_libraries(MbedTLS::mbedx509 INTERFACE PkgConfig::MBEDX509)
            target_include_directories(MbedTLS::mbedx509 INTERFACE ${MBEDX509_INCLUDE_DIRS})
            set(MBEDTLS_FOUND TRUE)
        endif()
    endif()
    if(NOT MBEDTLS_FOUND)
        find_path(MBEDTLS_INCLUDE_DIR mbedtls/ssl.h)
        find_library(MBEDTLS_LIBRARY mbedtls)
        find_library(MBEDCRYPTO_LIBRARY mbedcrypto)
        find_library(MBEDX509_LIBRARY mbedx509)
        if(MBEDTLS_INCLUDE_DIR AND MBEDTLS_LIBRARY AND MBEDCRYPTO_LIBRARY AND MBEDX509_LIBRARY)
            add_library(MbedTLS::mbedtls INTERFACE IMPORTED)
            target_include_directories(MbedTLS::mbedtls INTERFACE ${MBEDTLS_INCLUDE_DIR})
            target_link_libraries(MbedTLS::mbedtls INTERFACE ${MBEDTLS_LIBRARY})
            add_library(MbedTLS::mbedcrypto INTERFACE IMPORTED)
            target_include_directories(MbedTLS::mbedcrypto INTERFACE ${MBEDTLS_INCLUDE_DIR})
            target_link_libraries(MbedTLS::mbedcrypto INTERFACE ${MBEDCRYPTO_LIBRARY})
            add_library(MbedTLS::mbedx509 INTERFACE IMPORTED)
            target_include_directories(MbedTLS::mbedx509 INTERFACE ${MBEDTLS_INCLUDE_DIR})
            target_link_libraries(MbedTLS::mbedx509 INTERFACE ${MBEDX509_LIBRARY})
            set(MBEDTLS_FOUND TRUE)
        endif()
    endif()
    if(NOT MBEDTLS_FOUND)
        message(FATAL_ERROR "mbedTLS not found. Install libmbedtls-dev or set CMAKE_PREFIX_PATH.")
    endif()
endif()

set(CMAKE_REQUIRED_LIBRARIES MbedTLS::mbedcrypto)
check_cxx_source_compiles([[#include <mbedtls/chachapoly.h>
#include <mbedtls/hkdf.h>
int main() {
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    mbedtls_chachapoly_free(&ctx);
    return 0;
}]] OVPN2SS_MBEDTLS_AEAD_OK)
if(NOT OVPN2SS_MBEDTLS_AEAD_OK)
    message(FATAL_ERROR "mbedTLS must provide chachapoly and HKDF APIs. Enable MBEDTLS_CHACHAPOLY_C, MBEDTLS_HKDF_C, MBEDTLS_MD_C, and MBEDTLS_MD5_C.")
endif()

target_link_libraries(ovpn2ss PUBLIC
    lwip
    MbedTLS::mbedtls
    MbedTLS::mbedcrypto
    MbedTLS::mbedx509
)

if(OVPN2SS_BUILD_APP)
    add_executable(ovpn2ss_app src/main.cpp)
    target_link_libraries(ovpn2ss_app PRIVATE ovpn2ss)
endif()

if(OVPN2SS_BUILD_TESTS)
    enable_testing()
    add_executable(ovpn2ss_unit_tests tests/unit_tests.cpp)
    target_link_libraries(ovpn2ss_unit_tests PRIVATE ovpn2ss)
    add_test(NAME ovpn2ss_unit_tests COMMAND ovpn2ss_unit_tests)
endif()
