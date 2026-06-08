cmake_minimum_required(VERSION 3.15)
project(WiFiDriver LANGUAGES C CXX)

# wfb (wifibroadcast) mode is optional: it needs libsodium + (on Android) the JNI/log libs.
# OFF by default so the core libusb driver + Station L2 build standalone on any host.
option(WIFIDRIVER_WITH_WFB "Build the wfb-ng (wifibroadcast) mode (needs libsodium)" OFF)

if(WIN32 AND DEFINED ENV{VCPKG_ROOT} AND NOT "$ENV{VCPKG_ROOT}" STREQUAL "")
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(libusb REQUIRED IMPORTED_TARGET libusb-1.0)

# ---------------------------------------------------------------------------
#  WiFiDriver — the universal libusb RTL8812AU driver.
#  Runs on any host; does everything via USB control/bulk transfers.
#  Contains: HAL/PHY/RF/EEPROM/IQK, USB adapter, 802.11 framing, and the
#  Station L2 (scan -> auth -> assoc -> open | WPA2 4-way + CCMP -> L2 IP pipe).
#  Does NOT contain the IP layer (DHCP/RTP/ARP), the FPV/session glue, or any
#  JNI — those live in the `devourer` repo which depends on this one.
# ---------------------------------------------------------------------------
# Explicit HAL sources — the phydm/*.c reference tables (phydm_*, halhwimg8814a_*) are kept in
# the tree for reference but NOT compiled; PhyTableLoader walks the extracted Hal8814_PhyTables.c.
set(WIFIDRIVER_HAL
    hal/Hal8812PwrSeq.c
    hal/Hal8812a_TxPwrTrack.cpp
    hal/Hal8814PwrSeq.c
    hal/Hal8821APwrSeq.c
    hal/hal8812a_fw.c
    hal/hal8814a_fw.c
    hal/hal8821a_fw.c
    hal/phydm/rtl8814a/Hal8814_PhyTables.c)
file(GLOB WIFIDRIVER_SRC CONFIGURE_DEPENDS src/*.c src/*.cpp src/crypto/*.cpp)

add_library(WiFiDriver ${WIFIDRIVER_HAL} ${WIFIDRIVER_SRC})
target_compile_features(WiFiDriver PUBLIC cxx_std_20)
target_include_directories(WiFiDriver PUBLIC hal hal/phydm/rtl8814a src)
target_link_libraries(WiFiDriver PUBLIC PkgConfig::libusb)
if(WIN32)
    target_link_libraries(WiFiDriver PUBLIC ws2_32 bcrypt)  # winsock (LQ/sockets) + CNG CSPRNG
endif()

# ---------------------------------------------------------------------------
#  wfb-ng (wifibroadcast) mode — the existing wfb path, kept verbatim.
#  Attribution: derived from svpcom/wfb-ng (GPL) + the FEC (zfex). See README.
# ---------------------------------------------------------------------------
if(WIFIDRIVER_WITH_WFB)
    add_library(wfb-ng STATIC
        wfb/wfb-ng/src/zfex.c
        wfb/wfb-ng/src/radiotap.c
        wfb/wfb-ng/src/rx.cpp
        wfb/wfb-ng/src/wifibroadcast.cpp)
    target_include_directories(wfb-ng PUBLIC wfb/wfb-ng)
    target_compile_definitions(wfb-ng PRIVATE
        __WFB_RX_SHARED_LIBRARY__
        PREINCLUDE_FILE=<${CMAKE_CURRENT_SOURCE_DIR}/wfb/wfb_log.h>
        ZFEX_UNROLL_ADDMUL_SIMD=8 ZFEX_INLINE_ADDMUL ZFEX_INLINE_ADDMUL_SIMD)

    # wfb LOGIC only (RX/TX/FEC + signal quality). The JNI bridge (WfbngLink) lives in devourer.
    add_library(WiFiDriverWfb STATIC
        wfb/RxFrame.cpp wfb/TxFrame.cpp wfb/SignalQualityCalculator.cpp)
    target_include_directories(WiFiDriverWfb PUBLIC wfb)
    target_compile_features(WiFiDriverWfb PUBLIC cxx_std_20)
    target_link_libraries(WiFiDriverWfb PUBLIC WiFiDriver wfb-ng)
endif()
