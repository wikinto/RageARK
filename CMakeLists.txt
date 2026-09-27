cmake_minimum_required(VERSION 3.19)
project(rageark VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(ECM REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})
# install next to Ark's own plugins ($QT_PLUGIN_DIR/kerfuffle)
set(QT_MAJOR_VERSION 6)
set(KDE_INSTALL_USE_QT_SYS_PATHS ON CACHE BOOL "Install plugins into Qt's plugin directory")
include(KDEInstallDirs6)
include(KDECMakeSettings)

# must be set after the KDE includes (they reset output directories)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

find_package(Qt6 6.6 REQUIRED COMPONENTS Core Gui Widgets)
find_package(KF6 REQUIRED COMPONENTS CoreAddons I18n FileMetaData Config)
find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)

# Ark does not install kerfuffle headers; 3rdparty/kerfuffle vendors the ones
# we need from the installed Ark release. The library itself is found by file
# name because distros install it with NAMELINK_SKIP (no plain .so symlink).
find_library(KERFUFFLE_LIBRARY
    NAMES libkerfuffle.so.25 libkerfuffle.so.26 libkerfuffle.so.27
    REQUIRED)

# CodeWalker's magic.dat (never committed); installed next to the plugin data.
set(RAGEARK_MAGIC_DAT "" CACHE FILEPATH "CodeWalker magic.dat to install")
set(RAGEARK_MAGIC_DAT_INSTALL_PATH "${KDE_INSTALL_FULL_DATADIR}/rageark/magic.dat")

add_library(rageark_core STATIC
    src/librageark/bytes.cpp
    src/librageark/deflate.cpp
    src/librageark/rpf.cpp
    src/librageark/keys.cpp
    src/librageark/keystore.cpp
    src/librageark/awc.cpp
    src/librageark/ytd.cpp
    src/librageark/rpfedit.cpp
)
target_include_directories(rageark_core PUBLIC src/librageark)
target_compile_definitions(rageark_core PRIVATE RAGEARK_MAGIC_DAT_INSTALL_PATH="${RAGEARK_MAGIC_DAT_INSTALL_PATH}")
set_target_properties(rageark_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(rageark_core PUBLIC Qt6::Core ZLIB::ZLIB OpenSSL::Crypto)

kcoreaddons_add_plugin(kerfuffle_rageark
    SOURCES src/plugin/ragearkplugin.cpp src/plugin/exepickerquery.cpp
    INSTALL_NAMESPACE kerfuffle)
target_include_directories(kerfuffle_rageark PRIVATE src/plugin 3rdparty/kerfuffle)
target_compile_definitions(kerfuffle_rageark PRIVATE TRANSLATION_DOMAIN="rageark")
target_link_libraries(kerfuffle_rageark
    PRIVATE
        rageark_core
        Qt6::Core Qt6::Gui Qt6::Widgets
        KF6::CoreAddons KF6::I18n KF6::FileMetaData KF6::ConfigCore
        ${KERFUFFLE_LIBRARY})

install(FILES mime/x-rockstar-rpf.xml
        DESTINATION ${KDE_INSTALL_MIMEDIR})
if(RAGEARK_MAGIC_DAT)
    install(FILES ${RAGEARK_MAGIC_DAT} DESTINATION ${KDE_INSTALL_DATADIR}/rageark)
endif()
