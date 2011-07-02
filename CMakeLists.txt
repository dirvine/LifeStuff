# ============================================================================ #
#                                                                              #
# Copyright [2010] maidsafe.net limited                                        #
#                                                                              #
# Description:  CMakeList for LifeStuff project.                               #
# Version:      1.0                                                            #
# Created:      2010-04-15-21.01.30                                            #
# Revision:     none                                                           #
# Compiler:     N/A                                                            #
# Author:       Team                                                           #
# Company:      maidsafe.net limited                                           #
#                                                                              #
# The following source code is property of maidsafe.net limited and is not     #
# meant for external use.  The use of this code is governed by the license     #
# file LICENSE.TXT found in the root of this directory and also on             #
# www.maidsafe.net.                                                            #
#                                                                              #
# You are not free to copy, amend or otherwise use this source code without    #
# the explicit written permission of the board of directors of maidsafe.net.   #
#                                                                              #
# ============================================================================ #


CMAKE_MINIMUM_REQUIRED(VERSION 2.8 FATAL_ERROR)
MESSAGE("================================================================================\n")

SET(ERROR_MESSAGE_CMAKE_PATH "cmake ../../..")
GET_FILENAME_COMPONENT(CMAKE_BUILD_TYPE_DIR ${CMAKE_BINARY_DIR} NAME)

# Variable MSVC is not set until after PROJECT command below
IF(CMAKE_BUILD_TYPE_DIR MATCHES "Win_MSVC")
  SET(CMAKE_BUILD_TYPE_DIR Release)
  SET(ERROR_MESSAGE_CMAKE_PATH "   cmake ..\\..")
ELSEIF(CMAKE_BUILD_TYPE_DIR MATCHES "kdev")
  SET(CMAKE_BUILD_TYPE_DIR Debug)
  SET(KDEV 1)
ENDIF()

SET(ERROR_MESSAGE "No generator previously specified.\nTo see a full list of generators, run:\n\t${ERROR_MESSAGE_CMAKE_PATH} --help\n")
IF(NOT ${CMAKE_C_COMPILER_WORKS})
  MESSAGE(FATAL_ERROR ${ERROR_MESSAGE})
ENDIF()

IF((CMAKE_BUILD_TYPE_DIR MATCHES "Release") OR (DEFINED ${KDEV}))
  SET(PROJECT_NAME LifeStuff)
ELSE()
  SET(PROJECT_NAME LifeStuff_${CMAKE_BUILD_TYPE_DIR})
ENDIF()
OPTION (BUILD_SHARED_LIBS "Build shared libraries." OFF)

IF(WIN32)
  IF(${PACKAGE_BUILD})
    #Check if project open in MSVC - not allowing package build configuration if solution is open in MVSC
    FIND_FILE(PROJECT_OPENSDF_FILE NAMES  "${PROJECT_NAME}.opensdf" PATHS ${CMAKE_BINARY_DIR})
    IF(EXISTS "${PROJECT_OPENSDF_FILE}")
      MESSAGE(FATAL_ERROR "Please close the MSVC solution and run cmake again for package build")
    ENDIF()
    SET(CMAKE_CONFIGURATION_TYPES Release)
    SET(CMAKE_CONFIGURATION_TYPES ${CMAKE_CONFIGURATION_TYPES} CACHE STRING "Semicolon separated list of supported configuration types, only supports Release, anything else will be ignored." FORCE)
  ELSE()
    SET(CMAKE_CONFIGURATION_TYPES Debug Release RelWithDebInfo MinSizeRel)
    SET(CMAKE_CONFIGURATION_TYPES ${CMAKE_CONFIGURATION_TYPES} CACHE STRING "Semicolon separated list of supported configuration types, only supports Release, anything else will be ignored." FORCE)
  ENDIF()
ENDIF()

# This call resets CMAKE_BUILD_TYPE, hence it's copied from CMAKE_BUILD_TYPE_DIR which is set above.
PROJECT(${PROJECT_NAME})
SET(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE_DIR} CACHE INTERNAL "Except for MSVC, the build type is set by running cmake from the appropriate build subdirectory e.g. for a Debug build, \"cd build/Linux/Debug && cmake ../../..\"." FORCE)

###################################################################################################
# MaidSafe Common, DHT, Encrypt, Passport and PKI library search                                  #
###################################################################################################
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/build)
INCLUDE(maidsafe_find_common)
ADD_MAIDSAFE_LIBRARY(MaidSafe-DHT)
ADD_MAIDSAFE_LIBRARY(Encrypt)
ADD_MAIDSAFE_LIBRARY(PKI)
ADD_MAIDSAFE_LIBRARY(Passport)

###################################################################################################
# Callback File System / Fuse library search                                                      #
###################################################################################################
IF(WIN32)
  INCLUDE(maidsafe_find_cbfs)
  SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Cbfs_INCLUDE_DIR})
  SET(LIBS_DIRS ${LIBS_DIRS} ${Cbfs_LIBRARY_DIR})
  SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Cbfs_LIBRARY_DIR})
  SET(Fuse_LIBRARY ${Cbfs_LIBRARY})
ELSE()
  FIND_LIBRARY(Fuse_LIBRARY libfuse.a)
  IF(Fuse_LIBRARY)
    MESSAGE("-- Found library ${Fuse_LIBRARY}")
    GET_FILENAME_COMPONENT(Fuse_LIBRARY_DIR ${Fuse_LIBRARY} PATH)
    SET(LIBS_DIRS ${LIBS_DIRS} ${Fuse_LIBRARY_DIR})
    SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Fuse_LIBRARY_DIR})
  ELSE()
    SET(ERROR_MESSAGE "\nCould not find library libfuse.a.")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}  Run\n${ERROR_MESSAGE_CMAKE_PATH} -DADD_LIBRARY_DIR=<Path to libfuse.a directory>")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ENDIF()
ENDIF()

###################################################################################################
# Standard setup                                                                                  #
###################################################################################################
SET(PROTO_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
FILE(GLOB_RECURSE PROTO_FILES RELATIVE ${PROTO_SOURCE_DIR} "${PROTO_SOURCE_DIR}/maidsafe/*.proto")
INCLUDE(maidsafe_standard_setup)
HANDLE_VERSIONS(${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/shared/version.h)

###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
SET(SRC_MAIDSAFE "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff")

####    CODE    ####
FILE(GLOB SOURCE_FILES_CLIENT_DIR "${SRC_MAIDSAFE}/client/*.cc")
FILE(GLOB HEADER_FILES_CLIENT_DIR "${SRC_MAIDSAFE}/client/*.h")
SET(ALL_FILES_CLIENT_DIR ${SOURCE_FILES_CLIENT_DIR} ${HEADER_FILES_CLIENT_DIR})
SET(STYLE_CLIENT ${ALL_FILES_CLIENT_DIR})
LIST(REMOVE_ITEM STYLE_CLIENT "${SRC_MAIDSAFE}/client/lifestuff_messages.pb.h" "${SRC_MAIDSAFE}/client/lifestuff_messages.pb.cc")
SET(ALL_FILES_LOCALSTOREMANAGER_CLIENT_DIR ${ALL_FILES_CLIENT_DIR})
LIST(REMOVE_ITEM ALL_FILES_LOCALSTOREMANAGER_CLIENT_DIR "${SRC_MAIDSAFE}/client/clientrpc.cc")
LIST(REMOVE_ITEM ALL_FILES_LOCALSTOREMANAGER_CLIENT_DIR "${SRC_MAIDSAFE}/client/clientrpc.h")
SOURCE_GROUP("client Source Files" FILES ${SOURCE_FILES_CLIENT_DIR})
SOURCE_GROUP("client Header Files" FILES ${HEADER_FILES_CLIENT_DIR})

FILE(GLOB SOURCE_FILES_CLIENT_FILESYSTEM_DIR "${SRC_MAIDSAFE}/client/filesystem/*.cc")
FILE(GLOB HEADER_FILES_CLIENT_FILESYSTEM_DIR "${SRC_MAIDSAFE}/client/filesystem/*.h")
SET(ALL_FILES_CLIENT_FILESYSTEM_DIR ${SOURCE_FILES_CLIENT_FILESYSTEM_DIR} ${HEADER_FILES_CLIENT_FILESYSTEM_DIR})
SET(STYLE_CLIENT_FILESYSTEM ${ALL_FILES_CLIENT_FILESYSTEM_DIR})
SOURCE_GROUP("client filesystem Source Files" FILES ${SOURCE_FILES_CLIENT_FILESYSTEM_DIR})
SOURCE_GROUP("client filesystem Header Files" FILES ${HEADER_FILES_CLIENT_FILESYSTEM_DIR})

FILE(GLOB SOURCE_FILES_SHARED_DIR "${SRC_MAIDSAFE}/shared/*.cc" "${SRC_MAIDSAFE}/shared/sqlite3.c")
FILE(GLOB HEADER_FILES_SHARED_DIR "${SRC_MAIDSAFE}/shared/*.h")
SET(ALL_FILES_SHARED_DIR ${SOURCE_FILES_SHARED_DIR} ${HEADER_FILES_SHARED_DIR})
SET(STYLE_SHARED ${ALL_FILES_SHARED_DIR})
LIST(REMOVE_ITEM STYLE_SHARED "${SRC_MAIDSAFE}/shared/sqlite3.h")

SOURCE_GROUP("shared Source Files" FILES ${SOURCE_FILES_SHARED_DIR})
SOURCE_GROUP("shared Header Files" FILES ${HEADER_FILES_SHARED_DIR})

IF(WIN32)
  FILE(GLOB SOURCE_FILES_FUSE_DIR "${SRC_MAIDSAFE}/fuse/windows/*.cc")
  FILE(GLOB HEADER_FILES_FUSE_DIR "${SRC_MAIDSAFE}/fuse/windows/*.h")
ELSE()
  FILE(GLOB SOURCE_FILES_FUSE_DIR "${SRC_MAIDSAFE}/fuse/linux/*.cc")
  FILE(GLOB HEADER_FILES_FUSE_DIR "${SRC_MAIDSAFE}/fuse/linux/*.h")
ENDIF()
SET(ALL_FILES_FUSE_DIR ${SOURCE_FILES_FUSE_DIR};${HEADER_FILES_FUSE_DIR})
SET(STYLE_FUSE ${ALL_FILES_FUSE_DIR})
SOURCE_GROUP("fuse Source Files" FILES ${SOURCE_FILES_FUSE_DIR})
SOURCE_GROUP("fuse Header Files" FILES ${HEADER_FILES_FUSE_DIR})

####    TESTS    ####
FILE(GLOB ALL_FILES_CLIENT_TESTS_DIR "${SRC_MAIDSAFE}/client/tests/*.cc" "${SRC_MAIDSAFE}/client/tests/*.h")
LIST(REMOVE_ITEM ALL_FILES_CLIENT_TESTS_DIR "${SRC_MAIDSAFE}/client/tests/client_main.cc")
LIST(REMOVE_ITEM ALL_FILES_CLIENT_TESTS_DIR "${SRC_MAIDSAFE}/client/tests/testclientcontroller.cc")
LIST(REMOVE_ITEM ALL_FILES_CLIENT_TESTS_DIR "${SRC_MAIDSAFE}/client/tests/testimmessaging.cc")
LIST(REMOVE_ITEM ALL_FILES_CLIENT_TESTS_DIR "${SRC_MAIDSAFE}/client/tests/testauthentication.cc")

FILE(GLOB ALL_FILES_CLIENT_FILESYSTEM_TESTS_DIR "${SRC_MAIDSAFE}/client/filesystem/tests/*.cc" "${SRC_MAIDSAFE}/client/filesystem/tests/*.h")

#FILE(GLOB ALL_FILES_SHARED_TESTS_DIR "${SRC_MAIDSAFE}/shared/tests/*.cc" "${SRC_MAIDSAFE}/shared/tests/*.h")
#LIST(REMOVE_ITEM ALL_FILES_SHARED_TESTS_DIR "${SRC_MAIDSAFE}/shared/tests/testbufferpackethandler.cc")

FILE(GLOB ALL_FILES_FUSE_TESTS_DIR "${SRC_MAIDSAFE}/fuse/tests/*.cc" "${SRC_MAIDSAFE}/fuse/tests/*.h")

SET(NETWORK_TEST_FILES "${SRC_MAIDSAFE}/sharedtest/tests_main.cc")

FILE(GLOB ALL_FILES_CLIENT_DEMO_DIR "${SRC_MAIDSAFE}/client/tests/demo/*.cc"
                                    "${SRC_MAIDSAFE}/client/tests/demo/*.h")

###################################################################################################
# All Platforms:  Add exes and Create all LifeStuff libs                                          #
###################################################################################################

ADD_EXECUTABLE(ClientDemo ${ALL_FILES_CLIENT_DEMO_DIR})


SET(LOCAL_SYSTEM_TEST_TIMEOUT 1800)
SET(NETWORK_SYSTEM_TEST_TIMEOUT 3600)

# ADD_EXECUTABLE(TESTshared
#                  ${ALL_FILES_SHARED_TESTS_DIR}
#                  "${SRC_MAIDSAFE}/sharedtest/cached_keys.h"
#                  "${SRC_MAIDSAFE}/sharedtest/chunkstoreops.h"
#                  "${SRC_MAIDSAFE}/sharedtest/mockkadops.cc"
#                  "${SRC_MAIDSAFE}/sharedtest/mockkadops.h"
#                  "${SRC_MAIDSAFE}/sharedtest/testcallback.h"
#                  "${SRC_MAIDSAFE}/sharedtest/threadpool.cc"
#                  "${SRC_MAIDSAFE}/sharedtest/threadpool.h"
#                  "${SRC_MAIDSAFE}/sharedtest/tests_main.cc")
ADD_EXECUTABLE(TESTclientfilesystem
                 ${ALL_FILES_CLIENT_FILESYSTEM_TESTS_DIR}
                 "${SRC_MAIDSAFE}/sharedtest/cachepassport.h"
                 "${SRC_MAIDSAFE}/sharedtest/testcallback.h"
                 "${SRC_MAIDSAFE}/sharedtest/tests_main.cc")
ADD_EXECUTABLE(TESTclient
                  ${ALL_FILES_CLIENT_TESTS_DIR}
                  ${NETWORK_TEST_FILES}
                  "${SRC_MAIDSAFE}/sharedtest/cached_keys.h"
                  "${SRC_MAIDSAFE}/sharedtest/cachepassport.h"
                  "${SRC_MAIDSAFE}/sharedtest/mocksessionsingleton.h")

ADD_EXECUTABLE(TESTfuse EXCLUDE_FROM_ALL
                 ${ALL_FILES_FUSE_TESTS_DIR})
ADD_EXECUTABLE(TESTauthentication_net
                 ${NETWORK_TEST_FILES}
                 "${SRC_MAIDSAFE}/client/tests/testauthentication.cc")
# ADD_EXECUTABLE(TESTbufferpackethandler_net
#                  ${NETWORK_TEST_FILES}
#                  "${SRC_MAIDSAFE}/sharedtest/cached_keys.h"
#                  "${SRC_MAIDSAFE}/shared/tests/testbufferpackethandler.cc")
# ADD_EXECUTABLE(TESTclientcontroller_net
#                  ${NETWORK_TEST_FILES}
#                  "${SRC_MAIDSAFE}/sharedtest/mockclientcontroller.h"
#                  "${SRC_MAIDSAFE}/sharedtest/mocksessionsingleton.h"
#                  "${SRC_MAIDSAFE}/client/tests/testclientcontroller.cc")
ADD_EXECUTABLE(TESTclientcontroller_local
                 ${NETWORK_TEST_FILES}
                 "${SRC_MAIDSAFE}/sharedtest/mockclientcontroller.h"
                 "${SRC_MAIDSAFE}/sharedtest/mocksessionsingleton.h"
                 "${SRC_MAIDSAFE}/client/tests/testclientcontroller.cc")
# ADD_EXECUTABLE(TESTimconnectionhandler_net
#                  ${NETWORK_TEST_FILES}
#                  "${SRC_MAIDSAFE}/client/tests/testimconnhandler.cc"
#                  "${SRC_MAIDSAFE}/client/tests/testimmessaging.cc")

# ADD_EXECUTABLE(DEMOclient
#                  "${SRC_MAIDSAFE}/client/tests/client_main.cc")

# SET(ALL_EXECUTABLES lifestuff lslocal lslightlocal TESTshared TESTclientfilesystem TESTclientcontroller_local TESTfuse)
SET(ALL_EXECUTABLES TESTclient TESTauthentication_net TESTclientfilesystem TESTclientcontroller_local TESTfuse ClientDemo)
RENAME_EXECUTABLE(ClientDemo)
#RENAME_EXECUTABLE(TESTshared)
RENAME_EXECUTABLE(TESTclientfilesystem)
RENAME_EXECUTABLE(TESTclient)
RENAME_EXECUTABLE(TESTfuse)
RENAME_EXECUTABLE(TESTauthentication_net)
#RENAME_EXECUTABLE(TESTbufferpackethandler_net)
#RENAME_EXECUTABLE(TESTclientcontroller_net)
RENAME_EXECUTABLE(TESTclientcontroller_local)
#RENAME_EXECUTABLE(TESTimconnectionhandler_net)

# ADD_LIBRARY(LifeStuffclientlib STATIC ${ALL_FILES_CLIENT_DIR})
ADD_LIBRARY(LifeStufflsmclientlib STATIC ${ALL_FILES_LOCALSTOREMANAGER_CLIENT_DIR})
ADD_LIBRARY(LifeStuffclientfilesystemlib STATIC ${ALL_FILES_CLIENT_FILESYSTEM_DIR})
ADD_LIBRARY(LifeStuffsharedlib STATIC ${ALL_FILES_SHARED_DIR})
ADD_LIBRARY(LifeStufffuselib STATIC ${ALL_FILES_FUSE_DIR})

# ADD_CUSTOM_TARGET(AllTestsAndDemos DEPENDS TESTencrypt TESTshared
#                   TESTclientfilesystem TESTclient TESTfuse TESTclientcontroller_local DEMOclient)
ADD_CUSTOM_TARGET(AllTestsAndDemos DEPENDS TESTclientfilesystem TESTfuse TESTclientcontroller_local TESTclient TESTauthentication_net)

IF(UNIX)
  TARGET_LINK_LIBRARIES(LifeStuffsharedlib passport_static boost_filesystem dl)
ELSE()
  TARGET_LINK_LIBRARIES(LifeStuffsharedlib passport_static boost_filesystem)
ENDIF()
TARGET_LINK_LIBRARIES(LifeStuffclientfilesystemlib LifeStuffsharedlib encrypt_static pki_static boost_date_time)
TARGET_LINK_LIBRARIES(LifeStufflsmclientlib LifeStuffclientfilesystemlib ${QT_LIBRARIES} boost_regex)
TARGET_LINK_LIBRARIES(LifeStufffuselib ${Fuse_LIBRARY} boost_system)
# TARGET_LINK_LIBRARIES(TESTshared LifeStuffsharedlib boost_date_time gtest_static gmock_static)
TARGET_LINK_LIBRARIES(TESTclientfilesystem LifeStufflsmclientlib gtest_static)
TARGET_LINK_LIBRARIES(TESTclient LifeStufflsmclientlib gtest_static gmock_static)
TARGET_LINK_LIBRARIES(TESTfuse LifeStufffuselib gtest_static)
TARGET_LINK_LIBRARIES(TESTauthentication_net LifeStufflsmclientlib gtest_static)
# TARGET_LINK_LIBRARIES(TESTbufferpackethandler_net LifeStuffclientlib gtest_static)
# TARGET_LINK_LIBRARIES(TESTclientcontroller_net LifeStuffclientlib gtest_static)
TARGET_LINK_LIBRARIES(TESTclientcontroller_local LifeStufflsmclientlib gtest_static)
# TARGET_LINK_LIBRARIES(TESTimconnectionhandler_net LifeStuffclientlib gtest_static)
# TARGET_LINK_LIBRARIES(DEMOclient LifeStuffclientlib)
TARGET_LINK_LIBRARIES(ClientDemo LifeStuffclientfilesystemlib LifeStufflsmclientlib)

###################################################################################################
# Builds                                                                                          #
###################################################################################################
INCLUDE(maidsafe_standard_flags)

SET_TARGET_PROPERTIES(LifeStufflsmclientlib PROPERTIES COMPILE_FLAGS -DLOCAL_LifeStuffVAULT)
# SET_TARGET_PROPERTIES(TESTauthentication_net PROPERTIES COMPILE_FLAGS -DMS_NETWORK_TEST)
# SET_TARGET_PROPERTIES(TESTbufferpackethandler_net PROPERTIES COMPILE_FLAGS -DMS_NETWORK_TEST)
SET_TARGET_PROPERTIES(TESTclientcontroller_local PROPERTIES COMPILE_FLAGS -DLOCAL_LifeStuffVAULT)
# SET_TARGET_PROPERTIES(TESTclientcontroller_net PROPERTIES COMPILE_FLAGS -DMS_NETWORK_TEST)
# SET_TARGET_PROPERTIES(TESTimconnectionhandler_net PROPERTIES COMPILE_FLAGS -DMS_NETWORK_TEST)
IF(UNIX)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DQT_NO_DEBUG_OUTPUT -DQT_NO_WARNING_OUTPUT -DQT_NO_DEBUG_STREAM")
  SET_SOURCE_FILES_PROPERTIES(${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/client/filesystem/distributed_filesystem.pb.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/client/lifestuff_messages.pb.cc
                              PROPERTIES COMPILE_FLAGS "-w")

ELSEIF(MSVC)
  # Disabling C4512 'assignment operator could not be generated' caused by boost signals2 as per advice at http://lists.boost.org/boost-users/2009/01/44368.php
  # Also disabling C4503 'decorated name length exceeded' caused by boost multi-index's and others' high template depth.
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4512 /wd4503 /WX")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /D \"QT_NO_DEBUG_OUTPUT\" /D \"QT_NO_WARNING_OUTPUT\" /D \"QT_NO_DEBUG_STREAM\"")
  SET_SOURCE_FILES_PROPERTIES(${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/client/filesystem/distributed_filesystem.pb.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/client/lifestuff_messages.pb.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/shared/cppsqlite3.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/shared/sqlite3.c
                              PROPERTIES COMPILE_FLAGS "/W0")
  SET_TARGET_PROPERTIES(${ALL_EXECUTABLES} PROPERTIES
                            LINK_FLAGS "/STACK:1048576"
                            LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG /INCREMENTAL:NO ${LINKER_LIBS_DIRS_RELEASE}"
                            LINK_FLAGS_DEBUG "${LINKER_LIBS_DIRS_DEBUG}"
                            LINK_FLAGS_RELWITHDEBINFO "${LINKER_LIBS_DIRS_DEBUG}"
                            LINK_FLAGS_MINSIZEREL "${LINKER_LIBS_DIRS_DEBUG}")
ENDIF()


###################################################################################################
# Tests                                                                                           #
###################################################################################################
IF(PYTHONINTERP_FOUND)
  IF(UNIX)
    SET(STYLE_ALL ${STYLE_CLIENT} ${STYLE_SHARED} ${STYLE_FUSE})
    ADD_TEST(STYLE_CHECK python ${MaidSafeCommon_TOOLS_DIR}/cpplint.py ${STYLE_ALL})
  ELSE()
    STRING(REPLACE "/" "\\\\" STYLE_CHECK_SOURCE ${PROJECT_SOURCE_DIR})
    ADD_TEST(STYLE_CHECK ${MaidSafeCommon_TOOLS_DIR}/run_cpplint.bat ${STYLE_CHECK_SOURCE} ${MaidSafeCommon_TOOLS_DIR}/cpplint.py)
  ENDIF()
  SET_PROPERTY(TEST STYLE_CHECK PROPERTY LABELS Functional CodingStyle)
ENDIF()

ADD_GTESTS(TESTclient)
ADD_GTESTS(TESTclientfilesystem)
#ADD_GTESTS(TESTshared)
ADD_GTESTS(TESTfuse)
ADD_GTESTS(TESTauthentication_net)

TEST_SUMMARY_OUTPUT()

###################################################################################################
# Install details                                                                                 #
###################################################################################################
FINAL_MESSAGE()
#Removing the previous CPackConfig.cmake & CPackSourceConfig.cmake files
FIND_FILE(CPACK_CONFIG_CMAKE_FILES NAMES  CPackConfig.cmake CPackSourceConfig.cmake PATHS ${CMAKE_BINARY_DIR})
FILE(REMOVE ${CPACK_CONFIG_CMAKE_FILES})

IF(${PACKAGE_BUILD})
  IF(CMAKE_BUILD_TYPE MATCHES "Release")
    SET(CPACK_PACKAGE_VENDOR "MaidSafe.net")
    SET(CPACK_PACKAGE_VERSION_MAJOR "0")
    SET(CPACK_PACKAGE_VERSION_MINOR "1")
    SET(CPACK_PACKAGE_VERSION_PATCH "0")
    SET(CPACK_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH})
    SET(CPACK_PACKAGE_CONTACT "support@maidsafe.net")
    SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY " LifeStuff Client")
    IF(NOT APPLE)
      SET(CPACK_RESOURCE_FILE_README "${PROJECT_SOURCE_DIR}/README")
      SET(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/licence.txt")
    ENDIF()
    SET(CPACK_PACKAGE_EXECUTABLES "ClientDemo", "Life Stuff Client")
    SET(CPACK_STRIP_FILES "true")
    IF(UNIX AND NOT APPLE)
      # Linux requires lower case package names
      SET(CPACK_PACKAGE_NAME "lifestuff_client")
      SET(CMAKE_INSTALL_PREFIX /opt/maidsafe/lifestuff)
      SET(CPACK_TOPLEVEL_TAG ${CMAKE_INSTALL_PREFIX})
      SET(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
      INSTALL(TARGETS ClientDemo RUNTIME DESTINATION .)
      INSTALL(FILES ${PROJECT_SOURCE_DIR}/installer/linux/scripts/lifestuff_client.desktop DESTINATION .)
      INSTALL(FILES ${PROJECT_SOURCE_DIR}/installer/common/icons/WinLinux/installer.ico DESTINATION .)
      EXECUTE_PROCESS(
        COMMAND /usr/bin/dpkg --print-architecture
        OUTPUT_VARIABLE CPACK_DEBIAN_PACKAGE_ARCHITECTURE
        RESULT_VARIABLE EXECUTE_RESULT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
      IF(EXECUTE_RESULT)
        MESSAGE(STATUS "Unable to determine current dpkg architecture: ${EXECUTE_RESULT} - will try RPM")
        SET(CPACK_RPM_POST_INSTALL_SCRIPT_FILE ${PROJECT_SOURCE_DIR}/installer/linux/scripts/postinst)
        SET(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE ${PROJECT_SOURCE_DIR}/installer/linux/scripts/prerm)
        SET(CPACK_GENERATOR RPM;TGZ)
      ELSE()
        MESSAGE("Debian package architecture: ${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}")
        SET(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${PROJECT_SOURCE_DIR}/installer/linux/scripts/postinst;${PROJECT_SOURCE_DIR}/installer/linux/scripts/prerm") # postinstall and before remove
        SET(CPACK_DEBIAN_PACKAGE_SECTION "Network")
        SET(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}")
        SET(CPACK_GENERATOR DEB;TGZ)
      ENDIF()
      #MESSAGE("Package install directory is set to \"${CPACK_PACKAGE_INSTALL_DIRECTORY}\"")
      MESSAGE("================================================================================")
    ELSEIF(APPLE)
      INSTALL(TARGETS ClientDemo EXPORT ClientDemo
              BUNDLE DESTINATION /Applications/ COMPONENT Runtime
              RUNTIME DESTINATION /Applications/
              CONFIGURATIONS Release)
      SET(CPACK_SET_DESTDIR TRUE)
      SET(CPACK_GENERATOR PackageMaker)
    ELSEIF(WIN32)
      INSTALL(TARGETS ClientDemo RUNTIME DESTINATION bin CONFIGURATIONS Release)
      SET(CPACK_PACKAGE_NAME "LifeStuffClient")
      INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/installer/windows/cbfs DESTINATION drivers)
      SET(CPACK_PACKAGE_INSTALL_DIRECTORY "MaidSafe\\\\LifeStuff")
      SET(CPACK_GENERATOR NSIS)
      SET(CPACK_PACKAGE_INSTALL_REGISTRY_KEY "LifeStuff ${CPACK_PACKAGE_VERSION}")
      SET(CPACK_NSIS_MUI_ICON "${PROJECT_SOURCE_DIR}/installer/common/icons/WinLinux/installer.ico")
      SET(CPACK_NSIS_MUI_UNIICON "${PROJECT_SOURCE_DIR}/installer/common/icons/WinLinux/uninstaller.ico")
      SET(CPACK_NSIS_EXTRA_INSTALL_COMMANDS "
#           LogSet on
            SetShellVarContext all
            IfFileExists \\\"$SYSDIR\\\\drivers\\\\cbfs3.sys\\\"  upgrade 0
            CreateDirectory  \\\"$APPDATA\\\\LifeStuff\\\"
            Goto finish
            upgrade:
            !include Library.nsh
            Var /GLOBAL installer_dll
            Var /GLOBAL cab_file_name
            Var /GLOBAL product_name
            Var /GLOBAL support_pnp
            Var /GLOBAL modules_to_install
            Var /GLOBAL reboot_needed
            StrCpy $installer_dll \\\"drivers\\\\cbfs\\\\32bit\\\\cbfsinst.dll\\\"
            StrCpy $cab_file_name \\\"drivers\\\\cbfs\\\\cbfs.cab\\\"
            StrCpy $product_name \\\"713CC6CE-B3E2-4fd9-838D-E28F558F6866\\\"
            StrCpy $support_pnp \\\"1\\\"
            StrCpy $modules_to_install \\\"0x1 | 0x00010000 | 0x00020000\\\"
            StrCpy $reboot_needed \\\"0\\\"
            System::Call '$installer_dll::InstallA($cab_file_name, $product_name, $support_pnp, $modules_to_install, $reboot_needed)'
            IntCmp $0 0 done reboot_needed_is_true reboot_needed_is_true
            reboot_needed_is_true:
            SetRebootFlag true
            Goto done
            done:
            Pop $0
            finish:
        ")
      SET(CPACK_NSIS_MODIFY_PATH ON)
      SET(CPACK_NSIS_DISPLAY_NAME "LifeStuff Client")
      SET(CPACK_NSIS_PACKAGE_NAME "LifeStuff Client")
      SET(CPACK_NSIS_INSTALLED_ICON_NAME "bin\\\\ClientDemo.exe")
      SET(CPACK_NSIS_EXECUTABLES_DIRECTORY "bin")
      SET(CPACK_NSIS_HELP_LINK "http://www.maidsafe.net")
      SET(CPACK_NSIS_URL_INFO_ABOUT "http://maidsafe.net/lifestuff.asp")
      SET(CPACK_NSIS_CONTACT "support@maidsafe.net")
      SET(CPACK_PACKAGE_RELOCATABLE ON)
      SET(CPACK_NSIS_MENU_LINKS "http://maidsafe.net/lifestuff.asp" "About LifeStuff")
    ENDIF()
    SET(CPACK_STRIP_FILES ON)
    SET(CPACK_PACKAGE_CONTACT "support@maidsafe.net")
    SET(CPACK_PACKAGE_EXECUTABLES "ClientDemo" "LifeStuff Client")
    INCLUDE(CPack)
  ENDIF()

ELSE() # Installing the library
  SET(LIFESTUFF_CLIENT_INSTALL_FILES
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/client/user_credentials_api.h)
  FOREACH(LIFESTUFF_CLIENT_INSTALL_FILE ${LIFESTUFF_CLIENT_INSTALL_FILES})
    CHECK_INSTALL_HEADER_HAS_VERSION_GUARD(${LIFESTUFF_CLIENT_INSTALL_FILE})
  ENDFOREACH()

#  SET(LIFESTUFF_CLIENT_FILESYSTEM_INSTALL_FILES
#        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/client/filesystem/sehandler.h)
#  FOREACH(LIFESTUFF_CLIENT_FILESYSTEM_INSTALL_FILE ${LIFESTUFF_CLIENT_FILESYSTEM_INSTALL_FILES})
#    CHECK_INSTALL_HEADER_HAS_VERSION_GUARD(${LIFESTUFF_CLIENT_FILESYSTEM_INSTALL_FILE})
#  ENDFOREACH()
#  SET(LIFESTUFF_CLIENT_FILESYSTEM_INSTALL_FILES ${LIFESTUFF_CLIENT_FILESYSTEM_INSTALL_FILES}
#        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/client/filesystem/distributed_filesystem.pb.h)

#  IF(MSVC)
#    SET(LIFESTUFF_FUSE_INSTALL_FILES
#          ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/fuse/windows/fswin.h)
#    SET(LIFESTUFF_FUSE_INSTALL_DIR include/maidsafe/lifestuff/fuse/windows)
#  ELSE()
#    SET(LIFESTUFF_FUSE_INSTALL_FILES
#          ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/fuse/linux/fslinux.h
#          ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/fuse/linux/fusecpp.h)
#    SET(LIFESTUFF_FUSE_INSTALL_DIR include/maidsafe/lifestuff/fuse/linux)
#  ENDIF()
#  FOREACH(LIFESTUFF_FUSE_INSTALL_FILE ${LIFESTUFF_FUSE_INSTALL_FILES})
#    CHECK_INSTALL_HEADER_HAS_VERSION_GUARD(${LIFESTUFF_FUSE_INSTALL_FILE})
#  ENDFOREACH()

  SET(LIFESTUFF_SHARED_INSTALL_FILES
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/shared/config.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/shared/maidsafe.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/shared/returncodes.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/shared/version.h)
  FOREACH(LIFESTUFF_SHARED_INSTALL_FILE ${LIFESTUFF_SHARED_INSTALL_FILES})
    CHECK_INSTALL_HEADER_HAS_VERSION_GUARD(${LIFESTUFF_SHARED_INSTALL_FILE})
  ENDFOREACH()

  SET(EXPORT_NAME lifestuff_client)
  INSTALL(TARGETS LifeStufflsmclientlib LifeStuffsharedlib LifeStuffclientfilesystemlib LifeStufffuselib EXPORT ${EXPORT_NAME} ARCHIVE DESTINATION lib)
  INSTALL(FILES ${LIFESTUFF_CLIENT_INSTALL_FILES} DESTINATION include/maidsafe/lifestuff/client)
#  INSTALL(FILES ${LIFESTUFF_CLIENT_FILESYSTEM_INSTALL_FILES} DESTINATION include/maidsafe/lifestuff/client/filesystem)
#  INSTALL(FILES ${LIFESTUFF_FUSE_INSTALL_FILES} DESTINATION ${LIFESTUFF_FUSE_INSTALL_DIR})
  INSTALL(FILES ${LIFESTUFF_SHARED_INSTALL_FILES} DESTINATION include/maidsafe/lifestuff/shared)
  INSTALL(EXPORT ${EXPORT_NAME} DESTINATION share/maidsafe)
  ADD_VERSION_INFO_TO_INSTALLED_FILE()
ENDIF()
UNSET(PACKAGE_BUILD CACHE)
