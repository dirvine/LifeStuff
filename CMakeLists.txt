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
# MaidSafe Common, DHT, Drive, Passport and PKI library search                                  #
###################################################################################################
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/build)
INCLUDE(maidsafe_find_common)
ADD_MAIDSAFE_LIBRARY(MaidSafe-Transport)
ADD_MAIDSAFE_LIBRARY(MaidSafe-DHT)
ADD_MAIDSAFE_LIBRARY(Encrypt)
ADD_MAIDSAFE_LIBRARY(MaidSafe-Drive)
ADD_MAIDSAFE_LIBRARY(PKI)
ADD_MAIDSAFE_LIBRARY(Passport)
ADD_MAIDSAFE_LIBRARY(MaidSafe-PD)
ADD_MAIDSAFE_LIBRARY(MaidSafe-AWS-Transporter)


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
HANDLE_VERSIONS(${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/version.h)


###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
####    CODE    ####
FILE(GLOB SOURCE_FILES_LIFESTUFF_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/*.cc")
FILE(GLOB HEADER_FILES_LIFESTUFF_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/*.h")
SET(ALL_FILES_LIFESTUFF_DIR ${SOURCE_FILES_LIFESTUFF_DIR} ${HEADER_FILES_LIFESTUFF_DIR})
SET(STYLE_ALL ${ALL_FILES_LIFESTUFF_DIR})
LIST(REMOVE_ITEM STYLE_ALL "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff_messages.pb.h"
                           "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff_messages.pb.cc"
                           "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_atlas.pb.h"
                           "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_atlas.pb.cc")
SOURCE_GROUP("LifeStuff Source Files" FILES ${SOURCE_FILES_LIFESTUFF_DIR})
SOURCE_GROUP("LifeStuff Header Files" FILES ${HEADER_FILES_LIFESTUFF_DIR})

SET(SOURCE_FILES_LOCAL_STORE "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/local_store_manager.cc")
SET(HEADER_FILES_LOCAL_STORE "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/packet_manager.h"
                             "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/local_store_manager.h")
SET(ALL_FILES_LOCAL_STORE ${SOURCE_FILES_LOCAL_STORE} ${HEADER_FILES_LOCAL_STORE})
SET(SOURCE_FILES_AWS_STORE "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/aws_store_manager.cc"
                           "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/aws_chunk_manager.cc")
SET(HEADER_FILES_AWS_STORE "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/packet_manager.h"
                           "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/aws_store_manager.h"
                           "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/aws_chunk_manager.h")
SET(ALL_FILES_AWS_STORE ${SOURCE_FILES_AWS_STORE} ${HEADER_FILES_AWS_STORE})
SET(STYLE_ALL ${ALL_FILES_LOCAL_STORE} ${ALL_FILES_AWS_STORE})
SOURCE_GROUP("Store Components Source Files" FILES ${SOURCE_FILES_LOCAL_STORE} ${SOURCE_FILES_AWS_STORE})
SOURCE_GROUP("Store Components Header Files" FILES ${HEADER_FILES_LOCAL_STORE} ${HEADER_FILES_AWS_STORE})

####    TESTS    ####
FILE(GLOB SOURCE_FILES_LIFESTUFF_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/*.cc")
FILE(GLOB HEADER_FILES_LIFESTUFF_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/*.h")
SET(ALL_FILES_LIFESTUFF_TESTS_DIR ${SOURCE_FILES_LIFESTUFF_TESTS_DIR} ${HEADER_FILES_LIFESTUFF_TESTS_DIR})
SOURCE_GROUP("Test Source Files" FILES ${SOURCE_FILES_LIFESTUFF_TESTS_DIR})
SOURCE_GROUP("Test Header Files" FILES ${HEADER_FILES_LIFESTUFF_TESTS_DIR})

SET(TESTS_MAIN_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/tests_main.cc")
SET(CLIENT_MAIN_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/client_main.cc")
SET(AUTHENTICATION_TEST_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/authentication_test.cc")
SET(CLIENT_CONTROLLER_TEST_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/client_controller_test.cc")

LIST(REMOVE_ITEM ALL_FILES_LIFESTUFF_TESTS_DIR ${CLIENT_MAIN_CC} ${AUTHENTICATION_TEST_CC} ${CLIENT_CONTROLLER_TEST_CC})

####    DEMO    ####
FILE(GLOB SOURCE_FILES_LIFESTUFF_DEMO_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/demo/*.cc")
FILE(GLOB HEADER_FILES_LIFESTUFF_DEMO_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/demo/*.h")
SET(ALL_FILES_LIFESTUFF_DEMO_DIR ${SOURCE_FILES_LIFESTUFF_DEMO_DIR} ${HEADER_FILES_LIFESTUFF_DEMO_DIR})
SOURCE_GROUP("Demo Source Files" FILES ${SOURCE_FILES_LIFESTUFF_DEMO_DIR})
SOURCE_GROUP("Demo Header Files" FILES ${HEADER_FILES_LIFESTUFF_DEMO_DIR})


###################################################################################################
# All Platforms:  Add exes and Create all LifeStuff libs                                          #
###################################################################################################
ADD_EXECUTABLE(TESTlifestuff ${ALL_FILES_LIFESTUFF_TESTS_DIR} ${TESTS_MAIN_CC})
ADD_EXECUTABLE(TESTauthentication_local ${AUTHENTICATION_TEST_CC} ${TESTS_MAIN_CC})
ADD_EXECUTABLE(TESTclientcontroller_local ${CLIENT_CONTROLLER_TEST_CC} ${TESTS_MAIN_CC})
ADD_EXECUTABLE(TESTauthentication_aws ${AUTHENTICATION_TEST_CC} ${TESTS_MAIN_CC})
ADD_EXECUTABLE(TESTclientcontroller_aws ${CLIENT_CONTROLLER_TEST_CC} ${TESTS_MAIN_CC})

ADD_EXECUTABLE(LifestuffDemoLocal ${ALL_FILES_LIFESTUFF_DEMO_DIR})
ADD_EXECUTABLE(LifestuffDemoAWS ${ALL_FILES_LIFESTUFF_DEMO_DIR})

SET(TEST_EXECUTABLES
      TESTlifestuff
      TESTauthentication_local
      TESTclientcontroller_local
      TESTauthentication_aws
      TESTclientcontroller_aws)
SET(DEMO_EXECUTABLES
      LifestuffDemoLocal
      LifestuffDemoAWS)
SET(ALL_EXECUTABLES ${TEST_EXECUTABLES} ${DEMO_EXECUTABLES})

FOREACH(EXE ${ALL_EXECUTABLES})
  RENAME_EXECUTABLE(${EXE})
ENDFOREACH()

SET_TARGET_PROPERTIES(${TEST_EXECUTABLES} PROPERTIES FOLDER "Tests")
SET_TARGET_PROPERTIES(${DEMO_EXECUTABLES} PROPERTIES FOLDER "Demos")

ADD_LIBRARY(lifestuff_static STATIC ${ALL_FILES_LIFESTUFF_DIR})
ADD_LIBRARY(lifestuff_local_store_static STATIC ${ALL_FILES_LOCAL_STORE})
ADD_LIBRARY(lifestuff_aws_store_static STATIC ${ALL_FILES_AWS_STORE})

SET_TARGET_PROPERTIES(lifestuff_static PROPERTIES OUTPUT_NAME lifestuff FOLDER "MaidSafe Libraries")
SET_TARGET_PROPERTIES(lifestuff_local_store_static PROPERTIES OUTPUT_NAME lifestuff_local_store FOLDER "MaidSafe Libraries")
SET_TARGET_PROPERTIES(lifestuff_aws_store_static PROPERTIES OUTPUT_NAME lifestuff_aws_store FOLDER "MaidSafe Libraries")

ADD_CUSTOM_TARGET(AllTestsAndDemos DEPENDS ${TEST_EXECUTABLES})

# IF(UNIX)
#   TARGET_LINK_LIBRARIES(lifestuff_sql_utils_static dl)
# ENDIF()
TARGET_LINK_LIBRARIES(lifestuff_static maidsafe_drive_static passport_static boost_date_time ${QT_LIBRARIES} boost_regex)
TARGET_LINK_LIBRARIES(lifestuff_aws_store_static maidsafe_aws_transporter_static)

TARGET_LINK_LIBRARIES(TESTlifestuff lifestuff_static lifestuff_local_store_static gtest_static gmock_static)
TARGET_LINK_LIBRARIES(TESTauthentication_local lifestuff_static lifestuff_local_store_static gtest_static)
TARGET_LINK_LIBRARIES(TESTclientcontroller_local lifestuff_static lifestuff_local_store_static gtest_static)
TARGET_LINK_LIBRARIES(TESTauthentication_aws lifestuff_static lifestuff_aws_store_static gtest_static)
TARGET_LINK_LIBRARIES(TESTclientcontroller_aws lifestuff_static lifestuff_aws_store_static gtest_static)
TARGET_LINK_LIBRARIES(LifestuffDemoLocal lifestuff_static lifestuff_local_store_static)
TARGET_LINK_LIBRARIES(LifestuffDemoAWS lifestuff_static lifestuff_aws_store_static)


###################################################################################################
# Builds                                                                                          #
###################################################################################################
INCLUDE(maidsafe_standard_flags)

SET_TARGET_PROPERTIES(TESTauthentication_local TESTclientcontroller_local LifestuffDemoLocal
                        PROPERTIES COMPILE_DEFINITIONS LOCAL_STORE)
SET_TARGET_PROPERTIES(TESTauthentication_aws TESTclientcontroller_aws LifestuffDemoAWS
                        PROPERTIES COMPILE_DEFINITIONS AMAZON_WEB_SERVICE_STORE)
IF(UNIX)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DQT_NO_DEBUG_OUTPUT -DQT_NO_WARNING_OUTPUT -DQT_NO_DEBUG_STREAM")
  SET_SOURCE_FILES_PROPERTIES(${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_atlas.pb.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff_messages.pb.cc
                                PROPERTIES COMPILE_FLAGS "-w")
ELSEIF(MSVC)
  # C4503 'decorated name length exceeded' caused by boost multi-index and signals2
  # Disabled as per advice at https://svn.boost.org/trac/boost/wiki/Guidelines/WarningsGuidelines
  # C4512 'assignment operator could not be generated' caused by boost signals2
  # Disabled as per advice at http://lists.boost.org/boost-users/2009/01/44368.php
  # C4996 'Function call with parameters that may be unsafe' caused by boost signals2
  # Disabled as per advice at https://svn.boost.org/trac/boost/wiki/Guidelines/WarningsGuidelines
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4503 /wd4512 /wd4996")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /D \"QT_NO_DEBUG_OUTPUT\" /D \"QT_NO_WARNING_OUTPUT\" /D \"QT_NO_DEBUG_STREAM\"")
  SET_SOURCE_FILES_PROPERTIES(${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_atlas.pb.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff_messages.pb.cc
                                PROPERTIES COMPILE_FLAGS "/W0")
  SET_TARGET_PROPERTIES(${ALL_EXECUTABLES} PROPERTIES
                          LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG /INCREMENTAL:NO ${LINKER_LIBS_DIRS_RELEASE}"
                          LINK_FLAGS_DEBUG "${LINKER_LIBS_DIRS_DEBUG}"
                          LINK_FLAGS_RELWITHDEBINFO "${LINKER_LIBS_DIRS_DEBUG}"
                          LINK_FLAGS_MINSIZEREL "${LINKER_LIBS_DIRS_DEBUG}")
  SET_TARGET_PROPERTIES(lifestuff_static lifestuff_local_store_static lifestuff_aws_store_static
                          PROPERTIES STATIC_LIBRARY_FLAGS_RELEASE "/LTCG")
ENDIF()


###################################################################################################
# Tests                                                                                           #
###################################################################################################
SET(LOCAL_SYSTEM_TEST_TIMEOUT 1800)
SET(NETWORK_SYSTEM_TEST_TIMEOUT 3600)

IF(PYTHONINTERP_FOUND)
  IF(UNIX)
    ADD_TEST(STYLE_CHECK python ${MaidSafeCommon_TOOLS_DIR}/cpplint.py ${STYLE_ALL})
  ELSE()
    STRING(REPLACE "/" "\\\\" STYLE_CHECK_SOURCE ${PROJECT_SOURCE_DIR})
    ADD_TEST(STYLE_CHECK ${MaidSafeCommon_TOOLS_DIR}/run_cpplint.bat ${STYLE_CHECK_SOURCE} ${MaidSafeCommon_TOOLS_DIR}/cpplint.py)
  ENDIF()
  SET_PROPERTY(TEST STYLE_CHECK PROPERTY LABELS Functional CodingStyle)
ENDIF()

FOREACH(TEST_EXE ${TEST_EXECUTABLES})
  ADD_GTESTS(${TEST_EXE})
ENDFOREACH()
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
    SET(CPACK_PACKAGE_EXECUTABLES "LifestuffDemo", "Life Stuff Client")
    SET(CPACK_STRIP_FILES "true")
    IF(UNIX AND NOT APPLE)
      # Linux requires lower case package names
      SET(CPACK_PACKAGE_NAME "lifestuff_client")
      SET(CMAKE_INSTALL_PREFIX /opt/maidsafe/lifestuff)
      SET(CPACK_TOPLEVEL_TAG ${CMAKE_INSTALL_PREFIX})
      SET(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
      INSTALL(TARGETS LifestuffDemo RUNTIME DESTINATION .)
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
      INSTALL(TARGETS LifestuffDemo EXPORT LifestuffDemo
              BUNDLE DESTINATION /Applications/ COMPONENT Runtime
              RUNTIME DESTINATION /Applications/
              CONFIGURATIONS Release)
      SET(CPACK_SET_DESTDIR TRUE)
      SET(CPACK_GENERATOR PackageMaker)
    ELSEIF(WIN32)
      INSTALL(TARGETS LifestuffDemo RUNTIME DESTINATION bin CONFIGURATIONS Release)
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
      SET(CPACK_NSIS_INSTALLED_ICON_NAME "bin\\\\LifestuffDemo.exe")
      SET(CPACK_NSIS_EXECUTABLES_DIRECTORY "bin")
      SET(CPACK_NSIS_HELP_LINK "http://www.maidsafe.net")
      SET(CPACK_NSIS_URL_INFO_ABOUT "http://maidsafe.net/lifestuff.asp")
      SET(CPACK_NSIS_CONTACT "support@maidsafe.net")
      SET(CPACK_PACKAGE_RELOCATABLE ON)
      SET(CPACK_NSIS_MENU_LINKS "http://maidsafe.net/lifestuff.asp" "About LifeStuff")
    ENDIF()
    SET(CPACK_STRIP_FILES ON)
    SET(CPACK_PACKAGE_CONTACT "support@maidsafe.net")
    SET(CPACK_PACKAGE_EXECUTABLES "LifestuffDemo" "LifeStuff Client")
    INCLUDE(CPack)
  ENDIF()

ELSE() # Installing the library
  SET(LIFESTUFF_LIFESTUFF_INSTALL_FILES
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/client_controller.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/user_credentials_api.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/user_storage.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/maidsafe.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/return_codes.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/version.h)
  FOREACH(LIFESTUFF_LIFESTUFF_INSTALL_FILE ${LIFESTUFF_LIFESTUFF_INSTALL_FILES})
    CHECK_INSTALL_HEADER_HAS_VERSION_GUARD(${LIFESTUFF_LIFESTUFF_INSTALL_FILE})
  ENDFOREACH()

  SET(EXPORT_NAME lifestuff_client)
  INSTALL(TARGETS lifestuff_static lifestuff_local_store_static lifestuff_aws_store_static EXPORT ${EXPORT_NAME} ARCHIVE DESTINATION lib)
  INSTALL(FILES ${LIFESTUFF_LIFESTUFF_INSTALL_FILES} DESTINATION include/maidsafe/lifestuff)
  INSTALL(EXPORT ${EXPORT_NAME} DESTINATION share/maidsafe)
  ADD_VERSION_INFO_TO_INSTALLED_FILE()
ENDIF()
UNSET(PACKAGE_BUILD CACHE)
