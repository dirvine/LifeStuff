#==============================================================================#
#                                                                              #
#  Copyright (c) 2011 MaidSafe.net limited                                     #
#                                                                              #
#  The following source code is property of MaidSafe.net limited and is not    #
#  meant for external use.  The use of this code is governed by the license    #
#  file licence.txt found in the root directory of this project and also on    #
#  www.maidsafe.net.                                                           #
#                                                                              #
#  You are not free to copy, amend or otherwise use this source code without   #
#  the explicit written permission of the board of directors of MaidSafe.net.  #
#                                                                              #
#==============================================================================#


SET(MS_PROJECT_NAME lifestuff)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8.4 FATAL_ERROR)
MESSAGE("================================================================================\n")

GET_FILENAME_COMPONENT(CMAKE_BUILD_TYPE_DIR ${CMAKE_BINARY_DIR} NAME)

# Variable MSVC is not set until after "PROJECT" command below
IF(CMAKE_BUILD_TYPE_DIR MATCHES "Win_MSVC")
  SET(CMAKE_BUILD_TYPE_DIR Release)
ELSEIF(CMAKE_BUILD_TYPE_DIR MATCHES "kdev")
  SET(CMAKE_BUILD_TYPE_DIR Debug)
  SET(KDEV 1)
ENDIF()

IF(NOT ${CMAKE_C_COMPILER_WORKS})
  MESSAGE(FATAL_ERROR "No generator previously specified.\nTo see a full list of generators, run:\n\tcmake --help\n")
ENDIF()

# This "PROJECT" command resets CMAKE_BUILD_TYPE, hence it's copied from CMAKE_BUILD_TYPE_DIR which is set above.
IF((CMAKE_BUILD_TYPE_DIR MATCHES "Release") OR (DEFINED ${KDEV}))
  PROJECT(${MS_PROJECT_NAME})
ELSE()
  STRING(TOLOWER ${CMAKE_BUILD_TYPE_DIR} MS_PROJECT_NAME_APPENDIX)
  PROJECT(${MS_PROJECT_NAME}_${MS_PROJECT_NAME_APPENDIX})
ENDIF()

SET(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE_DIR} CACHE INTERNAL "Except for MSVC, the build type is set by running cmake from the appropriate build subdirectory e.g. for a Debug build, \"cd build/Linux/Debug && cmake ../../..\"." FORCE)


###################################################################################################
# MaidSafe Common, Private, Encrypt, DHT, Drive, PKI and Passport library search                  #
###################################################################################################
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/build)
INCLUDE(maidsafe_find_common)
ADD_MAIDSAFE_LIBRARY(MaidSafe-Private)
ADD_MAIDSAFE_LIBRARY(MaidSafe-Encrypt)
ADD_MAIDSAFE_LIBRARY(MaidSafe-Drive)
ADD_MAIDSAFE_LIBRARY(MaidSafe-PKI)
ADD_MAIDSAFE_LIBRARY(MaidSafe-Passport)
# ADD_MAIDSAFE_LIBRARY(MaidSafe-PD)
# ADD_MAIDSAFE_LIBRARY(MaidSafe-AWS-Transporter)


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
  IF(APPLE)
    FIND_LIBRARY(Fuse_LIBRARY libfuse_ino64.dylib)
  ELSE()
    FIND_LIBRARY(Fuse_LIBRARY libfuse.a)
  ENDIF()
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
LIST(REMOVE_ITEM STYLE_ALL "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_atlas.pb.h"
                           "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_atlas.pb.cc"
                           "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_types.pb.h"
                           "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_types.pb.cc"
                           "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff_messages.pb.h"
                           "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff_messages.pb.cc")
SOURCE_GROUP("LifeStuff Source Files" FILES ${SOURCE_FILES_LIFESTUFF_DIR})
SOURCE_GROUP("LifeStuff Header Files" FILES ${HEADER_FILES_LIFESTUFF_DIR})

SET(SOURCE_FILES_LOCAL_STORE "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/fake_store_manager.cc"
                             "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/local_store_manager.cc")
SET(HEADER_FILES_LOCAL_STORE "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/packet_manager.h"
                             "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/fake_store_manager.h"
                             "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/local_store_manager.h")
SET(ALL_FILES_LOCAL_STORE ${SOURCE_FILES_LOCAL_STORE} ${HEADER_FILES_LOCAL_STORE})
# SET(SOURCE_FILES_AWS_STORE "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/fake_store_manager.cc"
#                            "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/aws_store_manager.cc"
#                            "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/aws_remote_chunk_store.cc"
#                            "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/aws_chunk_manager.cc")
# SET(HEADER_FILES_AWS_STORE "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/packet_manager.h"
#                            "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/fake_store_manager.h"
#                            "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/aws_store_manager.h"
#                            "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/aws_remote_chunk_store.h"
#                            "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/aws_chunk_manager.h")
# SET(ALL_FILES_AWS_STORE ${SOURCE_FILES_AWS_STORE} ${HEADER_FILES_AWS_STORE})
SET(STYLE_ALL ${ALL_FILES_LOCAL_STORE}) # ${ALL_FILES_AWS_STORE})
SOURCE_GROUP("Store Components Source Files" FILES ${SOURCE_FILES_LOCAL_STORE}) # ${SOURCE_FILES_AWS_STORE})
SOURCE_GROUP("Store Components Header Files" FILES ${HEADER_FILES_LOCAL_STORE}) # ${HEADER_FILES_AWS_STORE})

####    TESTS    ####
FILE(GLOB SOURCE_FILES_LIFESTUFF_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/*.cc")
FILE(GLOB HEADER_FILES_LIFESTUFF_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/*.h")
SET(ALL_FILES_LIFESTUFF_TESTS_DIR ${SOURCE_FILES_LIFESTUFF_TESTS_DIR} ${HEADER_FILES_LIFESTUFF_TESTS_DIR})
SOURCE_GROUP("Tests Source Files" FILES ${SOURCE_FILES_LIFESTUFF_TESTS_DIR})
SOURCE_GROUP("Tests Header Files" FILES ${HEADER_FILES_LIFESTUFF_TESTS_DIR})

SET(TESTS_MAIN_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/tests_main.cc")
SET(CLIENT_MAIN_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/client_main.cc")
SET(AUTHENTICATION_TEST_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/authentication_test.cc")
SET(CLIENT_CONTROLLER_TEST_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/client_controller_test.cc")
SET(PUBLIC_ID_TEST_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/public_id_test.cc"
                      "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/message_handler_test.cc")

LIST(REMOVE_ITEM ALL_FILES_LIFESTUFF_TESTS_DIR ${CLIENT_MAIN_CC} ${AUTHENTICATION_TEST_CC} ${CLIENT_CONTROLLER_TEST_CC} ${PUBLIC_ID_TEST_CC})

####    DEMO    ####
FILE(GLOB SOURCE_FILES_LIFESTUFF_DEMO_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/demo/*.cc")
FILE(GLOB HEADER_FILES_LIFESTUFF_DEMO_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/demo/*.h")
SET(ALL_FILES_LIFESTUFF_DEMO_DIR ${SOURCE_FILES_LIFESTUFF_DEMO_DIR} ${HEADER_FILES_LIFESTUFF_DEMO_DIR})
SOURCE_GROUP("Demo Source Files" FILES ${SOURCE_FILES_LIFESTUFF_DEMO_DIR})
SOURCE_GROUP("Demo Header Files" FILES ${HEADER_FILES_LIFESTUFF_DEMO_DIR})


###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
MS_ADD_STATIC_LIBRARY(${MS_PROJECT_NAME} ${ALL_FILES_LIFESTUFF_DIR})
MS_ADD_STATIC_LIBRARY(lifestuff_local_store ${ALL_FILES_LOCAL_STORE})
# MS_ADD_STATIC_LIBRARY(lifestuff_aws_store ${ALL_FILES_AWS_STORE})

MS_ADD_EXECUTABLE(TESTlifestuff Tests ${ALL_FILES_LIFESTUFF_TESTS_DIR} ${TESTS_MAIN_CC})
MS_ADD_EXECUTABLE(TESTauthentication_local Tests ${AUTHENTICATION_TEST_CC} ${TESTS_MAIN_CC})
MS_ADD_EXECUTABLE(TESTclientcontroller_local Tests ${CLIENT_CONTROLLER_TEST_CC} ${TESTS_MAIN_CC})
MS_ADD_EXECUTABLE(TESTpublic_id_local Tests ${PUBLIC_ID_TEST_CC} ${TESTS_MAIN_CC})
# MS_ADD_EXECUTABLE(TESTauthentication_aws Tests ${AUTHENTICATION_TEST_CC} ${TESTS_MAIN_CC})
# MS_ADD_EXECUTABLE(TESTclientcontroller_aws Tests ${CLIENT_CONTROLLER_TEST_CC} ${TESTS_MAIN_CC})
# MS_ADD_EXECUTABLE(TESTpublic_id_aws Tests ${PUBLIC_ID_TEST_CC} ${TESTS_MAIN_CC})

MS_ADD_EXECUTABLE(LifestuffDemoLocal Demo ${ALL_FILES_LIFESTUFF_DEMO_DIR})
# MS_ADD_EXECUTABLE(LifestuffDemoAWS Demo ${ALL_FILES_LIFESTUFF_DEMO_DIR})

TARGET_LINK_LIBRARIES(lifestuff_static maidsafe_drive_static maidsafe_passport_static)
# TARGET_LINK_LIBRARIES(lifestuff_aws_store_static maidsafe_aws_transporter_static)

TARGET_LINK_LIBRARIES(TESTlifestuff lifestuff_local_store_static lifestuff_static gtest_static gmock_static)
TARGET_LINK_LIBRARIES(TESTauthentication_local lifestuff_local_store_static lifestuff_static gtest_static)
TARGET_LINK_LIBRARIES(TESTclientcontroller_local lifestuff_local_store_static lifestuff_static gtest_static)
TARGET_LINK_LIBRARIES(TESTpublic_id_local lifestuff_local_store_static lifestuff_static gtest_static)
# TARGET_LINK_LIBRARIES(TESTauthentication_aws lifestuff_aws_store_static lifestuff_static gtest_static)
# TARGET_LINK_LIBRARIES(TESTclientcontroller_aws lifestuff_aws_store_static lifestuff_static gtest_static)
# TARGET_LINK_LIBRARIES(TESTpublic_id_aws lifestuff_aws_store_static lifestuff_static gtest_static)
TARGET_LINK_LIBRARIES(LifestuffDemoLocal lifestuff_local_store_static lifestuff_static)
# TARGET_LINK_LIBRARIES(LifestuffDemoAWS lifestuff_aws_store_static lifestuff_static)


###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
INCLUDE(maidsafe_standard_flags)

# SET_TARGET_PROPERTIES(TESTauthentication_aws TESTclientcontroller_aws TESTpublic_id_aws LifestuffDemoAWS lifestuff_aws_store_static
#                         PROPERTIES COMPILE_DEFINITIONS AMAZON_WEB_SERVICE_STORE)
IF(MSVC)
  SET_SOURCE_FILES_PROPERTIES(${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_atlas.pb.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_types.pb.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff_messages.pb.cc
                                PROPERTIES COMPILE_FLAGS "/W0")
ELSEIF(UNIX)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")
  SET_SOURCE_FILES_PROPERTIES(${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_atlas.pb.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_types.pb.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff_messages.pb.cc
                                PROPERTIES COMPILE_FLAGS "-w")
ENDIF()


###################################################################################################
# Tests                                                                                           #
###################################################################################################
ADD_STYLE_TEST(${STYLE_ALL})

ADD_GTESTS(TESTlifestuff)
# ADD_GTESTS(TESTauthentication_aws)
# ADD_GTESTS(TESTclientcontroller_aws)
# ADD_GTESTS(TESTpublic_id_aws)
ADD_GTESTS(TESTauthentication_local)
ADD_GTESTS(TESTclientcontroller_local)
ADD_GTESTS(TESTpublic_id_local)

TEST_SUMMARY_OUTPUT()


###################################################################################################
# Install details                                                                                 #
###################################################################################################
FINAL_MESSAGE()
RENAME_OUTDATED_BUILT_EXES()

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
    SET(CPACK_PACKAGE_EXECUTABLES "LifestuffDemo", "LifeStuff Client")
    SET(CPACK_STRIP_FILES "true")
    IF(UNIX AND NOT APPLE)
      # Linux requires lower case package names
      SET(CPACK_PACKAGE_NAME "LifeStuff")
      SET(CMAKE_INSTALL_PREFIX /opt/maidsafe/lifestuff)
      SET(CPACK_TOPLEVEL_TAG ${CMAKE_INSTALL_PREFIX})
      SET(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
      INSTALL(TARGETS LifestuffDemo RUNTIME DESTINATION .)
      INSTALL(FILES ${PROJECT_SOURCE_DIR}/installer/linux/scripts/lifestuff.desktop DESTINATION .)
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
  SET(LIFESTUFF_INSTALL_FILES
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/client_controller.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/session.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/user_storage.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/message_handler.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/public_id.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/return_codes.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/version.h)
  SET(LIFESTUFF_STORE_COMPONENTS_INSTALL_FILES
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/packet_manager.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/fake_store_manager.h
        ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/local_store_manager.h)
#         ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/store_components/aws_store_manager.h)

  MS_INSTALL_LIBS(lifestuff_static lifestuff_local_store_static) # lifestuff_aws_store_static)
  MS_INSTALL_HEADERS(lifestuff ${LIFESTUFF_INSTALL_FILES})
  MS_INSTALL_HEADERS(lifestuff/store_components ${LIFESTUFF_STORE_COMPONENTS_INSTALL_FILES})
  MS_INSTALL_EXPORT()
ENDIF()
UNSET(PACKAGE_BUILD CACHE)
