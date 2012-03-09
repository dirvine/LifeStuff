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
IF(NOT LOCAL_TARGETS_ONLY)
  ADD_MAIDSAFE_LIBRARY(MaidSafe-Transport)
  ADD_MAIDSAFE_LIBRARY(MaidSafe-DHT)
  ADD_MAIDSAFE_LIBRARY(MaidSafe-PD)
ENDIF()


###################################################################################################
# Callback File System / Fuse library search                                                      #
###################################################################################################
IF(WIN32)
  INCLUDE(maidsafe_find_cbfs)
  SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Cbfs_INCLUDE_DIR})
  SET(LIBS_DIRS ${LIBS_DIRS} ${Cbfs_LIBRARY_DIR})
  SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Cbfs_LIBRARY_DIR})
  SET(Fuse_LIBRARY ${Cbfs_LIBRARY})
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

####    TESTS    ####
FILE(GLOB SOURCE_FILES_LIFESTUFF_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/*.cc")
FILE(GLOB HEADER_FILES_LIFESTUFF_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/*.h")
SET(ALL_FILES_LIFESTUFF_TESTS_DIR ${SOURCE_FILES_LIFESTUFF_TESTS_DIR} ${HEADER_FILES_LIFESTUFF_TESTS_DIR})
SOURCE_GROUP("Tests Source Files" FILES ${SOURCE_FILES_LIFESTUFF_TESTS_DIR})
SOURCE_GROUP("Tests Header Files" FILES ${HEADER_FILES_LIFESTUFF_TESTS_DIR})

SET(TESTS_MAIN_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/tests_main.cc")
SET(AUTHENTICATION_TEST_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/authentication_test.cc")
SET(CLIENT_CONTROLLER_TEST_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/client_controller_test.cc")
SET(PUBLIC_ID_TEST_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/public_id_test.cc"
                      "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/message_handler_test.cc")
SET(USER_STORAGE_TEST_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/user_storage_test.cc")

LIST(REMOVE_ITEM ALL_FILES_LIFESTUFF_TESTS_DIR ${CLIENT_MAIN_CC}
                                               ${AUTHENTICATION_TEST_CC}
                                               ${CLIENT_CONTROLLER_TEST_CC}
                                               ${PUBLIC_ID_TEST_CC}
                                               ${USER_STORAGE_TEST_CC})


###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
MS_ADD_STATIC_LIBRARY(lifestuff_local ${ALL_FILES_LIFESTUFF_DIR})
MS_ADD_EXECUTABLE(TESTlifestuff_local Tests ${ALL_FILES_LIFESTUFF_TESTS_DIR} ${TESTS_MAIN_CC})
MS_ADD_EXECUTABLE(TESTauthentication_local Tests ${AUTHENTICATION_TEST_CC} ${TESTS_MAIN_CC})
MS_ADD_EXECUTABLE(TESTclientcontroller_local Tests ${CLIENT_CONTROLLER_TEST_CC} ${TESTS_MAIN_CC})
MS_ADD_EXECUTABLE(TESTpublic_id_local Tests ${PUBLIC_ID_TEST_CC} ${TESTS_MAIN_CC})
MS_ADD_EXECUTABLE(TESTuser_storage_local Tests ${USER_STORAGE_TEST_CC} ${TESTS_MAIN_CC})
TARGET_LINK_LIBRARIES(lifestuff_local_static maidsafe_drive_static maidsafe_passport_static)
TARGET_LINK_LIBRARIES(TESTlifestuff_local lifestuff_local_static gtest_static)
TARGET_LINK_LIBRARIES(TESTauthentication_local lifestuff_local_static gtest_static)
TARGET_LINK_LIBRARIES(TESTclientcontroller_local lifestuff_local_static gtest_static)
TARGET_LINK_LIBRARIES(TESTpublic_id_local lifestuff_local_static gtest_static)
TARGET_LINK_LIBRARIES(TESTuser_storage_local lifestuff_local_static gtest_static)

IF(NOT LOCAL_TARGETS_ONLY)
  MS_ADD_STATIC_LIBRARY(${MS_PROJECT_NAME} ${ALL_FILES_LIFESTUFF_DIR})
  MS_ADD_EXECUTABLE(TESTlifestuff Tests ${ALL_FILES_LIFESTUFF_TESTS_DIR} ${TESTS_MAIN_CC})
  MS_ADD_EXECUTABLE(TESTauthentication Tests ${AUTHENTICATION_TEST_CC} ${TESTS_MAIN_CC})
  MS_ADD_EXECUTABLE(TESTclientcontroller Tests ${CLIENT_CONTROLLER_TEST_CC} ${TESTS_MAIN_CC})
  MS_ADD_EXECUTABLE(TESTpublic_id Tests ${PUBLIC_ID_TEST_CC} ${TESTS_MAIN_CC})
  MS_ADD_EXECUTABLE(TESTuser_storage Tests ${USER_STORAGE_TEST_CC} ${TESTS_MAIN_CC})
  TARGET_LINK_LIBRARIES(lifestuff_static maidsafe_drive_static maidsafe_passport_static maidsafe_pd_static)
  TARGET_LINK_LIBRARIES(TESTlifestuff lifestuff_static gtest_static)
  TARGET_LINK_LIBRARIES(TESTauthentication lifestuff_static gtest_static)
  TARGET_LINK_LIBRARIES(TESTclientcontroller lifestuff_static gtest_static)
  TARGET_LINK_LIBRARIES(TESTpublic_id lifestuff_static gtest_static)
  TARGET_LINK_LIBRARIES(TESTuser_storage lifestuff_static gtest_static)
ENDIF()



###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
INCLUDE(maidsafe_standard_flags)

IF(LOCAL_TARGETS_ONLY)
  ADD_DEFINITIONS(-DLOCAL_TARGETS_ONLY)
ENDIF()

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
ADD_STYLE_TEST(${STYLE_ALL} ${ALL_FILES_LIFESTUFF_TESTS_DIR} ${AUTHENTICATION_TEST_CC} ${CLIENT_CONTROLLER_TEST_CC} ${PUBLIC_ID_TEST_CC} ${USER_STORAGE_TEST_CC})

ADD_GTESTS(TESTlifestuff_local)
ADD_GTESTS(TESTauthentication_local)
ADD_GTESTS(TESTclientcontroller_local)
ADD_GTESTS(TESTpublic_id_local)
ADD_GTESTS(TESTuser_storage_local)

TEST_SUMMARY_OUTPUT()


###################################################################################################
# Install details                                                                                 #
###################################################################################################
FINAL_MESSAGE()

SET(JUST_LOCAL "Hello, user. If you should desire to build a local version of the\n")
SET(JUST_LOCAL "${JUST_LOCAL}libraries and tests, please use -DLOCAL_TARGETS_ONLY=ON\n")
SET(JUST_LOCAL "${JUST_LOCAL}when running cmake. To switch to both versions, please\n")
SET(JUST_LOCAL "${JUST_LOCAL}use -DLOCAL_TARGETS_ONLY=OFF\n")
MESSAGE(${JUST_LOCAL})
MESSAGE("================================================================================")

RENAME_OUTDATED_BUILT_EXES()

SET(LIFESTUFF_INSTALL_FILES
      ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/client_controller.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/session.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/user_storage.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/message_handler.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/public_id.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/return_codes.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/version.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/ye_olde_signal_to_callback_converter.h)

MS_INSTALL_LIBS(lifestuff_local_static)
IF(NOT LOCAL_TARGETS_ONLY)
  MS_INSTALL_LIBS(lifestuff_static)
ENDIF()
MS_INSTALL_HEADERS(lifestuff ${LIFESTUFF_INSTALL_FILES})
MS_INSTALL_EXPORT()
