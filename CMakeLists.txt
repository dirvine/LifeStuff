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

IF(NOT LOCAL_TARGETS_ONLY)
  SET(LOCAL_TARGETS_ONLY OFF)
ENDIF()


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
IF(${LOCAL_TARGETS_ONLY} MATCHES OFF)
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
FILE(GLOB_RECURSE PROTO_FILES RELATIVE ${PROTO_SOURCE_DIR} "${PROTO_SOURCE_DIR}/maidsafe/lifestuff/detail/*.proto")
INCLUDE(maidsafe_standard_setup)

SET(PATH_TO_SRC ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff)
HANDLE_VERSIONS(${PATH_TO_SRC}/version.h)


###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
####    CODE    ####
# Installables
FILE(GLOB SOURCE_FILES_LIFESTUFF_DIR "${PATH_TO_SRC}/*.cc")
FILE(GLOB HEADER_FILES_LIFESTUFF_DIR "${PATH_TO_SRC}/*.h")
SET(ALL_FILES_LIFESTUFF_DIR ${SOURCE_FILES_LIFESTUFF_DIR} ${HEADER_FILES_LIFESTUFF_DIR})
SOURCE_GROUP("LifeStuff Source Files" FILES ${SOURCE_FILES_LIFESTUFF_DIR})
SOURCE_GROUP("LifeStuff Header Files" FILES ${HEADER_FILES_LIFESTUFF_DIR})
LIST(REMOVE_ITEM ALL_FILES_LIFESTUFF_DIR "${PATH_TO_SRC}/lifestuff.h"
                                         "${PATH_TO_SRC}/lifestuff.cc"
                                         "${PATH_TO_SRC}/log.h"
                                         "${PATH_TO_SRC}/return_codes.h"
                                         "${PATH_TO_SRC}/version.h")
# Detail
FILE(GLOB SOURCE_FILES_DETAIL_DIR "${PATH_TO_SRC}/detail/*.cc"
                                  "${PATH_TO_SRC}/lifestuff.cc")
FILE(GLOB HEADER_FILES_DETAIL_DIR "${PATH_TO_SRC}/detail/*.h"
                                  "${PATH_TO_SRC}/lifestuff.h"
                                  "${PATH_TO_SRC}/log.h"
                                  "${PATH_TO_SRC}/return_codes.h"
                                  "${PATH_TO_SRC}/version.h")
SET(ALL_FILES_DETAIL_DIR ${SOURCE_FILES_DETAIL_DIR} ${HEADER_FILES_DETAIL_DIR})
SOURCE_GROUP("LifeStuff Detail Source Files" FILES ${SOURCE_FILES_DETAIL_DIR})
SOURCE_GROUP("LifeStuff Detail Header Files" FILES ${HEADER_FILES_DETAIL_DIR})

SET(STYLE_ALL ${ALL_FILES_DETAIL_DIR} ${ALL_FILES_LIFESTUFF_DIR})
LIST(REMOVE_ITEM STYLE_ALL "${PATH_TO_SRC}/detail/data_atlas.pb.h"
                           "${PATH_TO_SRC}/detail/data_atlas.pb.cc"
                           "${PATH_TO_SRC}/detail/data_types.pb.h"
                           "${PATH_TO_SRC}/detail/data_types.pb.cc"
                           "${PATH_TO_SRC}/detail/lifestuff_messages.pb.h"
                           "${PATH_TO_SRC}/detail/lifestuff_messages.pb.cc")

####    TESTS    ####
SET(TESTS_MAIN_CC "${PATH_TO_SRC}/tests/tests_main.cc")
SET(CLIENT_CONTROLLER_TEST_CC "${PATH_TO_SRC}/tests/user_credentials_test.cc")
SET(PUBLIC_ID_TEST_CC "${PATH_TO_SRC}/tests/public_id_test.cc"
                      "${PATH_TO_SRC}/tests/message_handler_test.cc")
SET(USER_STORAGE_TEST_CC "${PATH_TO_SRC}/tests/user_storage_test.cc")
SET(API_TEST_CC "${PATH_TO_SRC}/tests/full_api_test.cc")
SET(LIFESTUFF_TESTS_CC "${PATH_TO_SRC}/tests/contacts_test.cc"
                       "${PATH_TO_SRC}/tests/session_test.cc"
                       "${PATH_TO_SRC}/tests/utils_test.cc")

SOURCE_GROUP("Tests Source Files" FILES ${TESTS_MAIN_CC}
                                        ${CLIENT_CONTROLLER_TEST_CC}
                                        ${PUBLIC_ID_TEST_CC}
                                        ${USER_STORAGE_TEST_CC}
                                        ${API_TEST_CC}
                                        ${LIFESTUFF_TESTS_CC})

###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
MS_ADD_STATIC_LIBRARY(lifestuff_detail ${ALL_FILES_DETAIL_DIR})
MS_ADD_EXECUTABLE(TESTlifestuff_general Tests ${LIFESTUFF_TESTS_CC} ${TESTS_MAIN_CC})

MS_ADD_STATIC_LIBRARY(lifestuff_local ${ALL_FILES_LIFESTUFF_DIR})
MS_ADD_EXECUTABLE(TESTpublic_id_local Tests ${PUBLIC_ID_TEST_CC} ${TESTS_MAIN_CC})
MS_ADD_EXECUTABLE(TESTuser_credentials_local Tests ${CLIENT_CONTROLLER_TEST_CC} ${TESTS_MAIN_CC})
MS_ADD_EXECUTABLE(TESTuser_storage_local Tests ${USER_STORAGE_TEST_CC} ${TESTS_MAIN_CC})
MS_ADD_EXECUTABLE(TESTapi_local Tests ${API_TEST_CC} ${TESTS_MAIN_CC})

TARGET_LINK_LIBRARIES(lifestuff_detail_static maidsafe_drive_static maidsafe_passport_static boost_regex)
TARGET_LINK_LIBRARIES(lifestuff_local_static lifestuff_detail_static)
TARGET_LINK_LIBRARIES(TESTlifestuff_general lifestuff_local_static gtest_static)
TARGET_LINK_LIBRARIES(TESTpublic_id_local lifestuff_local_static gtest_static)
TARGET_LINK_LIBRARIES(TESTuser_credentials_local lifestuff_local_static gtest_static)
TARGET_LINK_LIBRARIES(TESTuser_storage_local lifestuff_local_static gtest_static)
TARGET_LINK_LIBRARIES(TESTapi_local lifestuff_local_static gtest_static)

IF(${LOCAL_TARGETS_ONLY} MATCHES OFF)
  MS_ADD_STATIC_LIBRARY(${MS_PROJECT_NAME} ${ALL_FILES_LIFESTUFF_DIR})
  MS_ADD_EXECUTABLE(TESTpublic_id Tests ${PUBLIC_ID_TEST_CC} ${TESTS_MAIN_CC})
  MS_ADD_EXECUTABLE(TESTuser_credentials Tests ${CLIENT_CONTROLLER_TEST_CC} ${TESTS_MAIN_CC})
  MS_ADD_EXECUTABLE(TESTuser_storage Tests ${USER_STORAGE_TEST_CC} ${TESTS_MAIN_CC})
  MS_ADD_EXECUTABLE(TESTapi Tests ${API_TEST_CC} ${TESTS_MAIN_CC})
  TARGET_LINK_LIBRARIES(lifestuff_static lifestuff_detail_static maidsafe_pd_static)
  TARGET_LINK_LIBRARIES(TESTpublic_id lifestuff_static gtest_static)
  TARGET_LINK_LIBRARIES(TESTuser_credentials lifestuff_static gtest_static)
  TARGET_LINK_LIBRARIES(TESTuser_storage lifestuff_static gtest_static)
  TARGET_LINK_LIBRARIES(TESTapi lifestuff_static gtest_static)
ENDIF()

# This target allows the library to be installed without building all project targets
IF(MSVC)
  ADD_CUSTOM_TARGET(install_fast ${CMAKE_COMMAND} -DBUILD_TYPE=$<CONFIGURATION> -P ${CMAKE_BINARY_DIR}/cmake_install.cmake)
ELSE()
  ADD_CUSTOM_TARGET(install_fast ${CMAKE_COMMAND} -DBUILD_TYPE=${CMAKE_BUILD_TYPE} -P ${CMAKE_BINARY_DIR}/cmake_install.cmake)
ENDIF()
ADD_DEPENDENCIES(install_fast lifestuff_detail_static lifestuff_local_static)
IF(${LOCAL_TARGETS_ONLY} MATCHES OFF)
  ADD_DEPENDENCIES(install_fast lifestuff_static)
ENDIF()


###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
INCLUDE(maidsafe_standard_flags)

SET_TARGET_PROPERTIES(lifestuff_local_static
                      TESTlifestuff_general
                      TESTpublic_id_local
                      TESTuser_credentials_local
                      TESTuser_storage_local
                      TESTapi_local
                      PROPERTIES COMPILE_FLAGS -DLOCAL_TARGETS_ONLY)

IF(MSVC)
  SET_SOURCE_FILES_PROPERTIES(${PATH_TO_SRC}/detail/data_atlas.pb.cc
                              ${PATH_TO_SRC}/detail/data_types.pb.cc
                              ${PATH_TO_SRC}/detail/lifestuff_messages.pb.cc
                                PROPERTIES COMPILE_FLAGS "/W0")
ELSEIF(UNIX)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")
  SET_SOURCE_FILES_PROPERTIES(${PATH_TO_SRC}/detail/data_atlas.pb.cc
                              ${PATH_TO_SRC}/detail/data_types.pb.cc
                              ${PATH_TO_SRC}/detail/lifestuff_messages.pb.cc
                                PROPERTIES COMPILE_FLAGS "-w")
ENDIF()


###################################################################################################
# Tests                                                                                           #
###################################################################################################
ADD_STYLE_TEST(${STYLE_ALL}
               ${LIFESTUFF_TESTS_CC}
               ${CLIENT_CONTROLLER_TEST_CC}
               ${PUBLIC_ID_TEST_CC}
               ${USER_STORAGE_TEST_CC}
               ${API_TEST_CC})

ADD_GTESTS(TESTlifestuff_general)
ADD_GTESTS(TESTpublic_id_local)
ADD_GTESTS(TESTuser_credentials_local)
ADD_GTESTS(TESTuser_storage_local)
ADD_GTESTS(TESTapi_local)

TEST_SUMMARY_OUTPUT()


###################################################################################################
# Install details                                                                                 #
###################################################################################################
FINAL_MESSAGE()

IF(${LOCAL_TARGETS_ONLY} MATCHES ON)
  SET(JUST_LOCAL "The local targets flag IS currently set.\n")
  SET(JUST_LOCAL "${JUST_LOCAL}To switch to the all-inclusive version, please use -DLOCAL_TARGETS_ONLY=OFF\n")
ELSE()
  SET(JUST_LOCAL "The local targets flag IS NOT currently set\n")
  SET(JUST_LOCAL "${JUST_LOCAL}To switch to the local targets only version, please use -DLOCAL_TARGETS_ONLY=ON\n")
ENDIF()
MESSAGE(${JUST_LOCAL})
MESSAGE("================================================================================")

RENAME_OUTDATED_BUILT_EXES()

SET(LIFESTUFF_INSTALL_FILES
      ${PATH_TO_SRC}/lifestuff.h
      ${PATH_TO_SRC}/return_codes.h
      ${PATH_TO_SRC}/version.h
      ${PATH_TO_SRC}/lifestuff_api.h)

MS_INSTALL_LIBS(lifestuff_detail_static lifestuff_local_static)
IF(${LOCAL_TARGETS_ONLY} MATCHES OFF)
  MS_INSTALL_LIBS(lifestuff_static)
ENDIF()
MS_INSTALL_HEADERS(lifestuff ${LIFESTUFF_INSTALL_FILES})
MS_INSTALL_EXPORT()
