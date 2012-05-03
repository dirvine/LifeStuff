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


set(MS_PROJECT_NAME lifestuff)

cmake_minimum_required(VERSION 2.8.4 FATAL_ERROR)
message("================================================================================\n")

get_filename_component(CMAKE_BUILD_TYPE_DIR ${CMAKE_BINARY_DIR} NAME)

# Variable MSVC is not set until after "PROJECT" command below
if(CMAKE_BUILD_TYPE_DIR MATCHES "Win_MSVC")
  set(CMAKE_BUILD_TYPE_DIR Release)
elseif(CMAKE_BUILD_TYPE_DIR MATCHES "kdev")
  set(CMAKE_BUILD_TYPE_DIR Debug)
  set(KDEV 1)
endif()

if(NOT ${CMAKE_C_COMPILER_WORKS})
  message(FATAL_ERROR "No generator previously specified.\nTo see a full list of generators, run:\n\tcmake --help\n")
endif()

# This "PROJECT" command resets CMAKE_BUILD_TYPE, hence it's copied from CMAKE_BUILD_TYPE_DIR which is set above.
if((CMAKE_BUILD_TYPE_DIR MATCHES "Release") OR (DEFINED ${KDEV}))
  project(${MS_PROJECT_NAME})
else()
  string(TOLOWER ${CMAKE_BUILD_TYPE_DIR} MS_PROJECT_NAME_APPENDIX)
  project(${MS_PROJECT_NAME}_${MS_PROJECT_NAME_APPENDIX})
endif()

set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE_DIR} CACHE INTERNAL "Except for MSVC, the build type is set by running cmake from the appropriate build subdirectory e.g. for a Debug build, \"cd build/Linux/Debug && cmake ../../..\"." FORCE)

if(NOT LOCAL_TARGETS_ONLY)
  set(LOCAL_TARGETS_ONLY OFF)
endif()


###################################################################################################
# MaidSafe Common, Private, Encrypt, DHT, Drive, PKI and Passport library search                  #
###################################################################################################
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/build)
include(maidsafe_find_common)
add_maidsafe_library(MaidSafe-Private)
add_maidsafe_library(MaidSafe-Encrypt)
add_maidsafe_library(MaidSafe-Drive)
add_maidsafe_library(MaidSafe-PKI)
add_maidsafe_library(MaidSafe-Passport)
if(${LOCAL_TARGETS_ONLY} MATCHES OFF)
  add_maidsafe_library(MaidSafe-Transport)
  add_maidsafe_library(MaidSafe-DHT)
  add_maidsafe_library(MaidSafe-PD)
endif()


###################################################################################################
# Callback File System / Fuse library search                                                      #
###################################################################################################
if(WIN32)
  include(maidsafe_find_cbfs)
  set(INCLUDE_DIRS ${INCLUDE_DIRS} ${Cbfs_INCLUDE_DIR})
  set(LIBS_DIRS ${LIBS_DIRS} ${Cbfs_LIBRARY_DIR})
  set(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Cbfs_LIBRARY_DIR})
  set(Fuse_LIBRARY ${Cbfs_LIBRARY})
endif()


###################################################################################################
# Standard setup                                                                                  #
###################################################################################################
set(PROTO_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
file(GLOB_RECURSE PROTO_FILES RELATIVE ${PROTO_SOURCE_DIR} "${PROTO_SOURCE_DIR}/maidsafe/*.proto")
include(maidsafe_standard_setup)
handle_versions(${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/version.h)


###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
####    CODE    ####
file(GLOB SOURCE_FILES_LIFESTUFF_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/*.cc")
file(GLOB HEADER_FILES_LIFESTUFF_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/*.h")
set(ALL_FILES_LIFESTUFF_DIR ${SOURCE_FILES_LIFESTUFF_DIR} ${HEADER_FILES_LIFESTUFF_DIR})

set(STYLE_ALL ${ALL_FILES_LIFESTUFF_DIR})
list(REMOVE_ITEM STYLE_ALL "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_atlas.pb.h"
                           "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_atlas.pb.cc"
                           "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_types.pb.h"
                           "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_types.pb.cc"
                           "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff_messages.pb.h"
                           "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff_messages.pb.cc")
source_group("LifeStuff Source Files" FILES ${SOURCE_FILES_LIFESTUFF_DIR})
source_group("LifeStuff Header Files" FILES ${HEADER_FILES_LIFESTUFF_DIR})

####    TESTS    ####
file(GLOB SOURCE_FILES_LIFESTUFF_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/*.cc")
file(GLOB HEADER_FILES_LIFESTUFF_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/*.h")
set(ALL_FILES_LIFESTUFF_TESTS_DIR ${SOURCE_FILES_LIFESTUFF_TESTS_DIR} ${HEADER_FILES_LIFESTUFF_TESTS_DIR})
source_group("Tests Source Files" FILES ${SOURCE_FILES_LIFESTUFF_TESTS_DIR})
source_group("Tests Header Files" FILES ${HEADER_FILES_LIFESTUFF_TESTS_DIR})

set(TESTS_MAIN_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/tests_main.cc")
set(AUTHENTICATION_TEST_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/authentication_test.cc")
set(CLIENT_CONTROLLER_TEST_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/user_credentials_test.cc")
set(PUBLIC_ID_TEST_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/public_id_test.cc"
                      "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/message_handler_test.cc")
set(USER_STORAGE_TEST_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/user_storage_test.cc")
set(API_TEST_CC "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/tests/full_api_test.cc")

list(REMOVE_ITEM ALL_FILES_LIFESTUFF_TESTS_DIR ${AUTHENTICATION_TEST_CC}
                                               ${CLIENT_CONTROLLER_TEST_CC}
                                               ${PUBLIC_ID_TEST_CC}
                                               ${USER_STORAGE_TEST_CC}
                                               ${API_TEST_CC})


###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
ms_add_static_library(lifestuff_local ${ALL_FILES_LIFESTUFF_DIR})
ms_add_executable(TESTlifestuff_local Tests ${ALL_FILES_LIFESTUFF_TESTS_DIR} ${TESTS_MAIN_CC})
ms_add_executable(TESTauthentication_local Tests ${AUTHENTICATION_TEST_CC} ${TESTS_MAIN_CC})
ms_add_executable(TESTpublic_id_local Tests ${PUBLIC_ID_TEST_CC} ${TESTS_MAIN_CC})
ms_add_executable(TESTuser_credentials_local Tests ${CLIENT_CONTROLLER_TEST_CC} ${TESTS_MAIN_CC})
ms_add_executable(TESTuser_storage_local Tests ${USER_STORAGE_TEST_CC} ${TESTS_MAIN_CC})
ms_add_executable(TESTapi_local Tests ${API_TEST_CC} ${TESTS_MAIN_CC})

target_link_libraries(lifestuff_local_static maidsafe_drive_static maidsafe_passport_static boost_regex)
target_link_libraries(TESTlifestuff_local lifestuff_local_static gtest_static)
target_link_libraries(TESTauthentication_local lifestuff_local_static gtest_static)
target_link_libraries(TESTpublic_id_local lifestuff_local_static gtest_static)
target_link_libraries(TESTuser_credentials_local lifestuff_local_static gtest_static)
target_link_libraries(TESTuser_storage_local lifestuff_local_static gtest_static)
target_link_libraries(TESTapi_local lifestuff_local_static gtest_static)

if(${LOCAL_TARGETS_ONLY} MATCHES OFF)
  ms_add_static_library(${MS_PROJECT_NAME} ${ALL_FILES_LIFESTUFF_DIR})
  ms_add_executable(TESTlifestuff Tests ${ALL_FILES_LIFESTUFF_TESTS_DIR} ${TESTS_MAIN_CC})
  ms_add_executable(TESTauthentication Tests ${AUTHENTICATION_TEST_CC} ${TESTS_MAIN_CC})
  ms_add_executable(TESTpublic_id Tests ${PUBLIC_ID_TEST_CC} ${TESTS_MAIN_CC})
  ms_add_executable(TESTuser_credentials Tests ${CLIENT_CONTROLLER_TEST_CC} ${TESTS_MAIN_CC})
  ms_add_executable(TESTuser_storage Tests ${USER_STORAGE_TEST_CC} ${TESTS_MAIN_CC})
  ms_add_executable(TESTapi Tests ${API_TEST_CC} ${TESTS_MAIN_CC})
  target_link_libraries(lifestuff_static maidsafe_drive_static maidsafe_passport_static maidsafe_pd_static boost_regex)
  target_link_libraries(TESTlifestuff lifestuff_static gtest_static)
  target_link_libraries(TESTauthentication lifestuff_static gtest_static)
  target_link_libraries(TESTpublic_id lifestuff_static gtest_static)
  target_link_libraries(TESTuser_credentials lifestuff_static gtest_static)
  target_link_libraries(TESTuser_storage lifestuff_static gtest_static)
  target_link_libraries(TESTapi lifestuff_static gtest_static)
endif()



###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
include(maidsafe_standard_flags)

set_target_properties(lifestuff_local_static
                      TESTlifestuff_local
                      TESTauthentication_local
                      TESTpublic_id_local
                      TESTuser_credentials_local
                      TESTuser_storage_local
                      TESTapi_local
                      PROPERTIES COMPILE_FLAGS -DLOCAL_TARGETS_ONLY)

if(MSVC)
  set_source_files_properties(${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_atlas.pb.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_types.pb.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff_messages.pb.cc
                                PROPERTIES COMPILE_FLAGS "/W0")
elseif(UNIX)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")
  set_source_files_properties(${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_atlas.pb.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_types.pb.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff_messages.pb.cc
                                PROPERTIES COMPILE_FLAGS "-w")
endif()


###################################################################################################
# Tests                                                                                           #
###################################################################################################
add_style_test(${STYLE_ALL}
               ${ALL_FILES_LIFESTUFF_TESTS_DIR}
               ${AUTHENTICATION_TEST_CC}
               ${CLIENT_CONTROLLER_TEST_CC}
               ${PUBLIC_ID_TEST_CC}
               ${USER_STORAGE_TEST_CC}
               ${API_TEST_CC})

add_gtests(TESTlifestuff_local)
add_gtests(TESTauthentication_local)
add_gtests(TESTpublic_id_local)
add_gtests(TESTuser_credentials_local)
add_gtests(TESTuser_storage_local)
add_gtests(TESTapi_local)

test_summary_output()


###################################################################################################
# Install details                                                                                 #
###################################################################################################
final_message()

if(${LOCAL_TARGETS_ONLY} MATCHES ON)
  set(JUST_LOCAL "The local targets flag IS currently set.\n")
  set(JUST_LOCAL "${JUST_LOCAL}To switch to the all-inclusive version, please use -DLOCAL_TARGETS_ONLY=OFF\n")
else()
  set(JUST_LOCAL "The local targets flag IS NOT currently set\n")
  set(JUST_LOCAL "${JUST_LOCAL}To switch to the local targets only version, please use -DLOCAL_TARGETS_ONLY=ON\n")
endif()
message(${JUST_LOCAL})
message("================================================================================")

rename_outdated_built_exes()

set(LIFESTUFF_INSTALL_FILES
      ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/return_codes.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/version.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff_api.h)

ms_install_libs(lifestuff_local_static)
if(${LOCAL_TARGETS_ONLY} MATCHES OFF)
  ms_install_libs(lifestuff_static)
endif()
ms_install_headers(lifestuff ${LIFESTUFF_INSTALL_FILES})
ms_install_export()
