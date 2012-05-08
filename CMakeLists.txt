#==============================================================================#
#                                                                              #
#  Copyright (c) 2012 MaidSafe.net limited                                     #
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


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

cmake_minimum_required(VERSION 2.8.7 FATAL_ERROR)
project(lifestuff)

if(NOT LOCAL_TARGETS_ONLY)
  set(LOCAL_TARGETS_ONLY OFF)
endif()

set(PROTO_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
file(GLOB_RECURSE PROTO_FILES RELATIVE ${PROTO_SOURCE_DIR} "${PROTO_SOURCE_DIR}/maidsafe/*.proto")
include(../../cmake_modules/maidsafe_standard_setup.cmake)

include_directories(${common_SOURCE_DIR}/include)
include_directories(${private_SOURCE_DIR}/include)
include_directories(${encrypt_SOURCE_DIR}/include)
include_directories(${drive_SOURCE_DIR}/include)
include_directories(${pki_SOURCE_DIR}/include)
include_directories(${passport_SOURCE_DIR}/include)
if(NOT ${LOCAL_TARGETS_ONLY})
  include_directories(${transport_SOURCE_DIR}/include)
  include_directories(${dht_SOURCE_DIR}/include)
  include_directories(${pd_SOURCE_DIR}/include)
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

target_link_libraries(maidsafe_lifestuff_local maidsafe_drive maidsafe_passport)
target_link_libraries(TESTlifestuff_local maidsafe_lifestuff_local)
target_link_libraries(TESTauthentication_local maidsafe_lifestuff_local)
target_link_libraries(TESTpublic_id_local maidsafe_lifestuff_local)
target_link_libraries(TESTuser_credentials_local maidsafe_lifestuff_local)
target_link_libraries(TESTuser_storage_local maidsafe_lifestuff_local)
target_link_libraries(TESTapi_local maidsafe_lifestuff_local)

if(NOT ${LOCAL_TARGETS_ONLY})
  ms_add_static_library(lifestuff ${ALL_FILES_LIFESTUFF_DIR})
  ms_add_executable(TESTlifestuff Tests ${ALL_FILES_LIFESTUFF_TESTS_DIR} ${TESTS_MAIN_CC})
  ms_add_executable(TESTauthentication Tests ${AUTHENTICATION_TEST_CC} ${TESTS_MAIN_CC})
  ms_add_executable(TESTpublic_id Tests ${PUBLIC_ID_TEST_CC} ${TESTS_MAIN_CC})
  ms_add_executable(TESTuser_credentials Tests ${CLIENT_CONTROLLER_TEST_CC} ${TESTS_MAIN_CC})
  ms_add_executable(TESTuser_storage Tests ${USER_STORAGE_TEST_CC} ${TESTS_MAIN_CC})
  ms_add_executable(TESTapi Tests ${API_TEST_CC} ${TESTS_MAIN_CC})
  target_link_libraries(maidsafe_lifestuff maidsafe_drive maidsafe_passport maidsafe_pd)
  target_link_libraries(TESTlifestuff maidsafe_lifestuff)
  target_link_libraries(TESTauthentication maidsafe_lifestuff)
  target_link_libraries(TESTpublic_id maidsafe_lifestuff)
  target_link_libraries(TESTuser_credentials maidsafe_lifestuff)
  target_link_libraries(TESTuser_storage maidsafe_lifestuff)
  target_link_libraries(TESTapi maidsafe_lifestuff)
endif()

rename_outdated_built_exes()


###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
include(maidsafe_standard_flags)
ms_disable_warnings(${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_atlas.pb.cc
                    ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/data_types.pb.cc
                    ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff_messages.pb.cc)

set_target_properties(maidsafe_lifestuff_local
                      TESTlifestuff_local
                      TESTauthentication_local
                      TESTpublic_id_local
                      TESTuser_credentials_local
                      TESTuser_storage_local
                      TESTapi_local
                      PROPERTIES COMPILE_FLAGS -DLOCAL_TARGETS_ONLY)

if(UNIX)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")
endif()
if(APPLE)
  add_definitions(-D_FILE_OFFSET_BITS=64)
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
if(${LOCAL_TARGETS_ONLY} MATCHES ON)
  message(STATUS "The local targets flag IS currently set.")
  message(STATUS "To switch to the all-inclusive version, please use -DLOCAL_TARGETS_ONLY=OFF")
else()
  message(STATUS "The local targets flag IS NOT currently set")
  message(STATUS "To switch to the local targets only version, please use -DLOCAL_TARGETS_ONLY=ON")
endif()

# set(LIFESTUFF_INSTALL_FILES
#       ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff.h
#       ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/return_codes.h
#       ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/version.h
#       ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff/lifestuff_api.h)
# 
# ms_install_libs(lifestuff_local_static)
# if(${LOCAL_TARGETS_ONLY} MATCHES OFF)
#   ms_install_libs(lifestuff_static)
# endif()
# ms_install_headers(lifestuff ${LIFESTUFF_INSTALL_FILES})
# ms_install_export()
