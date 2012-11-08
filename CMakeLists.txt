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

set(PROTO_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
file(GLOB_RECURSE PROTO_FILES RELATIVE ${PROTO_SOURCE_DIR} "${PROTO_SOURCE_DIR}/maidsafe/*.proto")
include(../../cmake_modules/maidsafe_standard_setup.cmake)

include_directories(${common_SOURCE_DIR}/include)
include_directories(${private_SOURCE_DIR}/include)
include_directories(${encrypt_SOURCE_DIR}/include)
include_directories(${drive_SOURCE_DIR}/include)
include_directories(${passport_SOURCE_DIR}/include)
include_directories(${rudp_SOURCE_DIR}/include)
include_directories(${routing_SOURCE_DIR}/include)
include_directories(${pd_SOURCE_DIR}/include)


###################################################################################################
# Callback File System / Fuse library search                                                      #
###################################################################################################
if(WIN32 OR APPLE)
  include_directories(${DRIVE_THIRD_PARTY_INCLUDES})
endif()

###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
set(PATH_TO_INCLUDE ${PROJECT_SOURCE_DIR}/include/maidsafe/lifestuff)
set(PATH_TO_SRC ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff)
set(PATH_TO_DETAIL ${PATH_TO_SRC}/detail)
set(PATH_TO_TESTS ${PATH_TO_SRC}/tests)
set(PATH_TO_COMMAND_LINE ${PATH_TO_SRC}/command_line)

####    CODE    ####
file(GLOB SOURCE_FILES_LIFESTUFF_DIR "${PATH_TO_SRC}/lifestuff_api.cc"
                                     "${PATH_TO_SRC}/lifestuff_impl.cc"
                                     "${PATH_TO_SRC}/rcs_helper.cc")
file(GLOB HEADER_FILES_LIFESTUFF_DIR "${PATH_TO_SRC}/lifestuff_impl.h"
                                     "${PATH_TO_SRC}/rcs_helper.h")
file(GLOB API_FILES_LIFESTUFF_DIR "${PATH_TO_INCLUDE}/lifestuff_api.h")
set(ALL_FILES_LIFESTUFF_DIR ${SOURCE_FILES_LIFESTUFF_DIR} ${HEADER_FILES_LIFESTUFF_DIR} ${API_FILES_LIFESTUFF_DIR})

file(GLOB SOURCE_FILES_DETAIL_DIR "${PATH_TO_DETAIL}/*.cc")
file(GLOB HEADER_FILES_DETAIL_DIR "${PATH_TO_DETAIL}/*.h")
set(ALL_FILES_DETAIL_DIR ${SOURCE_FILES_DETAIL_DIR}
                         ${HEADER_FILES_DETAIL_DIR}
                         "${PATH_TO_INCLUDE}/lifestuff.h"
                         "${PATH_TO_INCLUDE}/return_codes.h")

file(GLOB SOURCE_FILES_COMMAND_LINE_DIR "${PATH_TO_COMMAND_LINE}/*.cc")
set(ALL_FILES_COMMAND_LINE_DIR ${SOURCE_FILES_COMMAND_LINE_DIR})

set(STYLE_ALL ${ALL_FILES_DETAIL_DIR} ${ALL_FILES_LIFESTUFF_DIR} ${ALL_FILES_COMMAND_LINE_DIR})
list(REMOVE_ITEM STYLE_ALL "${PATH_TO_DETAIL}/data_atlas.pb.h"
                           "${PATH_TO_DETAIL}/data_atlas.pb.cc")

source_group("LifeStuff Source Files" FILES ${SOURCE_FILES_LIFESTUFF_DIR})
source_group("LifeStuff Header Files" FILES ${HEADER_FILES_LIFESTUFF_DIR})
source_group("LifeStuff API Files" FILES ${API_FILES_LIFESTUFF_DIR}
                                         "${PATH_TO_INCLUDE}/lifestuff.h"
                                         "${PATH_TO_INCLUDE}/return_codes.h")
source_group("LifeStuff Detail Source Files" FILES ${SOURCE_FILES_DETAIL_DIR})
source_group("LifeStuff Detail Header Files" FILES ${HEADER_FILES_DETAIL_DIR})
source_group("LifeStuff Command Line Source Files" FILES ${SOURCE_FILES_COMMAND_LINE_DIR})

####    TESTS    ####
set(TESTS_MAIN_CC "${PATH_TO_TESTS}/tests_main.cc")
set(CLIENT_CONTROLLER_TEST_CC "${PATH_TO_TESTS}/credentials_test.cc")
set(PUBLIC_ID_TEST_CC "${PATH_TO_TESTS}/public_id_test.cc"
                      "${PATH_TO_TESTS}/message_handler_test.cc")
set(STORAGE_TEST_CC "${PATH_TO_TESTS}/storage_test.cc")
set(ROUTINGS_HANDLER_TEST_CC "${PATH_TO_TESTS}/routings_handler_test.cc")
set(API_TEST_CC "${PATH_TO_TESTS}/api/full_api_test.cc"
                "${PATH_TO_TESTS}/api/api_user_credentials_test.cc"
                "${PATH_TO_TESTS}/api/api_public_id_test.cc"
                "${PATH_TO_TESTS}/api/api_test_resources.cc")
set(LIFESTUFF_TESTS_CC "${PATH_TO_TESTS}/contacts_test.cc"
                       "${PATH_TO_TESTS}/session_test.cc"
                       "${PATH_TO_TESTS}/utils_test.cc")
set(NETWORK_HELPER_CC "${PATH_TO_TESTS}/network_helper.cc")
set(NETWORK_HELPER_H "${PATH_TO_TESTS}/network_helper.h")
set(NETWORK_HELPER_PROTOS "${PATH_TO_TESTS}/bootstrap.pb.cc"
                          "${PATH_TO_TESTS}/bootstrap.pb.h"
                          "${PATH_TO_TESTS}/bootstrap_pb.h"
                          "${PATH_TO_TESTS}/bootstrap.proto")
set(NETWORK_HELPER_FILES ${NETWORK_HELPER_CC} ${NETWORK_HELPER_H} ${NETWORK_HELPER_PROTOS})

source_group("Tests Source Files" FILES ${TESTS_MAIN_CC}
                                        ${CLIENT_CONTROLLER_TEST_CC}
                                        ${PUBLIC_ID_TEST_CC}
                                        ${STORAGE_TEST_CC}
                                        ${ROUTINGS_HANDLER_TEST_CC}
                                        ${API_TEST_CC}
                                        ${LIFESTUFF_TESTS_CC}
                                        ${NETWORK_HELPER_CC})

source_group("Tests Header Files" FILES ${PROJECT_BINARY_DIR}/keys_helper.h
                                        ${NETWORK_HELPER_H})

source_group("Tests Proto Files" FILES ${NETWORK_HELPER_PROTOS})


###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
ms_add_static_library(lifestuff_detail ${ALL_FILES_DETAIL_DIR})
ms_add_executable(TESTlifestuff_general "Tests/LifeStuff" ${LIFESTUFF_TESTS_CC} ${TESTS_MAIN_CC})
ms_add_executable(TESTlifestuff_routings_handler "Tests/LifeStuff" ${ROUTINGS_HANDLER_TEST_CC} ${TESTS_MAIN_CC})
ms_add_executable(TESTlifestuff_credentials "Tests/LifeStuff" ${CLIENT_CONTROLLER_TEST_CC} ${TESTS_MAIN_CC})
ms_add_executable(TESTlifestuff_public_id "Tests/LifeStuff" ${PUBLIC_ID_TEST_CC} ${TESTS_MAIN_CC})
ms_add_executable(TESTlifestuff_storage "Tests/LifeStuff" ${STORAGE_TEST_CC} ${TESTS_MAIN_CC})

target_link_libraries(maidsafe_lifestuff_detail maidsafe_drive maidsafe_passport maidsafe_routing)
target_link_libraries(TESTlifestuff_general maidsafe_lifestuff_detail)
target_link_libraries(TESTlifestuff_routings_handler maidsafe_lifestuff_detail)
target_link_libraries(TESTlifestuff_credentials maidsafe_lifestuff_detail)
target_link_libraries(TESTlifestuff_public_id maidsafe_lifestuff_detail)
target_link_libraries(TESTlifestuff_storage maidsafe_lifestuff_detail)

ms_add_static_library(lifestuff ${ALL_FILES_LIFESTUFF_DIR})
ms_add_executable(TESTlifestuff_api "Tests/LifeStuff" ${API_TEST_CC} ${TESTS_MAIN_CC} ${NETWORK_HELPER_FILES})
ms_add_executable(command_line_lifestuff "Tools" ${ALL_FILES_COMMAND_LINE_DIR})

target_link_libraries(maidsafe_lifestuff maidsafe_private maidsafe_pd maidsafe_lifestuff_detail)
add_custom_command(TARGET maidsafe_lifestuff
                   PRE_BUILD
                   COMMAND ${CMAKE_COMMAND} -E echo "#ifndef MAIDSAFE_PD_CLIENT_KEYS_HELPER_H_" > ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "#define MAIDSAFE_PD_CLIENT_KEYS_HELPER_H_" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "// NOTE: DO NOT EDIT.  This file is auto generated by CMake.  Any changes made will be overwritten." >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "#include \"boost/filesystem/path.hpp\"" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "namespace maidsafe {" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&

                           ${CMAKE_COMMAND} -E echo "" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "namespace pd {" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "boost::filesystem::path kVaultExecutable() {" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "  static boost::filesystem::path exe(\"$<TARGET_FILE:lifestuff_vault>\");  // NOLINT" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "  return exe;" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "}" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "boost::filesystem::path kKeysHelperExecutable() {" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "  static boost::filesystem::path exe(\"$<TARGET_FILE:pd_key_helper>\");  // NOLINT" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "  return exe;" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "}" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "}  //  namespace pd" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&

                           ${CMAKE_COMMAND} -E echo "namespace priv {" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "boost::filesystem::path kLifeStuffManagerExecutable() {" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "  static boost::filesystem::path exe(\"$<TARGET_FILE:lifestuff_mgr>\");  // NOLINT" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "  return exe;" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "}" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "boost::filesystem::path kLifeStuffManagerTestExecutable() {" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "  static boost::filesystem::path exe(\"$<TARGET_FILE:lifestuff_manager_test>\");  // NOLINT" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "  return exe;" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "}" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "}  //  namespace priv" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&

                           ${CMAKE_COMMAND} -E echo "}  //  namespace maidsafe" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "" >> ${PROJECT_BINARY_DIR}/keys_helper.h &&
                           ${CMAKE_COMMAND} -E echo "#endif  // MAIDSAFE_PD_CLIENT_KEYS_HELPER_H_" >> ${PROJECT_BINARY_DIR}/keys_helper.h
                   VERBATIM
                   )
target_link_libraries(TESTlifestuff_api maidsafe_lifestuff maidsafe_lifestuff_manager_test ${BoostIostreamsLibs} ${BoostRegexLibs})
add_dependencies(TESTlifestuff_api pd-vault pd-keys-helper lifestuff_manager_test)
target_link_libraries(command_line_lifestuff maidsafe_lifestuff maidsafe_lifestuff_manager_test)
add_dependencies(command_line_lifestuff pd-vault pd-keys-helper lifestuff_manager_test)

include_directories(${PROJECT_BINARY_DIR})

rename_outdated_built_exes()


###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
include(maidsafe_standard_flags)

file(GLOB_RECURSE PROTO_SOURCE_FILES "${PATH_TO_SRC}/*.pb.cc")
ms_disable_warnings(${PROTO_SOURCE_FILES})

if(UNIX)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")
endif()


###################################################################################################
# Tests                                                                                           #
###################################################################################################
add_style_test(${STYLE_ALL}
               ${LIFESTUFF_TESTS_CC}
               ${CLIENT_CONTROLLER_TEST_CC}
               ${PUBLIC_ID_TEST_CC}
               ${STORAGE_TEST_CC}
               ${ROUTINGS_HANDLER_TEST_CC}
               ${API_TEST_CC})

add_gtests(TESTlifestuff_general)
add_gtests(TESTlifestuff_api)

add_project_experimental()
test_summary_output()
