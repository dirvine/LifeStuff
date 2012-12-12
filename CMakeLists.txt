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

set(STYLE_ALL ${ALL_FILES_DETAIL_DIR} ${ALL_FILES_LIFESTUFF_DIR})
list(REMOVE_ITEM STYLE_ALL "${PATH_TO_DETAIL}/data_atlas.pb.h"
                           "${PATH_TO_DETAIL}/data_atlas.pb.cc")

source_group("LifeStuff Source Files" FILES ${SOURCE_FILES_LIFESTUFF_DIR})
source_group("LifeStuff Header Files" FILES ${HEADER_FILES_LIFESTUFF_DIR})
source_group("LifeStuff API Files" FILES ${API_FILES_LIFESTUFF_DIR}
                                         "${PATH_TO_INCLUDE}/lifestuff.h"
                                         "${PATH_TO_INCLUDE}/return_codes.h")
source_group("LifeStuff Detail Source Files" FILES ${SOURCE_FILES_DETAIL_DIR})
source_group("LifeStuff Detail Header Files" FILES ${HEADER_FILES_DETAIL_DIR})

####    TESTS    ####
set(TESTS_MAIN_CC "${PATH_TO_TESTS}/tests_main.cc")
set(CLIENT_CONTROLLER_TEST_CC "${PATH_TO_TESTS}/credentials_test.cc")
set(PUBLIC_ID_TEST_CC "${PATH_TO_TESTS}/public_id_test.cc"
                      "${PATH_TO_TESTS}/message_handler_test.cc")
set(STORAGE_TEST_CC "${PATH_TO_TESTS}/storage_test.cc")
set(ROUTINGS_HANDLER_TEST_CC "${PATH_TO_TESTS}/routings_handler_test.cc")
set(API_USER_CREDENTIALS_TEST_CC "${PATH_TO_TESTS}/api/api_user_credentials_test.cc"
                                 "${PATH_TO_TESTS}/api/api_test_resources.cc")
set(API_PUBLIC_ID_TEST_CC "${PATH_TO_TESTS}/api/api_public_id_test.cc"
                          "${PATH_TO_TESTS}/api/api_test_resources.cc")
set(API_VIRTUAL_DRIVE_TEST_CC "${PATH_TO_TESTS}/api/api_virtual_drive_test.cc"
                          "${PATH_TO_TESTS}/api/api_test_resources.cc")
set(API_REAL_DRIVE_TEST_CC "${PATH_TO_TESTS}/api/api_real_drive_test.cc")
set(LIFESTUFF_TESTS_CC "${PATH_TO_TESTS}/contacts_test.cc"
                       "${PATH_TO_TESTS}/session_test.cc"
                       "${PATH_TO_TESTS}/utils_test.cc")
set(TEST_UTILS_CC "${PATH_TO_TESTS}/test_utils.cc")
set(TEST_UTILS_H "${PATH_TO_TESTS}/test_utils.h")
set(TEST_UTILS_FILES ${TEST_UTILS_CC} ${TEST_UTILS_H})

source_group("Tests Source Files" FILES ${TESTS_MAIN_CC}
                                        ${CLIENT_CONTROLLER_TEST_CC}
                                        ${PUBLIC_ID_TEST_CC}
                                        ${STORAGE_TEST_CC}
                                        ${ROUTINGS_HANDLER_TEST_CC}
                                        ${API_USER_CREDENTIALS_TEST_CC}
                                        ${API_PUBLIC_ID_TEST_CC}
                                        ${API_VIRTUAL_DRIVE_TEST_CC}
                                        ${API_REAL_DRIVE_TEST_CC}
                                        ${LIFESTUFF_TESTS_CC}
                                        ${NETWORK_HELPER_CC}
                                        ${TEST_UTILS_CC})


###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
ms_add_static_library(lifestuff_detail ${ALL_FILES_DETAIL_DIR})
if(MAIDSAFE_TESTING)
  ms_add_executable(TESTlifestuff_general "Tests/LifeStuff" ${LIFESTUFF_TESTS_CC} ${TESTS_MAIN_CC})
  ms_add_executable(TESTlifestuff_routings_handler "Tests/LifeStuff" ${ROUTINGS_HANDLER_TEST_CC} ${TESTS_MAIN_CC})
  ms_add_executable(TESTlifestuff_credentials "Tests/LifeStuff" ${CLIENT_CONTROLLER_TEST_CC} ${TESTS_MAIN_CC})
  ms_add_executable(TESTlifestuff_public_id "Tests/LifeStuff" ${PUBLIC_ID_TEST_CC} ${TESTS_MAIN_CC})
  ms_add_executable(TESTlifestuff_storage "Tests/LifeStuff" ${STORAGE_TEST_CC} ${TESTS_MAIN_CC})
endif()

target_link_libraries(maidsafe_lifestuff_detail maidsafe_drive maidsafe_passport maidsafe_routing ${BoostRegexLibs})
if(MAIDSAFE_TESTING)
  target_link_libraries(TESTlifestuff_general maidsafe_lifestuff_detail ${BoostRegexLibs})
  target_link_libraries(TESTlifestuff_routings_handler maidsafe_lifestuff_detail ${BoostRegexLibs})
  target_link_libraries(TESTlifestuff_credentials maidsafe_lifestuff_detail ${BoostRegexLibs})
  target_link_libraries(TESTlifestuff_public_id maidsafe_lifestuff_detail ${BoostRegexLibs})
  target_link_libraries(TESTlifestuff_storage maidsafe_lifestuff_detail ${BoostRegexLibs})
endif()

ms_add_static_library(lifestuff ${ALL_FILES_LIFESTUFF_DIR})

add_library(lifestuff_python_api SHARED ${PATH_TO_SRC}/python_bindings/lifestuff_python_api.cc)
if(NO_JUST_THREADS AND CMAKE_COMPILER_IS_GNUCXX)
  target_link_libraries(lifestuff_python_api maidsafe_lifestuff maidsafe_lifestuff_manager ${BoostPythonLibs} stdc++ )
elseif(CMAKE_COMPILER_IS_GNUCXX)
  target_link_libraries(lifestuff_python_api maidsafe_lifestuff maidsafe_lifestuff_manager ${BoostPythonLibs} stdc++ justthread)
else()
  target_link_libraries(lifestuff_python_api maidsafe_lifestuff maidsafe_lifestuff_manager ${BoostPythonLibs})
endif()
if(WIN32)
  set_target_properties(lifestuff_python_api PROPERTIES SUFFIX ".pyd")
endif()
set_target_properties(lifestuff_python_api PROPERTIES PREFIX ""
                                                      DEBUG_POSTFIX ""
                                                      LABELS Lifestuff
                                                      FOLDER "MaidSafe/Python Bindings")

add_dependencies(lifestuff_python_api lifestuff_vault lifestuff_mgr pd_key_helper routing_key_helper)
add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:lifestuff_python_api> ${CMAKE_BINARY_DIR})
add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:lifestuff_python_api> ${CMAKE_SOURCE_DIR}/tools)
add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:lifestuff_vault> ${CMAKE_BINARY_DIR})
add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:lifestuff_mgr> ${CMAKE_BINARY_DIR})
add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:vault_key_helper> ${CMAKE_BINARY_DIR})
add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:routing_key_helper> ${CMAKE_BINARY_DIR})

if(MAIDSAFE_TESTING)
  ms_add_executable(TESTlifestuff_api_user_credentials "Tests/LifeStuff" ${API_USER_CREDENTIALS_TEST_CC} ${TESTS_MAIN_CC} ${NETWORK_HELPER_FILES})
  ms_add_executable(TESTlifestuff_api_public_id "Tests/LifeStuff" ${API_PUBLIC_ID_TEST_CC} ${TESTS_MAIN_CC} ${NETWORK_HELPER_FILES})
  ms_add_executable(TESTlifestuff_api_virtual_drive "Tests/LifeStuff" ${API_VIRTUAL_DRIVE_TEST_CC} ${TESTS_MAIN_CC} ${TEST_UTILS_FILES} ${NETWORK_HELPER_FILES})
  ms_add_executable(TESTlifestuff_api_real_drive "Tests/LifeStuff" ${API_REAL_DRIVE_TEST_CC} ${TEST_UTILS_FILES})
endif()

target_link_libraries(maidsafe_lifestuff maidsafe_private maidsafe_pd maidsafe_lifestuff_detail)
if(MAIDSAFE_TESTING)
  target_link_libraries(TESTlifestuff_api_user_credentials maidsafe_lifestuff maidsafe_lifestuff_manager ${BoostIostreamsLibs} ${BoostRegexLibs})
  add_dependencies(TESTlifestuff_api_user_credentials lifestuff_vault pd_key_helper lifestuff_mgr ${BoostRegexLibs})
  target_link_libraries(TESTlifestuff_api_public_id maidsafe_lifestuff maidsafe_lifestuff_manager ${BoostIostreamsLibs} ${BoostRegexLibs})
  add_dependencies(TESTlifestuff_api_public_id lifestuff_vault pd_key_helper lifestuff_mgr ${BoostRegexLibs})
  target_link_libraries(TESTlifestuff_api_virtual_drive maidsafe_lifestuff maidsafe_lifestuff_manager ${BoostIostreamsLibs} ${BoostRegexLibs})
  add_dependencies(TESTlifestuff_api_virtual_drive lifestuff_vault pd_key_helper lifestuff_mgr ${BoostRegexLibs})
  target_link_libraries(TESTlifestuff_api_real_drive maidsafe_drive ${BoostRegexLibs})
endif()

include_directories(${PYTHON_INCLUDE_DIRS})
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

if(MAIDSAFE_TESTING)
  set_target_properties(TESTlifestuff_api_user_credentials TESTlifestuff_api_public_id TESTlifestuff_api_virtual_drive
                        PROPERTIES COMPILE_DEFINITIONS TOOLS_PATH=${CMAKE_SOURCE_DIR}/tools)
endif()

###################################################################################################
# Tests                                                                                           #
###################################################################################################
if(MAIDSAFE_TESTING)
  add_style_test(${STYLE_ALL}
                 ${LIFESTUFF_TESTS_CC}
                 ${CLIENT_CONTROLLER_TEST_CC}
                 ${PUBLIC_ID_TEST_CC}
                 ${STORAGE_TEST_CC}
                 ${ROUTINGS_HANDLER_TEST_CC}
                 ${API_USER_CREDENTIALS_TEST_CC}
                 ${API_PUBLIC_ID_TEST_CC}
                 ${API_VIRTUAL_DRIVE_TEST_CC}
                 ${API_REAL_DRIVE_TEST_CC}
                 ${NETWORK_HELPER_STYLE})

  add_gtests(TESTlifestuff_general)
  add_gtests(TESTlifestuff_api_user_credentials)
  add_gtests(TESTlifestuff_api_public_id)
  add_gtests(TESTlifestuff_api_virtual_drive)
  add_gtests(TESTlifestuff_api_real_drive)

  label_as_critical_tests(SessionTest.BEH_SetsGetsAndReset
                          SessionTest.BEH_SessionName
                          SessionTest.BEH_SerialisationAndParsing
                          UtilsTest.BEH_WordValidity
                          UtilsTest.BEH_PinValidity
                          OneUserApiTest.FUNC_LoggedInState
                          OneUserApiTest.FUNC_IncorrectLoginLogoutSequences
                          OneUserApiTest.FUNC_CreateLogoutLoginLogout
                          OneUserApiTest.FUNC_ChangeCredentials
                          OneUserApiTest.FUNC_CreateInvalidUsers
                          OneUserApiTest.FUNC_ChangeCredentialsAndLogOut
                          OneUserApiTest.FUNC_LogInFromTwoPlaces
                          OneUserApiTest.FUNC_LogInAfterCreateUser
                          OneUserApiTest.FUNC_CreatePublicIdCases
                          OneUserApiTest.FUNC_AddInvalidContact
                          TwoUsersApiTest.FUNC_SendFileSaveToGivenPath
                          TwoUsersApiTest.FUNC_SendFileSaveToDefaultLocation
                          TwoUsersApiTest.FUNC_SendFileAcceptToDeletedDefaultLocation
                          TwoUsersApiTest.FUNC_SendFileWithRejection
                          #TwoUsersApiTest.FUNC_RemoveContact
                          #TwoUsersApiTest.FUNC_RemoveContactAddContact
                          TwoUsersApiTest.FUNC_AddContactWithMessage
                          #TwoUsersApiTest.FUNC_AddThenRemoveOfflineUser
                          TwoUsersApiTest.FUNC_ChangeProfilePicture
                          )

  add_project_experimental()
  test_summary_output()
endif()
