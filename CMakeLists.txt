#==================================================================================================#
#                                                                                                  #
#  Copyright (c) 2012 MaidSafe.net limited                                                         #
#                                                                                                  #
#  The following source code is property of MaidSafe.net limited and is not meant for external     #
#  use.  The use of this code is governed by the license file licence.txt found in the root        #
#  directory of this project and also on www.maidsafe.net.                                         #
#                                                                                                  #
#  You are not free to copy, amend or otherwise use this source code without the explicit written  #
#  permission of the board of directors of MaidSafe.net.                                           #
#                                                                                                  #
#==================================================================================================#


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

cmake_minimum_required(VERSION 2.8.10 FATAL_ERROR)
project(lifestuff)

include(../../cmake_modules/standard_setup.cmake)

include_directories(${common_SOURCE_DIR}/include)
include_directories(${passport_SOURCE_DIR}/include)
include_directories(${private_SOURCE_DIR}/include)
include_directories(${rudp_SOURCE_DIR}/include)
include_directories(${routing_SOURCE_DIR}/include)
include_directories(${nfs_SOURCE_DIR}/include)
include_directories(${encrypt_SOURCE_DIR}/include)
include_directories(${drive_SOURCE_DIR}/include)
if(WIN32 OR APPLE)
  include_directories(${DriveThirdPartyIncludes})
endif()


#==================================================================================================#
# Set up all files as GLOBs                                                                        #
#==================================================================================================#
set(LifestuffSourcesDir ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff)
glob_dir(Lifestuff ${LifestuffSourcesDir} LifeStuff)
glob_dir(LifestuffDetail ${LifestuffSourcesDir}/detail "LifeStuff Detail")


####    TESTS    ####
set(TESTS_MAIN_CC ${LifestuffSourcesDir}/tests/tests_main.cc)
set(USER_STORAGE_TEST_CC ${LifestuffSourcesDir}/tests/user_storage_test.cc)
set(USER_INPUT_TEST_CC ${LifestuffSourcesDir}/tests/user_input_test.cc)
set(TEST_UTILS_CC ${LifestuffSourcesDir}/tests/test_utils.cc)
set(TEST_UTILS_H ${LifestuffSourcesDir}/tests/test_utils.h)
set(TEST_UTILS_FILES ${TEST_UTILS_CC} ${TEST_UTILS_H})

source_group("Tests Source Files" FILES ${TESTS_MAIN_CC}
                                        ${USER_STORAGE_TEST_CC}
                                        ${USER_INPUT_TEST_CC}
                                        ${NETWORK_HELPER_CC}
                                        ${TEST_UTILS_CC})


#==================================================================================================#
# Define MaidSafe libraries and executables                                                        #
#==================================================================================================#
ms_add_static_library(lifestuff_detail ${LifestuffDetailAllFiles})
if(MaidsafeTesting)
  ms_add_executable(TESTlifestuff_user_storage "Tests/LifeStuff" ${USER_STORAGE_TEST_CC} ${TEST_UTILS_FILES} ${TESTS_MAIN_CC})
  ms_add_executable(TESTlifestuff_user_input "Tests/LifeStuff" ${USER_INPUT_TEST_CC} ${TESTS_MAIN_CC})
endif()

target_link_libraries(maidsafe_lifestuff_detail maidsafe_lifestuff_manager maidsafe_drive maidsafe_passport maidsafe_routing ${BoostRegexLibs})
if(MaidsafeTesting)
  target_link_libraries(TESTlifestuff_user_storage maidsafe_lifestuff_detail ${BoostRegexLibs})
  target_link_libraries(TESTlifestuff_user_input maidsafe_lifestuff ${BoostRegexLibs})
endif()

ms_add_static_library(lifestuff ${LifestuffAllFiles})

if(MaidsafeTesting)
  target_link_libraries(TESTlifestuff_user_input maidsafe_lifestuff ${BoostRegexLibs})
endif()

add_library(lifestuff_python_api SHARED ${LifestuffSourcesDir}/python_bindings/lifestuff_python_api.cc)
if(CMAKE_COMPILER_IS_GNUCXX)
  target_link_libraries(lifestuff_python_api maidsafe_lifestuff maidsafe_lifestuff_manager ${BoostPythonLibs} stdc++ ${JustThread_LIBRARIES})
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

                                                    #add_dependencies(lifestuff_python_api lifestuff_vault lifestuff_mgr pd_key_helper routing_key_helper)
add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:lifestuff_python_api> ${CMAKE_BINARY_DIR})
add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:lifestuff_python_api> ${CMAKE_SOURCE_DIR}/tools)
add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:lifestuff_vault> ${CMAKE_BINARY_DIR})
add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:lifestuff_mgr> ${CMAKE_BINARY_DIR})
#add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:vault_key_helper> ${CMAKE_BINARY_DIR})
#add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:routing_key_helper> ${CMAKE_BINARY_DIR})

target_link_libraries(maidsafe_lifestuff maidsafe_private maidsafe_vault maidsafe_lifestuff_detail maidsafe_lifestuff_manager)

include_directories(${PYTHON_INCLUDE_DIRS})
include_directories(${PROJECT_BINARY_DIR})

rename_outdated_built_exes()


#==================================================================================================#
# Set compiler and linker flags                                                                    #
#==================================================================================================#
include(standard_flags)
if(UNIX)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")
elseif(Cbfs_FOUND)
  add_definitions(-DHAVE_CBFS)
endif()


#==================================================================================================#
# Set Windows Registry Keys for WPF UI                                                             #
#==================================================================================================#

### Do NOT Switch \\ for / in the following lines
if(WIN32)
  set(REGISTRY_PATH "HKEY_CURRENT_USER\\Software\\MaidSafe\\LibPaths")
  if(CMAKE_CL_64)
    set(REGISTRY_PATH "${REGISTRY_PATH}\\x64")
  else()
    set(REGISTRY_PATH "${REGISTRY_PATH}\\x86")
  endif()
  # Debug Paths
  execute_process(COMMAND ${CMAKE_COMMAND} -E write_regv "${REGISTRY_PATH}\\Debug;CbfsLib" "${Cbfs_LIBRARY_DEBUG}")
  execute_process(COMMAND ${CMAKE_COMMAND} -E write_regv "${REGISTRY_PATH}\\Debug;JustThreadLib" "${JustThread_LIBRARY_DEBUG}")
  execute_process(COMMAND ${CMAKE_COMMAND} -E write_regv "${REGISTRY_PATH}\\Debug;NativeIncludeDir" "${lifestuff_SOURCE_DIR}/include")
  execute_process(COMMAND ${CMAKE_COMMAND} -E write_regv "${REGISTRY_PATH}\\Debug;NativeLibDir" "${maidsafe_BINARY_DIR}/Debug")
  # Release Paths
  execute_process(COMMAND ${CMAKE_COMMAND} -E write_regv "${REGISTRY_PATH}\\Release;CbfsLib" "${Cbfs_LIBRARY}")
  execute_process(COMMAND ${CMAKE_COMMAND} -E write_regv "${REGISTRY_PATH}\\Release;JustThreadLib" "${JustThread_LIBRARY}")
  execute_process(COMMAND ${CMAKE_COMMAND} -E write_regv "${REGISTRY_PATH}\\Release;NativeIncludeDir" "${lifestuff_SOURCE_DIR}/include")
  execute_process(COMMAND ${CMAKE_COMMAND} -E write_regv "${REGISTRY_PATH}\\Release;NativeLibDir" "${maidsafe_BINARY_DIR}/Release")
endif()


#==================================================================================================#
# Tests                                                                                            #
#==================================================================================================#
if(MaidsafeTesting)
  add_style_test()
  label_as_critical_tests()
  add_project_experimental()
  test_summary_output()
endif()
