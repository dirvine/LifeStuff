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
  target_link_libraries(lifestuff_python_api maidsafe_lifestuff maidsafe_lifestuff_manager ${BoostPythonLibs} ${PYTHON_LIBRARIES} stdc++ ${JustThread_LIBRARIES})
else()
  target_link_libraries(lifestuff_python_api maidsafe_lifestuff maidsafe_lifestuff_manager ${BoostPythonLibs} ${PYTHON_LIBRARIES})
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
# Write LifeStuff paths into WPF UI's CustomProperties.props file                                  #
#==================================================================================================#
if(WIN32 AND UI_WPF_ROOT_DIR)
  cmake_minimum_required(VERSION 2.8.11 FATAL_ERROR)
  unset(UiWpfProps CACHE)
  find_file(UiWpfProps NAMES CustomProperties.props
              PATHS ${UI_WPF_ROOT_DIR}/Native.LifeStuff.Wrapper
              DOC "Path to LifeStuff-UI-Windows CustomProperties.props file."]
              NO_DEFAULT_PATH)
  if(UiWpfProps)
    file(READ ${UiWpfProps} PropsContents)
    get_dependencies(maidsafe_lifestuff OptimizedDependencies DebugDependencies)
    string(REPLACE "/" "\\\\" OptimizedDependencies "${OptimizedDependencies}")
    string(REPLACE "/" "\\\\" DebugDependencies "${DebugDependencies}")
    string(REPLACE "/" "\\\\" IncludesPath "\"${PROJECT_SOURCE_DIR}/include\"")
    if(${TargetArchitecture} STREQUAL "x86_64")
      set(Arch x64)
    elseif(${TargetArchitecture} STREQUAL "i386")
      set(Arch x86)
    else()
      message(FATAL_ERROR "\nUnknown target architecture.  Should be \"x86_64\" or \"i386\" but is \"${TargetArchitecture}\"")
    endif()
    string(REGEX REPLACE "<NativeLibs${Arch}Debug>.*</NativeLibs${Arch}Debug>" "<NativeLibs${Arch}Debug>${DebugDependencies}</NativeLibs${Arch}Debug>" PropsContents "${PropsContents}")
    string(REGEX REPLACE "<NativeLibs${Arch}Release>.*</NativeLibs${Arch}Release>" "<NativeLibs${Arch}Release>${OptimizedDependencies}</NativeLibs${Arch}Release>" PropsContents "${PropsContents}")
    string(REGEX REPLACE "<NativeIncludes>.*</NativeIncludes>" "<NativeIncludes>${IncludesPath}</NativeIncludes>" PropsContents "${PropsContents}")
    # Don't always overwrite the original file; use a temp copy and 'configure_file' to avoid copying if they're the same
    set(TempCopyUiWpfProps ${CMAKE_BINARY_DIR}/UI-Windows-CustomProperties.props)
    file(WRITE ${TempCopyUiWpfProps} "${PropsContents}")
    configure_file(${TempCopyUiWpfProps} ${UiWpfProps} COPYONLY)
  else()
    set(WarningMessage "\nUI_WPF_ROOT_DIR has been specified as \"${UI_WPF_ROOT_DIR}\", but ")
    set(WarningMessage "${WarningMessage}${UI_WPF_ROOT_DIR}\\Native.LifeStuff.Wrapper\\CustomProperties.props ")
    set(WarningMessage "${WarningMessage}doesn't exist.\nEither pass the correct path using\n  cmake . ")
    set(WarningMessage "${WarningMessage}-DUI_WPF_ROOT_DIR=\"<Path to LifeStuff-UI-Windows root directory>\"\n")
    set(WarningMessage "${WarningMessage}or unset UI_WPF_ROOT_DIR in the cache using\n  cmake . -UUI_WPF_ROOT_DIR")
    message(WARNING "${WarningMessage}")
  endif()
endif()


#==================================================================================================#
# Tests                                                                                            #
#==================================================================================================#
if(MaidsafeTesting)
  add_style_test()
  label_as_critical_tests()
  add_project_experimental()
  add_dependencies(AllLifestuff lifestuff_python_api)
  test_summary_output()
endif()
