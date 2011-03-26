# ============================================================================ #
#                                                                              #
# Copyright [2011] Sigmoid Solutions Ltd                                       #
#                                                                              #
# Description:  Module used to locate MaidSafe-Common tools, cmake modules     #
#               and the maidsafe_common libs and headers.                      #
# Created:      2010-12-29                                                     #
# Company:      Sigmoid Solutions Ltd                                          #
#                                                                              #
# The following source code is property of Sigmoid Solutions Ltd and is not    #
# meant for external use.  The use of this code is governed by the license     #
# file LICENSE.TXT found in the root of this directory and also on             #
# www.sigmoidsolutions.com                                                     #
#                                                                              #
# You are not free to copy, amend or otherwise use this source code without    #
# the explicit written permission of the board of directors of Sigmoid         #
# Solutions.                                                                   #
#                                                                              #
# ============================================================================ #

UNSET(MaidSafeCommon_INCLUDE_DIR CACHE)
UNSET(MaidSafeCommon_MODULES_DIR CACHE)
UNSET(MaidSafeCommon_TOOLS_DIR CACHE)
UNSET(MaidSafeCommon_VERSION CACHE)

IF(NOT MAIDSAFE_COMMON_INSTALL_DIR AND DEFAULT_THIRD_PARTY_ROOT)
  SET(MAIDSAFE_COMMON_INSTALL_DIR ${DEFAULT_THIRD_PARTY_ROOT})
ENDIF()

SET(MAIDSAFE_PATH_SUFFIX share/maidsafe)
FIND_FILE(MAIDSAFE_THIRD_PARTY_CMAKE maidsafe_third_party.cmake PATHS ${MAIDSAFE_COMMON_INSTALL_DIR} PATH_SUFFIXES ${MAIDSAFE_PATH_SUFFIX} NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)
FIND_FILE(BOOST_LIBS_CMAKE boost_libs.cmake PATHS ${MAIDSAFE_COMMON_INSTALL_DIR} PATH_SUFFIXES ${MAIDSAFE_PATH_SUFFIX} NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)
FIND_FILE(MAIDSAFE_COMMON_CMAKE maidsafe_common.cmake PATHS ${MAIDSAFE_COMMON_INSTALL_DIR} PATH_SUFFIXES ${MAIDSAFE_PATH_SUFFIX} NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)
FIND_FILE(MAIDSAFE_ENCRYPT_CMAKE encrypt.cmake PATHS ${MAIDSAFE_COMMON_INSTALL_DIR} PATH_SUFFIXES ${MAIDSAFE_PATH_SUFFIX} NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)
IF(MAIDSAFE_THIRD_PARTY_CMAKE AND BOOST_LIBS_CMAKE AND MAIDSAFE_COMMON_CMAKE AND MAIDSAFE_ENCRYPT_CMAKE)
  INCLUDE(${MAIDSAFE_THIRD_PARTY_CMAKE})
  INCLUDE(${BOOST_LIBS_CMAKE})
  INCLUDE(${MAIDSAFE_COMMON_CMAKE})
  INCLUDE(${MAIDSAFE_ENCRYPT_CMAKE})
ENDIF()

SET(MAIDSAFE_PATH_SUFFIX include)
FIND_PATH(MaidSafeCommon_INCLUDE_DIR maidsafe/common/version.h PATHS ${MAIDSAFE_COMMON_INC_DIR} ${MAIDSAFE_COMMON_INSTALL_DIR} PATH_SUFFIXES ${MAIDSAFE_PATH_SUFFIX} NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)

SET(MAIDSAFE_PATH_SUFFIX include/maidsafe)
FIND_PATH(MaidSafeEncrypt_INCLUDE_DIR maidsafe-encrypt/version.h PATHS ${MAIDSAFE_COMMON_INC_DIR} ${MAIDSAFE_COMMON_INSTALL_DIR} PATH_SUFFIXES ${MAIDSAFE_PATH_SUFFIX} NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)

SET(MAIDSAFE_PATH_SUFFIX share/maidsafe/cmake_modules)
FIND_PATH(MaidSafeCommon_MODULES_DIR maidsafe_run_protoc.cmake PATHS ${MAIDSAFE_COMMON_INSTALL_DIR} PATH_SUFFIXES ${MAIDSAFE_PATH_SUFFIX} NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)

SET(MAIDSAFE_PATH_SUFFIX share/maidsafe/tools)
FIND_PATH(MaidSafeCommon_TOOLS_DIR cpplint.py PATHS ${MAIDSAFE_COMMON_INSTALL_DIR} PATH_SUFFIXES ${MAIDSAFE_PATH_SUFFIX} NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${MaidSafeCommon_MODULES_DIR})

SET(MAIDSAFE_PATH_SUFFIX ../../..)
FIND_PATH(DEFAULT_THIRD_PARTY_ROOT README PATHS ${MAIDSAFE_COMMON_INSTALL_DIR} PATH_SUFFIXES ${MAIDSAFE_PATH_SUFFIX} NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)

IF(NOT MaidSafeCommon_INCLUDE_DIR OR NOT MaidSafeEncrypt_INCLUDE_DIR OR NOT MaidSafeCommon_MODULES_DIR OR NOT MaidSafeCommon_TOOLS_DIR)
  SET(ERROR_MESSAGE "${MaidSafeCommon_INCLUDE_DIR}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${MaidSafeCommon_MODULES_DIR}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${MaidSafeCommon_TOOLS_DIR}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\nCould not find MaidSafe Common.\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can clone it at git@github.com:maidsafe/MaidSafe-Common.git\n\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If MaidSafe Common is already installed, run:")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_COMMON_INSTALL_DIR=<Path to MaidSafe Common install directory>\n\n")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()

FILE(STRINGS ${MaidSafeCommon_INCLUDE_DIR}/maidsafe/common/version.h MaidSafeCommon_VERSION
       REGEX "VERSION [0-9]+$")
STRING(REGEX MATCH "[0-9]+$" MaidSafeCommon_VERSION ${MaidSafeCommon_VERSION})
FILE(STRINGS ${MaidSafeEncrypt_INCLUDE_DIR}/maidsafe-encrypt/version.h MaidSafeEncrypt_VERSION
       REGEX "ENCRYPT_VERSION [0-9]+$")

STRING(REGEX MATCH "[0-9]+$" MaidSafeCommon_VERSION ${MaidSafeCommon_VERSION})
STRING(REGEX MATCH "[0-9]+$" MaidSafeEncrypt_VERSION ${MaidSafeEncrypt_VERSION})
INCLUDE_DIRECTORIES(${MaidSafeCommon_INCLUDE_DIR} ${MaidSafeEncrypt_INCLUDE_DIR})

MESSAGE("-- Found MaidSafe Common library (version ${MaidSafeCommon_VERSION})")
MESSAGE("-- Found MaidSafe Common Debug library (version ${MaidSafeCommon_VERSION})")
MESSAGE("-- Found MaidSafe Encrypt library (version ${MaidSafeEncrypt_VERSION})")
MESSAGE("-- Found MaidSafe Encrypt Debug library (version ${MaidSafeEncrypt_VERSION})")
