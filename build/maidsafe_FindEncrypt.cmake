#==============================================================================#
#                                                                              #
#  Copyright (c) 2011 Sigmoid Solutions limited                                #
#  All rights reserved.                                                        #
#                                                                              #
#  Redistribution and use in source and binary forms, with or without          #
#  modification, are permitted provided that the following conditions are met: #
#                                                                              #
#      * Redistributions of source code must retain the above copyright        #
#        notice, this list of conditions and the following disclaimer.         #
#      * Redistributions in binary form must reproduce the above copyright     #
#        notice, this list of conditions and the following disclaimer in the   #
#        documentation and/or other materials provided with the distribution.  #
#      * Neither the name of the maidsafe.net limited nor the names of its     #
#        contributors may be used to endorse or promote products derived from  #
#        this software without specific prior written permission.              #
#                                                                              #
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" #
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE   #
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE  #
#  ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE  #
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR         #
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF        #
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS    #
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN     #
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)     #
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE  #
#  POSSIBILITY OF SUCH DAMAGE.                                                 #
#                                                                              #
#==============================================================================#
#                                                                              #
#  Module used to locate MaidSafe-Encrypt libs and headers.                    #
#                                                                              #
#  Settable variables to aid with finding Encrypt are:                         #
#    ENCRYPT_LIB_DIR, ENCRYPT_INC_DIR and ENCRYPT_ROOT_DIR                     #
#                                                                              #
#  Variables set and cached by this module are:                                #
#    Encrypt_INCLUDE_DIR, Encrypt_LIBRARY_DIR, Encrypt_LIBRARY                 #
#                                                                              #
#  For MSVC, Encrypt_LIBRARY_DIR_DEBUG is also set and cached.                 #
#                                                                              #
#==============================================================================#

UNSET(WARNING_MESSAGE)
UNSET(Encrypt_INCLUDE_DIR CACHE)
UNSET(Encrypt_LIBRARY_DIR CACHE)
UNSET(Encrypt_LIBRARY_DIR_DEBUG CACHE)
UNSET(Encrypt_LIBRARY CACHE)
UNSET(Encrypt_LIBRARY_DEBUG CACHE)


IF(ENCRYPT_LIB_DIR)
  SET(ENCRYPT_LIB_DIR ${ENCRYPT_LIB_DIR} CACHE PATH "Path to MaidSafe-Encrypt libraries directory" FORCE)
ENDIF()
IF(ENCRYPT_INC_DIR)
  SET(ENCRYPT_INC_DIR ${ENCRYPT_INC_DIR} CACHE PATH "Path to MaidSafe-Encrypt include directory" FORCE)
ENDIF()
IF(ENCRYPT_ROOT_DIR)
  SET(ENCRYPT_ROOT_DIR ${ENCRYPT_ROOT_DIR} CACHE PATH "Path to MaidSafe-Encrypt root directory" FORCE)
ENDIF()

SET(ENCRYPT_INC_DIR /home/maidsafe/LifeStuff/MaidSafe-Common/installed/)
SET(ENCRYPT_LIB_DIR /home/maidsafe/LifeStuff/MaidSafe-Common/installed/)
SET(ENCRYPT_ROOT_DIR /home/maidsafe/LifeStuff/MaidSafe-Common/installed/)

Message (ENCRYPT_INC_DIR ${ENCRYPT_INC_DIR})
Message (ENCRYPT_LIB_DIR ${ENCRYPT_LIB_DIR})

IF(MSVC)
  IF(CMAKE_CL_64)
    SET(ENCRYPT_LIBPATH_SUFFIX build/Win_MSVC/bin/x64/Release)
  ELSE()
    SET(ENCRYPT_LIBPATH_SUFFIX build/Win_MSVC/bin/win32/Release)
  ENDIF()
ELSE()
  SET(ENCRYPT_LIBPATH_SUFFIX lib lib64)
ENDIF()
#FIND_LIBRARY(Encrypt_LIBRARY_RELEASE NAMES maidsafe_encrypt_d.a maidsafe_encrypt PATHS ${ENCRYPT_LIB_DIR} ${ENCRYPT_ROOT_DIR} PATH_SUFFIXES ${ENCRYPT_LIBPATH_SUFFIX})
FIND_LIBRARY(Encrypt_LIBRARY_RELEASE NAMES maidsafe_encrypt.a maidsafe_encrypt PATHS ${ENCRYPT_LIB_DIR} ${ENCRYPT_ROOT_DIR} PATH_SUFFIXES ${ENCRYPT_LIBPATH_SUFFIX})

IF(MSVC)
  IF(CMAKE_CL_64)
    SET(ENCRYPT_LIBPATH_SUFFIX build/Win_MSVC/bin/x64/Debug)
  ELSE()
    SET(ENCRYPT_LIBPATH_SUFFIX build/Win_MSVC/bin/win32/Debug)
  ENDIF()
  FIND_LIBRARY(Encrypt_LIBRARY_DEBUG NAMES maidsafe_encrypt_d PATHS ${ENCRYPT_LIB_DIR} ${ENCRYPT_ROOT_DIR} PATH_SUFFIXES ${ENCRYPT_LIBPATH_SUFFIX})
ENDIF()

IF(MSVC)
  SET(ENCRYPT_INCLUDEPATH_SUFFIX build/Win_MSVC/include)
ELSE()
  SET(ENCRYPT_INCLUDEPATH_SUFFIX include)
ENDIF()
#FIND_PATH(Encrypt_INCLUDE_DIR maidsafe-encrypt/version.h PATHS ${ENCRYPT_INC_DIR} ${ENCRYPT_ROOT_DIR} PATH_SUFFIXES ${ENCRYPT_INCLUDEPATH_SUFFIX})
FIND_PATH(Encrypt_INCLUDE_DIR version.h /home/maidsafe/LifeStuff/MaidSafe-Common/installed/include/maidsafe/maidsafe-encrypt/)

MESSAGE(BC ${Encrypt_INCLUDE_DIR})
message("--- ${Encrypt_INCLUDE_DIR} ---")

# Check version maidsafe-encrypt version is OK
FIND_FILE(ENCRYPT_VERSION_DOT_H version.h /home/maidsafe/LifeStuff/MaidSafe-Common/installed/include/maidsafe/maidsafe-encrypt/)
FILE(STRINGS ${ENCRYPT_VERSION_DOT_H} VERSION_LINE REGEX "MAIDSAFE_ENCRYPT_VERSION ")
STRING(REPLACE "#define MAIDSAFE_ENCRYPT_VERSION " "" INSTALLED_ENCRYPT_VERSION ${VERSION_LINE})
# FIND_FILE(SIGMOID_DOT_H sigmoid.h ${${PROJECT_NAME}_ROOT}/src/sigmoid)
# FILE(STRINGS ${SIGMOID_DOT_H} VERSION_LINE REGEX "#define THIS_MAIDSAFE_ENCRYPT_VERSION")
STRING(REPLACE "#define THIS_MAIDSAFE_ENCRYPT_VERSION " "" THIS_MAIDSAFE_ENCRYPT_VERSION ${VERSION_LINE})
IF(NOT ${THIS_MAIDSAFE_ENCRYPT_VERSION} MATCHES ${INSTALLED_ENCRYPT_VERSION})
  SET(ERROR_MESSAGE "\nInstalled version of MaidSafe-Encrypt has MAIDSAFE_ENCRYPT_VERSION == ${INSTALLED_ENCRYPT_VERSION}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}This project has MAIDSAFE_ENCRYPT_VERSION == ${THIS_MAIDSAFE_ENCRYPT_VERSION}\n")
  IF(${THIS_MAIDSAFE_ENCRYPT_VERSION} LESS ${INSTALLED_ENCRYPT_VERSION})
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}Please update ${SIGMOID_DOT_H}\n")
  ELSE()
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}Please update MaidSafe-Encrypt.\n")
  ENDIF()
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()

GET_FILENAME_COMPONENT(ENCRYPT_LIBRARY_DIR ${Encrypt_LIBRARY_RELEASE} PATH)
SET(Encrypt_LIBRARY_DIR ${ENCRYPT_LIBRARY_DIR} CACHE PATH "Path to MaidSafe-Encrypt libraries directory" FORCE)
IF(MSVC)
  GET_FILENAME_COMPONENT(ENCRYPT_LIBRARY_DIR_DEBUG ${Encrypt_LIBRARY_DEBUG} PATH)
  SET(Encrypt_LIBRARY_DIR_DEBUG ${ENCRYPT_LIBRARY_DIR_DEBUG} CACHE PATH "Path to MaidSafe-Encrypt debug libraries directory" FORCE)
ENDIF()

IF(NOT Encrypt_LIBRARY_RELEASE)
  SET(ERROR_MESSAGE "\nCould not find MaidSafe-Encrypt.  NO ENCRYPT LIBRARY - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If MaidSafe-Encrypt is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DENCRYPT_LIB_DIR=<Path to encrypt lib directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DENCRYPT_ROOT_DIR=<Path to encrypt root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ELSE()
  SET(Encrypt_LIBRARY ${Encrypt_LIBRARY_RELEASE} CACHE PATH "Path to Google Protocol Buffers library" FORCE)
ENDIF()

IF(MSVC)
  IF(NOT Encrypt_LIBRARY_DEBUG)
    SET(ERROR_MESSAGE "\nCould not find MaidSafe-Encrypt.  NO *DEBUG* ENCRYPT LIBRARY - ")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If MaidSafe-Encrypt is already installed, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DENCRYPT_ROOT_DIR=<Path to encrypt root directory>")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ELSE()
    SET(Encrypt_LIBRARY debug ${Encrypt_LIBRARY_DEBUG} optimized ${Encrypt_LIBRARY_RELEASE} CACHE PATH "Path to MaidSafe-Encrypt libraries" FORCE)
  ENDIF()
ENDIF()

IF(NOT Encrypt_INCLUDE_DIR)
  SET(ERROR_MESSAGE "\nCould not find MaidSafe-Encrypt.  NO VERSION.H - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If MaidSafe-Encrypt is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DENCRYPT_INC_DIR=<Path to encrypt include directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DENCRYPT_ROOT_DIR=<Path to encrypt root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()

MESSAGE("-- Found MaidSafe-Encrypt library")
IF(MSVC)
  MESSAGE("-- Found MaidSafe-Encrypt Debug library")
ENDIF()

