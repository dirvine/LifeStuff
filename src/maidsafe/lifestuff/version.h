/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Description:  Local version definition and DHT version check
* Created:      2011-01-27
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef MAIDSAFE_LIFESTUFF_VERSION_H_
#define MAIDSAFE_LIFESTUFF_VERSION_H_

#define MAIDSAFE_LIFESTUFF_VERSION 300

#if defined CMAKE_MAIDSAFE_LIFESTUFF_VERSION &&\
  MAIDSAFE_LIFESTUFF_VERSION != CMAKE_MAIDSAFE_LIFESTUFF_VERSION
#  error The project version has changed.  Re-run CMake.
#endif

#include "maidsafe/common/version.h"
#define THIS_NEEDS_MAIDSAFE_COMMON_VERSION 1100
#if MAIDSAFE_COMMON_VERSION < THIS_NEEDS_MAIDSAFE_COMMON_VERSION
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-common library.
#elif MAIDSAFE_COMMON_VERSION > THIS_NEEDS_MAIDSAFE_COMMON_VERSION
#  error This API uses a newer version of the maidsafe-common library.\
    Please update this project.
#endif

#include "maidsafe/private/version.h"
#define THIS_NEEDS_MAIDSAFE_PRIVATE_VERSION 200
#if MAIDSAFE_PRIVATE_VERSION < THIS_NEEDS_MAIDSAFE_PRIVATE_VERSION
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-private library.
#elif MAIDSAFE_PRIVATE_VERSION > THIS_NEEDS_MAIDSAFE_PRIVATE_VERSION
#  error This API uses a newer version of the maidsafe-private library.\
    Please update this project.
#endif

#include "maidsafe/encrypt/version.h"
#define THIS_NEEDS_MAIDSAFE_ENCRYPT_VERSION 1100
#if MAIDSAFE_ENCRYPT_VERSION < THIS_NEEDS_MAIDSAFE_ENCRYPT_VERSION
#  error This API is not compatible with the installed library.\
    Please update the MaidSafe-Encrypt library.
#elif MAIDSAFE_ENCRYPT_VERSION > THIS_NEEDS_MAIDSAFE_ENCRYPT_VERSION
#  error This API uses a newer version of the MaidSafe-Encrypt library.\
    Please update this project.
#endif

#include "maidsafe/drive/version.h"
#define THIS_NEEDS_MAIDSAFE_DRIVE_VERSION 300
#if MAIDSAFE_DRIVE_VERSION < THIS_NEEDS_MAIDSAFE_DRIVE_VERSION
#  error This API is not compatible with the installed library.\
    Please update the MaidSafe-Drive library.
#elif MAIDSAFE_DRIVE_VERSION > THIS_NEEDS_MAIDSAFE_DRIVE_VERSION
#  error This API uses a newer version of the MaidSafe-Drive library.\
    Please update this project.
#endif

#include "maidsafe/pki/version.h"
#define THIS_NEEDS_MAIDSAFE_PKI_VERSION 200
#if MAIDSAFE_PKI_VERSION < THIS_NEEDS_MAIDSAFE_PKI_VERSION
#  error This API is not compatible with the installed library.\
    Please update the MaidSafe-PKI library.
#elif MAIDSAFE_PKI_VERSION > THIS_NEEDS_MAIDSAFE_PKI_VERSION
#  error This API uses a newer version of the MaidSafe-PKI library.\
    Please update this project.
#endif

#include "maidsafe/passport/version.h"
#define THIS_NEEDS_MAIDSAFE_PASSPORT_VERSION 300
#if MAIDSAFE_PASSPORT_VERSION < THIS_NEEDS_MAIDSAFE_PASSPORT_VERSION
#  error This API is not compatible with the installed library.\
    Please update the MaidSafe-Passport library.
#elif MAIDSAFE_PASSPORT_VERSION > THIS_NEEDS_MAIDSAFE_PASSPORT_VERSION
#  error This API uses a newer version of the MaidSafe-Passport library.\
    Please update this project.
#endif

#ifndef LOCAL_TARGETS_ONLY

#include "maidsafe/transport/version.h"
#define THIS_NEEDS_MAIDSAFE_TRANSPORT_VERSION 200
#if MAIDSAFE_TRANSPORT_VERSION < THIS_NEEDS_MAIDSAFE_TRANSPORT_VERSION
#  error This API is not compatible with the installed library.\
    Please update the MaidSafe-Transport library.
#elif MAIDSAFE_TRANSPORT_VERSION > THIS_NEEDS_MAIDSAFE_TRANSPORT_VERSION
#  error This API uses a newer version of the MaidSafe-Transport library.\
    Please update this project.
#endif

#include "maidsafe/dht/version.h"
#define THIS_NEEDS_MAIDSAFE_DHT_VERSION 3200
#if MAIDSAFE_DHT_VERSION < THIS_NEEDS_MAIDSAFE_DHT_VERSION
#  error This API is not compatible with the installed library.\
    Please update the MaidSafe-DHT library.
#elif MAIDSAFE_DHT_VERSION > THIS_NEEDS_MAIDSAFE_DHT_VERSION
#  error This API uses a newer version of the MaidSafe-DHT library.\
    Please update this project.
#endif

#include "maidsafe/pd/version.h"
#define THIS_NEEDS_MAIDSAFE_PD_VERSION 800
#if MAIDSAFE_PD_VERSION < THIS_NEEDS_MAIDSAFE_PD_VERSION
#  error This API is not compatible with the installed library.\
    Please update the MaidSafe-PD library.
#elif MAIDSAFE_PD_VERSION > THIS_NEEDS_MAIDSAFE_PD_VERSION
#  error This API uses a newer version of the MaidSafe-PD library.\
    Please update this project.
#endif

#endif

#endif  // MAIDSAFE_LIFESTUFF_VERSION_H_
