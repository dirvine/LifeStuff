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

#ifndef MAIDSAFE_LIFESTUFF_SHARED_VERSION_H_
#define MAIDSAFE_LIFESTUFF_SHARED_VERSION_H_

#define MAIDSAFE_LIFESTUFF_CLIENT_VERSION 1

#include "maidsafe/dht/common/version.h"
#define THIS_NEEDS_MAIDSAFE_DHT_VERSION 29
#if MAIDSAFE_DHT_VERSION < THIS_NEEDS_MAIDSAFE_DHT_VERSION
#error This API is not compatible with the installed library.\
  Please update the maidsafe-dht library.
#elif MAIDSAFE_DHT_VERSION > THIS_NEEDS_MAIDSAFE_DHT_VERSION
#error This API uses a newer version of the maidsafe-dht library.\
  Please update this project.
#endif

#include "maidsafe/encrypt/version.h"
#define THIS_NEEDS_MAIDSAFE_ENCRYPT_VERSION 7
#if MAIDSAFE_ENCRYPT_VERSION < THIS_NEEDS_MAIDSAFE_ENCRYPT_VERSION
#error This API is not compatible with the installed library.\
  Please update the MaidSafe-Encrypt library.
#elif MAIDSAFE_ENCRYPT_VERSION > THIS_NEEDS_MAIDSAFE_ENCRYPT_VERSION
#error This API uses a newer version of the MaidSafe-Encrypt library.\
  Please update this project.
#endif

#include "maidsafe/passport/version.h"
#define THIS_NEEDS_MAIDSAFE_PASSPORT_VERSION 1
#if MAIDSAFE_PASSPORT_VERSION < THIS_NEEDS_MAIDSAFE_PASSPORT_VERSION
#error This API is not compatible with the installed library.\
  Please update the MaidSafe-Passport library.
#elif MAIDSAFE_PASSPORT_VERSION > THIS_NEEDS_MAIDSAFE_PASSPORT_VERSION
#error This API uses a newer version of the MaidSafe-Passport library.\
  Please update this project.
#endif

#include "maidsafe/pki/version.h"
#define THIS_NEEDS_MAIDSAFE_PKI_VERSION 1
#if MAIDSAFE_PKI_VERSION < THIS_NEEDS_MAIDSAFE_PKI_VERSION
#error This API is not compatible with the installed library.\
  Please update the MaidSafe-Pki library.
#elif MAIDSAFE_PKI_VERSION > THIS_NEEDS_MAIDSAFE_PKI_VERSION
#error This API uses a newer version of the MaidSafe-Pki library.\
  Please update this project.
#endif

#endif  // MAIDSAFE_LIFESTUFF_SHARED_VERSION_H_