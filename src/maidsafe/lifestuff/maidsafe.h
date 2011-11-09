/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Definition of system-wide constants/enums/structs
* Version:      1.0
* Created:      2009-01-29-00.15.50
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#ifndef MAIDSAFE_LIFESTUFF_MAIDSAFE_H_
#define MAIDSAFE_LIFESTUFF_MAIDSAFE_H_

#include <string>
#include <vector>
#include "boost/cstdint.hpp"
#include "boost/function.hpp"
#include "maidsafe/dht/version.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/version.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 110
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif


namespace kad { class Contact; }

namespace maidsafe {

namespace lifestuff {

// This is the size in bytes of the NON-HEX format strings used as keys.  When
// encoded to hex the string size is doubled.
const boost::uint32_t kKeySize = 64;

const boost::uint16_t kRsaKeySize = 4096;
// const crypto::hashtype kHashSize(crypto::SHA_512);

const std::string kAnonymousRequestSignature(2 * kKeySize, 'f');

const std::string kRoot("/");

const int kRootSubdirSize = 4;
const int kSharesSubdirSize = 1;

const std::string kRootSubdir[kRootSubdirSize][2] = {
  {"/My Stuff", ""},
  {"/Shares", "" },
  {"/Emails", ""},
  {"/Chat", ""}
};

const std::string kSharesSubdir[kSharesSubdirSize][2] = {
  {"/Shares/Private", ""} /*,*/
//  {
//  "/Shares/Public", "a0590baf0f811834de68fec77950c179595f5ecb5dc3c6abac67dc34
//  "9714101e40b44531054196b4616f3314cee94d71babb5fbc7010d7fff958d8c8cc54836c"
//  },
//  {
//    "/Shares/Anonymous",
//    "63ed99cc9f91c7dd568247337fd5b479e2cec00e9054ec4c5797c3"
//    "19a80fe3ab07a01dca8200dfd63142b1ed376970bb3a9acd3fa55e9"
//    "d631d3c0aff42f7660e"
//  }
};

enum DirType { ANONYMOUS, PRIVATE, PRIVATE_SHARE, PUBLIC_SHARE };

enum SortingMode { kAlpha, kRank, kLast };

enum ShareFilter { kAll, kRo, kAdmin };

enum DefConLevels { kDefCon1 = 1, kDefCon2, kDefCon3 };

//  typedef std::function<void(int)> OneIntFunction;
typedef std::function<void(int)> VoidFuncOneInt;  // NOLINT (Dan)
typedef std::function<void(const ReturnCode&, const kad::Contact&)>
        VoidFuncIntContact;
typedef std::function<void(const ReturnCode&,
                           const std::vector<kad::Contact>&)>
        VoidFuncIntContacts;


inline std::string HexSubstr(const std::string &non_hex) {
  std::string hex(EncodeToHex(non_hex));
  if (hex.size() > 16)
    return (hex.substr(0, 7) + ".." + hex.substr(hex.size() - 7));
  else
    return hex;
}

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_MAIDSAFE_H_
