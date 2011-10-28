/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  List of error codes
* Version:      1.0
* Created:      2009-10-12-13.48.44
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

#ifndef MAIDSAFE_LIFESTUFF_RETURNCODES_H_
#define MAIDSAFE_LIFESTUFF_RETURNCODES_H_

#include "maidsafe/lifestuff/version.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 109
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif


namespace maidsafe {

namespace lifestuff {

enum ReturnCode {
  // General
  kSuccess = 0,
  kPendingResult = -4,

  // Authentication
  kAuthenticationError = -1001,
  kPasswordFailure = -1002,
  kUserDoesntExist = -1003,
  kUserExists = -1004,
  kPublicUsernameExists = -1005,
  kPublicUsernameAlreadySet = -1006,
  kFailedToDeleteOldPacket = -1007,

  // Client Controller
  kClientControllerNotInitialised = -4002,


  // Store Managers
  kStoreManagerError = -7001,
  kStoreManagerInitError = -7002,
  kStoreChunkError = -7005,
  kFindValueFailure = -7024,
  kSendPacketFailure = -7035,
  kDeletePacketFailure = -7044,
  kLoadPacketFailure = -7046,
  kNoPublicKeyToCheck = -7054,
  kKeyUnique = -7055,
  kKeyNotUnique = -7056,
  kUpdatePacketFailure = -7057,

  // Session & FileSystem
  kEmptyConversationId = -11001,
  kNonExistentConversation = -11002,
  kExistingConversation = -11003,
  kGetKeyFailure = -11005,
  kContactListFailure = -11006,
  kAddLiveContactFailure = -11012,
  kLiveContactNotFound = -11013,
  kLiveContactNoEp = -11014
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_RETURNCODES_H_
