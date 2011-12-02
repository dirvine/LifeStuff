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

#ifndef MAIDSAFE_LIFESTUFF_RETURN_CODES_H_
#define MAIDSAFE_LIFESTUFF_RETURN_CODES_H_

#include "maidsafe/lifestuff/version.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 110
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif


namespace maidsafe {

namespace lifestuff {

enum ReturnCode {
  // General
  kSuccess = 0,
  kPendingResult = -201,
  kGetPublicKeyFailure = -202,
  kGetMpidFailure = -203,
  kInvalidPublicKey = -204,

  // Authentication
  kAuthenticationError = -201001,
  kPasswordFailure = -201002,
  kUserDoesntExist = -201003,
  kUserExists = -201004,
  kPublicUsernameExists = -201005,
  kPublicUsernameAlreadySet = -201006,
  kFailedToDeleteOldPacket = -201007,

  // Client Controller
  kClientControllerNotInitialised = -202001,

  // Store Manager
  kStoreManagerInitError = -203001,
  kStorePacketFailure = -203002,
  kDeletePacketFailure = -203003,
  kGetPacketFailure = -203004,
  kUpdatePacketFailure = -203005,
  kNoPublicKeyToCheck = -203006,
  kKeyUnique = -203007,
  kKeyNotUnique = -203008,

  // Session
  kEmptyConversationId = -204001,
  kNonExistentConversation = -204002,
  kExistingConversation = -204003,
  kGetKeyFailure = -204004,
  kContactListFailure = -204005,
  kAddLiveContactFailure = -204006,
  kLiveContactNotFound = -204007,
  kLiveContactNoEp = -204008,

  // Data-Handler
  kParseFailure = -205001,
  kPreOperationCheckFailure = -205002,
  kDuplicateNameFailure = -205003,
  kStoreFailure = -205004,
  kVerifyDataFailure = -205005,
  kDeleteFailure = -205006,
  kModifyFailure = -205007,
  kMissingSignedData = -205008,
  kInvalidUpdate = -205009,
  kSignatureVerificationFailure =  -205010,
  kNotHashable = -205011,
  kNotOwner = -205012,
  kNonExistent = -205013,
  kUnknownFailure = -205014,

  // PublicId
  kPublicIdExists = -206001,
  kGetPublicIdError = -206002,
  kSigningError = -206003,
  kPublicIdException = -206004,
  kPublicIdTimeout = -206005,
  kSendContactInfoFailure = -206006,
  kStorePublicIdFailure = -206007,
  kPublicIdEmpty = -206008,
  kNoPublicIds = -206009
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_RETURN_CODES_H_
