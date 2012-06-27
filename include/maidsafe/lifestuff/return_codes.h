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


namespace maidsafe {

namespace lifestuff {

enum ReturnCode {
  // General
  kSuccess = 0,
  kGeneralError = -200001,
  kGeneralException = -200002,
  kPendingResult = -200003,
  kGetPublicKeyFailure = -200004,
  kGetMpidFailure = -200005,
  kInvalidPublicKey = -200006,
  kOperationTimeOut = -200007,
  kRemoteChunkStoreFailure = -200008,

  // Authentication
  kAuthenticationError = -201001,
  kPasswordFailure = -201002,
  kUserDoesntExist = -201003,
  kUserExists = -201004,
  kFailedToDeleteOldPacket = -201005,
  kCorruptedPacket = -201006,
  kIdPacketNotFound = -201007,
  kTemporaryIdPacketNotFound = -201008,
  kAccountCorrupted = -201009,
  kUsingNextToLastSession = -201010,
  kSessionFailure = -201011,
  kCreateSignaturePacketInfoFailure = -201012,
  kCreateSignaturePacketsFailure = -201013,
  kSessionSerialisationFailure = -201014,
  kSetIdentityPacketsFailure = -201015,
  kStoreIdentityPacketsFailure = -201016,
  kSaveSessionFailure = -201017,
  kDeleteIdentityPacketsFailure = -201018,
  kChangeUsernamePinFailure = -201019,
  kChangePasswordFailure = -201020,
  kAtLeastOneFailure = -201021,
  kDeleteSignaturePacketsFailure = -201022,

  // User Credentials
  kCredentialValidityFailure = -202001,

  // Session
  kPublicIdInsertionFailure = -204001,
  kPublicIdNotFoundFailure = -204002,
  kContactNotFoundFailure = -204003,

  // PublicId
  kGetPublicIdError = -206002,
  kSigningError = -206003,
  kEncryptingError = -206004,
  kPublicIdException = -206005,
  kPublicIdTimeout = -206006,
  kSendContactInfoFailure = -206007,
  kStorePublicIdFailure = -206008,
  kPublicIdEmpty = -206009,
  kNoPublicIds = -206010,
  kModifyAppendabilityFailure = -206011,
  kGenerateNewMMIDFailure = -206012,
  kRemoveContactFailure = -206013,
  kSetProfilePictureError = -206014,
  kDeletePublicIdFailure = -206015,

  // MessageHandler
  kMessageHandlerException = -207001,
  kMessageHandlerNotInitialised = -207002,
  kMessageHandlerError = -207003,

  // Share
  kNoShareTarget = -208001,
  kOwnerTryingToLeave = -208002,
  kNoKeyForUpgrade = -208003,
  kInvalidKeyringForOpenShare = -208004
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_RETURN_CODES_H_
