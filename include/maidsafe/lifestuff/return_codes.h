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

  // API States and permissions
  kWrongState = -200010,
  kWrongLoggedInState = -200011,
  kWrongAccessLevel = -200012,
  kReadOnlyRestrictedSuccess = -200013,

  // API RETURN CODES
  // (Each should be traceable to a unique 'return' in public functions of lifestuff_impl.cc)
  // API State operations
  kInitialiseUpdateFunctionFailure = -209011,
  kInitialiseBootstrapsFailure = -209012,
  kInitialiseChunkStoreFailure = -209013,
  kSetSlotsFailure = -209021,
  kConnectSignalsFailure = -209022,
  // API Credential operations
  kCreationPmidFailure = -209031,
  kCreationVaultFailure = -209032,
  kCreatePublicIdGeneralFailure = -209041,
  kLoginPmidFailure = -209051,
  kLogoutCredentialsFailure = -209061,
  kLogoutCompleteChunkFailure = -209062,
  kCreateDirectoryError = -209071,
  kMountDriveOnCreationError = -209072,
  kCreateMyStuffError = -209073,
  kCreateSharedStuffError = -209074,
  kGeneralError1 = -209081,  // TODO(Alison) - improve name (for problem when mounting drive)
  kGeneralError2 = -209082,  // TODO(Alison) - improve name (for problem when mounting drive)
  kMountDriveError = -209083,
  kUnMountDriveError = -209091,
  kStartMessagesNoPublicIds = -209101,
  kKeywordSizeInvalid = -209121,
  kKeywordPatternInvalid = -209122,
  kChangeKeywordFailure = -209123,
  kChangePinFailure = -209131,
  kPasswordSizeInvalid = -209141,
  kPasswordPatternInvalid = -209142,
  // API Contact operations
  kAddContactGeneralFailure = -209151,
  kConfirmContactGeneralFailure = -209161,
  kConfirmContactPresenceFailure = -209162,
  kDeclineContactGeneralFailure = -209171,
  kRemoveContactGeneralFailure = -209181,
  kChangePictureWrongSize = -209191,
  kChangePictureGeneralFailure = -209192,  // TODO(Alison) - make this more exclusive?
  kGetLifeStuffCardGeneralFailure = -209211,
  kSetLifeStuffCardGeneralFailure = -209212,
  // API Messaging
  kSendMessageSizeFailure = -209221,
  kSendMessageGeneralFailure = -209222,
  kSendFileGeneralFailure = -209231,  // TODO(Alison) - make this more exclusive?
  kAcceptFilePathError = -209241,
  kAcceptFileGeneralFailure = -209242,  // TODO(Alison) - make this more exclusive?
  kRejectFileGeneralFailure = -209251,
  // API Filesystem
  kReadHiddenFileContentFailure = -209261,
  kReadHiddenFileGeneralFailure = -209262,
  kWriteHiddenFileGeneralFailure = -209271,
  kDeleteHiddenFileGeneralFailure = -209281,
  kSearchHiddenFileGeneralFailure = -209291,


  // UNDERLYING RETURN CODES (May be passed through API to user)
  // Credentials
  kCheckPasswordFailure = -208011,
  kChangePasswordFailure = -208012,
  kWordSizeInvalid = -208021,
  kWordPatternInvalid = -208022,
  kPinSizeInvalid = -208031,
  kPinPatternInvalid = -208032,
  // Logging out
  kLogOutSaveSessionFailure = -208041,
  kLogOutLidFailure = -208042,
  // Vault creation
  kVaultCreationFailure = -208051,
  // Public ID
  kPublicIdEmpty = -208061,
  kPublicIdLengthInvalid = -208062,
  kPublicIdEndSpaceInvalid = -208063,
  kPublicIdDoubleSpaceInvalid = -208064,


  // INTERNAL RETURN CODES (Should never reach API)

  // General
  kGetPublicKeyFailure = -201001,
  kRemoteChunkStoreFailure = -201002,
  kReadOnlyFailure = -201003,
  kMustDieFailure = -201004,
  kTryAgainLater = -201005,
//  kWrongOrderFailure = -200013,

  // Authentication
  kCorruptedLidPacket = -202001,
  kLidIdentifierAlreadyInUse = -202002,
  kLidFullAccessUnavailable = -202003,
  kLidIdentifierNotFound = -202004,
  kCorruptedPacket = -202005,
  kIdPacketNotFound = -202006,
  kTemporaryIdPacketNotFound = -202007,
  kSetIdentityPacketsFailure = -202008,
  kStoreIdentityPacketsFailure = -202009,
  kDeleteIdentityPacketsFailure = -202010,
  kCreateSignaturePacketInfoFailure = -202011,
  kCreateSignaturePacketsFailure = -202012,
  kDeleteSignaturePacketsFailure = -202013,
  kSessionFailure = -202014,
  kSessionSerialisationFailure = -202015,
  kSaveSessionFailure = -202016,
  kUsingNextToLastSession = -202017,
  kAccountAlreadyLoggedIn = -202018,
  kUserDoesntExist = -202019,
  kAccountCorrupted = -202020,
  kAtLeastOneFailure = -202021,

  // Session
  kPublicIdInsertionFailure = -203001,
  kPublicIdNotFoundFailure = -203002,
  kContactNotFoundFailure = -203003,

  // PublicId
  kGetPublicIdError = -204002,
  kSigningError = -204003,
  kEncryptingError = -204004,
  kPublicIdException = -204005,
  kPublicIdTimeout = -204006,
  kSendContactInfoFailure = -204007,
  kStorePublicIdFailure = -204008,
  kNoPublicIds = -204010,
  kModifyAppendabilityFailure = -204011,
  kGenerateNewMMIDFailure = -204012,
  kRemoveContactFailure = -204013,
  kDeletePublicIdFailure = -204018,

  // MessageHandler
  kMessageHandlerException = -205001,

  // RETURN CODES USED ONLY BY SHARES
  kNoShareTarget = -206001,
  kOwnerTryingToLeave = -206002
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_RETURN_CODES_H_
