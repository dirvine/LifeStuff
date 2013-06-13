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

//enum ReturnCode {
//  // General
//  kSuccess = 0,
//  kGeneralError = -200001,
//  kRemoteChunkStoreFailure = -200003,
//  kPublicIdNotFoundFailure = -200004,
//  kGetPublicIdError = -200005,
//
//  // LifeStuff Impl and API
//  kWrongState = -201001,
//  kWrongLoggedInState = -201002,
//  kWrongAccessLevel = -201003,
//  kInitialiseUpdateFunctionFailure = -201004,
//  kInitialiseBootstrapsFailure = -201005,
//  kInitialiseChunkStoreFailure = -201006,
//  kSetSlotsFailure = -201007,
//  kConnectSignalsFailure = -201008,
//  kLogoutCredentialsFailure = -201009,
//  kLogoutCompleteChunkFailure = -201010,
//  kCreateDirectoryError = -201011,
//  kMountDriveOnCreationError = -201012,
//  kCreateMyStuffError = -201013,
//  kCreateSharedStuffError = -201014,
//  kMountDriveTryManualUnMount = -201015,
//  kMountDriveMountPointCreationFailure = -201016,
//  kMountDriveError = -201017,
//  kUnMountDriveError = -201018,
//  kStartMessagesAndContactsNoPublicIds = -201019,
//  kChangePictureWrongSize = -201020,
//  kChangePictureWriteHiddenFileFailure = -201021,
//  kChangePictureEmptyDataMap = -201022,
//  kChangePictureReconstructionError = -201023,
//  kSendMessageSizeFailure = -201024,
//  kAcceptFilePathError = -201025,
//  kAcceptFileSerialisedIdentifierEmpty = -201026,
//  kAcceptFileGetFileNameDataFailure = -201027,
//  kAcceptFileCorruptDatamap = -201028,
//  kAcceptFileVerifyCreatePathFailure = -201029,
//  kAcceptFileNameFailure = -201030,
//  kReadHiddenFileContentFailure = -201031,
//  kCheckPasswordFailure = -201032,
//  kVaultCreationCredentialsFailure = -201033,
//  kVaultCreationStartFailure = -201034,
//  kNoShareTarget = -201035,
//  kCouldNotAcquirePmidKeys = -201036,
//
//  // Contacts
//  kContactInsertionFailure = -203001,
//  kContactErasureFailure = -203002,
//  kContactNotPresentFailure = -203003,
//  kContactReplacementFailure = -203004,
//
//  // Message Hander
//  kStartMessagesNoPublicIds = -204001,
//  kPublicIdTimeout = -204002,
//  kMessageHandlerException = -204003,
//  kCannotConvertInboxItemToProtobuf = -204004,
//  kContactInfoContentsFailure = -204005,
//
//  // Public ID
//  kStartContactsNoPublicIds = -205001,
//  kGetPublicKeyFailure = -205002,
//  kContactNotFoundFailure = -205003,
//  kSigningError = -205004,
//  kEncryptingError = -205005,
//  kPublicIdException = -205006,
//  kSendContactInfoFailure = -205007,
//  kStorePublicIdFailure = -205008,
//  kModifyAppendabilityFailure = -205009,
//  kGenerateNewMMIDFailure = -205010,
//  kRemoveContactFailure = -205011,
//  kDeletePublicIdFailure = -205012,
//  kCannotAddOwnPublicId = -205013,
//  kCanOnlyRejectPendingResponseContact = -205014,
//  kConfirmContactGetInfoFailure = -205015,
//  kConfirmContactInformFailure = -205016,
//  kConfirmContactStatusFailure = -205017,
//  kPRWERGetInfoFailure = -205018,
//  kPRWERPublicKeyFailure = -205019,
//  kPRWERInformFailure = -205020,
//  kPRWERStatusFailure = -205021,
//
//  // Routings Handler
//
//  // Session
//  kTryAgainLater = -206001,
//  kPublicIdInsertionFailure = -206002,
//  kParseDataAtlasTmidEmpty = -206003,
//  kParseDataAtlasTmidDoesNotParse = -206004,
//  kParseDataAtlasKeyringDoesNotParse = -206005,
//  kSerialiseDataAtlasKeyringFailure = -206006,
//  kSerialiseDataAtlasToStringFailure = -206007,
//
//  // User Credentials
//  kChangePasswordFailure = -207001,  // TODO(Alison) - make this more exclusive? Or feed values up?
//  kLoginUserNonExistence = -207002,  // TODO(Alison) - make this more exclusive? (probably needn't)
//  kLoginAccountCorrupted = -207003,  // TODO(Alison) - make this more exclusive?
//  kLoginSessionNotYetSaved = -207004,  // User needs to wait ~15s for SaveSession
//  kLoginUsingNextToLastSession = -207005,
//  kMustDieFailure = -207006,
//  kCorruptedPacket = -207007,
//  kIdPacketNotFound = -207008,
//  kTemporaryIdPacketNotFound = -207009,
//  kSetIdentityPacketsFailure = -207010,
//  kStoreIdentityPacketsFailure = -207011,
//  kDeleteIdentityPacketsFailure = -207012,
//  kCreateSignaturePacketInfoFailure = -207013,
//  kCreateSignaturePacketsFailure = -207014,
//  kDeleteSignaturePacketsFailure = -207015,
//  kSessionFailure = -207016,
//  kSessionSerialisationFailure = -207017,
//  kSaveSessionFailure = -207018,
//  kUsingNextToLastSession = -207019,
//  kNoLogoutResponse = -207020,
//
//  // User Storage
//  kOwnerTryingToLeave = -208001,  // Only used by Shares
//
//  // Utils
//  kWordSizeInvalid = -209001,
//  kWordPatternInvalid = -209002,
//  kKeywordSizeInvalid = -209003,
//  kKeywordPatternInvalid = -209004,
//  kPinSizeInvalid = -209005,
//  kPinPatternInvalid = -209006,
//  kPasswordSizeInvalid = -209007,
//  kPasswordPatternInvalid = -209008,
//  kPublicIdEmpty = -209009,  // TODO(Alison) - make this more exclusive?
//  kPublicIdLengthInvalid = -209010,
//  kPublicIdEndSpaceInvalid = -209011,
//  kPublicIdDoubleSpaceInvalid = -209012,
//  kAtLeastOneFailure = -209013,
//
//  // Codes remaining in DISABLED tests. Expect these codes to be redundant soon.
//  kUserDoesntExist = -209992
//};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_RETURN_CODES_H_
