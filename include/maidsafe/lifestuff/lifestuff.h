/***************************************************************************************************
 *  Copyright 2013 MaidSafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use.  The use of this code is governed by the licence file licence.txt found in the root of    *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit         *
 *  written permission of the board of directors of MaidSafe.net.                                  *
 **************************************************************************************************/

#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_H_
#define MAIDSAFE_LIFESTUFF_LIFESTUFF_H_

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/types.h"

#include "maidsafe/lifestuff/return_codes.h"

namespace maidsafe {
namespace lifestuff {

enum ContactOrder { kAlphabetical, kPopular, kLastContacted };

typedef TaggedValue<Identity, struct KeywordTag> Keyword;
typedef TaggedValue<Identity, struct PinTag> Pin;
typedef TaggedValue<Identity, struct PasswordTag> Password;

struct LifeStuffReturn {
  // constructed based on exception.error_code() then get translated into LifeStuff ReturnCode
  ReturnCode return_code;
  char* msg;  // exception.what()
};

/// Contact Related Return Types
typedef uint16_t ContactRank;
enum ContactPresence { kOffline, kOnline };
enum ContactStatus {
  kAll = 0x00,
  kUninitialised = 0x01,
  kRequestSent = 0x02,
  kPendingResponse = 0x04,
  kConfirmed = 0x08,
  kBlocked = 0x10,
  kSpamer = 0x20
};
typedef std::map<NonEmptyString, std::pair<ContactStatus, ContactPresence> > ContactMap;

/// State Related Return Types
enum LifeStuffState { kZeroth, kInitialised, kConnected, kLoggedIn };
enum LoggedInState {
  kBaseState = 0x00,
  kCredentialsLoggedIn = 0x01,
  kDriveMounted = 0x02,
  kMessagesAndIntrosStarted = 0x04
};

/// Share levels
enum ShareLevel {
  kOwner = 0,
  kGroup,
  kWorld
};

/// Constants
const size_t kMaxChatMessageSize(1 * 1024 * 1024);
const uint32_t kFileRecontructionLimit(20 * 1024 * 1024);
const uint8_t kThreads(5);
const uint8_t kSecondsInterval(5);
const size_t kMinWordSize(5);
const size_t kMaxWordSize(30);
const size_t kMaxPublicIdSize(30);
const size_t kPinSize(4);
const std::string kLiteralOnline("kOnline");
const std::string kLiteralOffline("kOffline");
const NonEmptyString kBlankProfilePicture("BlankPicture");
const std::string kAppHomeDirectory(".lifestuff");
const std::string kMyStuff("My Stuff");
const std::string kDownloadStuff("Accepted Files");
const std::string kHiddenFileExtension(".ms_hidden");

/// General Call Back function signatures
typedef std::function<void(const NonEmptyString&, const NonEmptyString&, const NonEmptyString&)>
        ThreeStringsFunction;
typedef std::function<void(const NonEmptyString&,  // NOLINT (Fraser)
                           const NonEmptyString&,
                           const NonEmptyString&,
                           const NonEmptyString&)>
        FourStringsFunction;
typedef std::function<void(const NonEmptyString&,  // NOLINT (Fraser)
                           const NonEmptyString&,
                           const NonEmptyString&,
                           const NonEmptyString&,
                           const NonEmptyString&)>
        FiveStringsFunction;
typedef std::function<void(const NonEmptyString&,  // NOLINT (Fraser)
                           const NonEmptyString&,
                           const NonEmptyString&,
                           const NonEmptyString&,
                           const NonEmptyString&,
                           const NonEmptyString&)>
        SixStringsFunction;

/// Operation Result
// success or failure for SendMsg, ShareElement, AddContact, ShareVault and SendFile
enum class LifeStuffOperation : int {
  kAddContact = 1,
  kSendMsg,
  kSendFile,
  kShareElement,
  kShareVault
};

// Own public ID, Contact public ID, LifeStuffOpertion, request_id, result
typedef std::function<void(const NonEmptyString&,
                           const NonEmptyString&,
                           LifeStuffOperation,
                           const NonEmptyString&,
                           int)> OpertionResultFunction;

/// Message Received : notification, chat and email
// Own public ID, Contact public ID, request_id, Message, Timestamp
typedef FiveStringsFunction MsgFunction;

/// Element shared
// Own public ID, Contact public ID, request_id, element_path, data_map_hash, Timestamp
typedef SixStringsFunction ElementShareFunction;

/// File transfer
// Own public ID, Contact public ID, request_id, file_name, data_map_hash, Timestamp
typedef SixStringsFunction FileTransferFunction;

/// Vault shared
struct VaultUsageInfo {
  NonEmptyString id;
  uint64_t size_in_KB;
  uint64_t free_space_in_KB;
  int rank;
  // include owner id(s)?
};

// Own public ID, Contact public ID, request_id, vault_info, Timestamp
typedef std::function<void(const NonEmptyString&,
                           const NonEmptyString&,
                           const NonEmptyString&,
                           const VaultUsageInfo&,
                           const NonEmptyString&)> VaultShareFunction;

/// Contact
// Own public ID, Contact public ID, request_id, introduction_msg, Timestamp
typedef FiveStringsFunction ContactRequestFunction;

// Own public ID, Contact public ID, Timestamp, contact_presence
typedef std::function<void(const NonEmptyString&,          // Own public ID
                           const NonEmptyString&,          // Contact public ID
                           const NonEmptyString&,          // Timestamp
                           ContactPresence presence)>      // online/offline
        ContactPresenceFunction;

// Own public ID, Contact public ID, Message, Timestamp
typedef std::function<void(const NonEmptyString&,          // Own public ID
                           const NonEmptyString&,          // Contact public ID
                           const std::string&,             // Message
                           const NonEmptyString&)> ContactDeletionFunction;

/// New version update
typedef std::function<void(NonEmptyString)> UpdateAvailableFunction;  // NOLINT (Dan)

/// Network health
typedef std::function<void(const int&)> NetworkHealthFunction;  // NOLINT (Dan)

/// Quitting
typedef std::function<void()> ImmediateQuitRequiredFunction;

/// Operation Progress Report for multi-stage operations
enum class MultiStageOperation : int {
  kCreateUser = -1,
  kLogIn = -2,
  kLogOut = -3
};
enum class SubTask : int {
  kInitialiseAnonymousComponents = -1001,
  kCreateUserCredentials = -1002,
  kCreateVault = -1003,
  kInitialiseClientComponents = -1004,
  kRetrieveUserCredentials = -1005,
  kStoreUserCredentials = -1006,
  kWaitForNetworkOperations = -1007,
  kCleanUp = -1008
};
// multi_stage_operation, sub_task
typedef std::function<void(MultiStageOperation, SubTask)> OperationProgressFunction;

struct Slots {
  OpertionResultFunction operation_result_slot;
  MsgFunction msg_slot;
  ElementShareFunction element_share_slot;
  FileTransferFunction file_transfer_slot;
  VaultShareFunction vault_share_slot;
  ContactRequestFunction contact_request_slot;
  ContactPresenceFunction contact_presence_slot;
  ContactDeletionFunction contact_deletion_slot;
  UpdateAvailableFunction update_available_slot;
  NetworkHealthFunction network_health_slot;
  ImmediateQuitRequiredFunction immediate_quit_required_slot;
  OperationProgressFunction operation_progress_slot;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_H_



// /*
// * ============================================================================
// *
// * Copyright [2009] maidsafe.net limited
// *
// * Description:  Definition of system-wide constants/enums/structs
// * Version:      1.0
// * Created:      2009-01-29-00.15.50
// * Revision:     none
// * Compiler:     gcc
// * Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
// * Company:      maidsafe.net limited
// *
// * The following source code is property of maidsafe.net limited and is not
// * meant for external use.  The use of this code is governed by the license
// * file LICENSE.TXT found in the root of this directory and also on
// * www.maidsafe.net.
// *
// * You are not free to copy, amend or otherwise use this source code without
// * the explicit written permission of the board of directors of maidsafe.net.
// *
// * ============================================================================
// */
//
// #ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_H_
// #define MAIDSAFE_LIFESTUFF_LIFESTUFF_H_
//
// #include <cstdint>
// #include <functional>
// #include <map>
// #include <string>
// #include <utility>
// #include <vector>
//
// #include "boost/filesystem/path.hpp"
//
// #include "maidsafe/common/types.h"
//
// #include "maidsafe/lifestuff/return_codes.h"
//
// namespace maidsafe {
//
// namespace lifestuff {
//
// enum DefConLevels { kDefCon1 = 1, kDefCon2, kDefCon3 };
// enum ContactOrder { kAlphabetical, kPopular, kLastContacted };
//
// typedef
// struct LifeStuffReturn {
//  // constructed based on exception.error_code() then get translated into LifeStuff ReturnCode
//  ReturnCode return_code;
//  char* msg;  // exception.what()
// };
//
// /// Contact Related Return Types
// typedef uint16_t ContactRank;
// enum ContactPresence { kOffline, kOnline };
// enum ContactStatus {
//  kAll = 0x00,
//  kUninitialised = 0x01,
//  kRequestSent = 0x02,
//  kPendingResponse = 0x04,
//  kConfirmed = 0x08,
//  kBlocked = 0x10,
//  kSpamer = 0x20
// };
// typedef std::map<NonEmptyString, std::pair<ContactStatus, ContactPresence> > ContactMap;
//
// /// State Related Return Types
// enum LifeStuffState { kZeroth, kInitialised, kConnected, kLoggedIn };
// enum LoggedInState {
//  kBaseState = 0x00,
//  kCredentialsLoggedIn = 0x01,
//  kDriveMounted = 0x02,
//  kMessagesAndIntrosStarted = 0x04
// };
//
// /// Share levels
// enum ShareLevel {
//  kOwner = 0,
//  kGroup,
//  kWorld
// };
//
// /// Constants
// const size_t kMaxChatMessageSize(1 * 1024 * 1024);
// const uint32_t kFileRecontructionLimit(20 * 1024 * 1024);
// const uint8_t kThreads(5);
// const uint8_t kSecondsInterval(5);
// const size_t kMinWordSize(5);
// const size_t kMaxWordSize(30);
// const size_t kMaxPublicIdSize(30);
// const size_t kPinSize(4);
// const std::string kLiteralOnline("kOnline");
// const std::string kLiteralOffline("kOffline");
// const NonEmptyString kBlankProfilePicture("BlankPicture");
// const std::string kAppHomeDirectory(".lifestuff");
// const std::string kMyStuff("My Stuff");
// const std::string kDownloadStuff("Accepted Files");
// const std::string kHiddenFileExtension(".ms_hidden");
//
// /// General Call Back function signatures
// typedef std::function<void(const NonEmptyString&, const NonEmptyString&, const NonEmptyString&)>
//        ThreeStringsFunction;
// typedef std::function<void(const NonEmptyString&,  // NOLINT (Fraser)
//                           const NonEmptyString&,
//                           const NonEmptyString&,
//                           const NonEmptyString&)>
//        FourStringsFunction;
// typedef std::function<void(const NonEmptyString&,  // NOLINT (Fraser)
//                           const NonEmptyString&,
//                           const NonEmptyString&,
//                           const NonEmptyString&,
//                           const NonEmptyString&)>
//        FiveStringsFunction;
// typedef std::function<void(const NonEmptyString&,  // NOLINT (Fraser)
//                           const NonEmptyString&,
//                           const NonEmptyString&,
//                           const NonEmptyString&,
//                           const NonEmptyString&,
//                           const NonEmptyString&)>
//        SixStringsFunction;
//
// /// Operation Result
// // success or failure for SendMsg, ShareElement, AddContact, ShareVault and SendFile
// enum class LifeStuffOperation : int {
//  kAddContact = 1,
//  kSendMsg,
//  kSendFile,
//  kShareElement,
//  kShareVault
// };
//
// // Own public ID, Contact public ID, LifeStuffOpertion, request_id, result
// typedef std::function<void(const NonEmptyString&,
//                           const NonEmptyString&,
//                           LifeStuffOperation,
//                           const NonEmptyString&,
//                           int)> OpertionResultFunction;
//
// /// Message Received : notification, chat and email
// // Own public ID, Contact public ID, request_id, Message, Timestamp
// typedef FiveStringsFunction MsgFunction;
//
// /// Element shared
// // Own public ID, Contact public ID, request_id, element_path, data_map_hash, Timestamp
// typedef SixStringsFunction ElementShareFunction;
//
// /// File transfer
// // Own public ID, Contact public ID, request_id, file_name, data_map_hash, Timestamp
// typedef SixStringsFunction FileTransferFunction;
//
// /// Vault shared
// struct VaultUsageInfo {
//  NonEmptyString id;
//  uint64_t size_in_KB;
//  uint64_t free_space_in_KB;
//  int rank;
//  // include owner id(s)?
// };
//
// // Own public ID, Contact public ID, request_id, vault_info, Timestamp
// typedef std::function<void(const NonEmptyString&,
//                           const NonEmptyString&,
//                           const NonEmptyString&,
//                           const VaultUsageInfo&,
//                           const NonEmptyString&)> VaultShareFunction;
//
// /// Contact
// // Own public ID, Contact public ID, request_id, introduction_msg, Timestamp
// typedef FiveStringsFunction ContactRequestFunction;
//
// // Own public ID, Contact public ID, Timestamp, contact_presence
// typedef std::function<void(const NonEmptyString&,          // Own public ID
//                           const NonEmptyString&,          // Contact public ID
//                           const NonEmptyString&,          // Timestamp
//                           ContactPresence presence)>      // online/offline
//        ContactPresenceFunction;
//
// // Own public ID, Contact public ID, Message, Timestamp
// typedef std::function<void(const NonEmptyString&,          // Own public ID
//                           const NonEmptyString&,          // Contact public ID
//                           const std::string&,             // Message
//                           const NonEmptyString&)> ContactDeletionFunction;
//
// /// New version update
// typedef std::function<void(NonEmptyString)> UpdateAvailableFunction;  // NOLINT (Dan)
//
// /// Network health
// typedef std::function<void(const int&)> NetworkHealthFunction;  // NOLINT (Dan)
//
// /// Quitting
// typedef std::function<void()> ImmediateQuitRequiredFunction;
//
// /// Operation Progress Report for multi-stage operations
// enum class MultiStageOperation : int {
//  kCreateUser = -1,
//  kLogIn = -2,
//  kLogOut = -3
// };
// enum class SubTask : int {
//  kInitialiseAnonymousComponents = -1001,
//  kCreateUserCredentials = -1002,
//  kCreateVault = -1003,
//  kInitialiseClientComponents = -1004,
//  kRetrieveUserCredentials = -1005,
//  kStoreUserCredentials = -1006,
//  kWaitForNetworkOperations = -1007,
//  kCleanUp = -1008
// };
// // multi_stage_operation, sub_task
// typedef std::function<void(MultiStageOperation, SubTask)> OperationProgressFunction;
//
// struct Slots {
//  OpertionResultFunction operation_result_slot;
//  MsgFunction msg_slot;
//  ElementShareFunction element_share_slot;
//  FileTransferFunction file_transfer_slot;
//  VaultShareFunction vault_share_slot;
//  ContactRequestFunction contact_request_slot;
//  ContactPresenceFunction contact_presence_slot;
//  ContactDeletionFunction contact_deletion_slot;
//  UpdateAvailableFunction update_available_slot;
//  NetworkHealthFunction network_health_slot;
//  ImmediateQuitRequiredFunction immediate_quit_required_slot;
//  OperationProgressFunction operation_progress_slot;
// };
//
// }  // namespace lifestuff
//
// }  // namespace maidsafe
//
// #endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_H_
