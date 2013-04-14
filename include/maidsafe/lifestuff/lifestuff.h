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
#include <string>
#include <functional>

namespace maidsafe {
namespace lifestuff {

enum InputField {
  kPin = 0,
  kKeyword,
  kPassword,
  kConfirmationPin,
  kConfirmationKeyword,
  kConfirmationPassword,
  kCurrentPassword
};

enum Action {
  kCreateUser = 0,
  kLogin,
  kChangeKeyword,
  kChangePin,
  kChangePassword
};

enum ProgessCode {
  kInitialiseProcess = 0,
  kCreatingUserCredentials,
  kJoiningNetwork,
  kInitialisingClientComponents,
  kCreatingVault,
  kStartingVault,
  kVerifyingMount,
  kVerifyingUnmount,
  kStoringUserCredentials,
  kRetrievingUserCredentials
};

// New version update...
typedef std::function<void(const std::string&)> UpdateAvailableFunction;
// Network health...
typedef std::function<void(int32_t)> NetworkHealthFunction;
// Safe to quit...
typedef std::function<void(bool)> OperationsPendingFunction;
// Report progress...
typedef std::function<void(Action, ProgessCode)> ReportProgressFunction;

struct Slots {
  UpdateAvailableFunction update_available;
  NetworkHealthFunction network_health;
  OperationsPendingFunction operations_pending;
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
const std::string kBlankProfilePicture("BlankPicture");
const std::string kAppHomeDirectory(".lifestuff");
const std::string kOwner("Owner");
const std::string kDownloadStuff("Accepted Files");
const std::string kHiddenFileExtension(".ms_hidden");


//struct LifeStuffReturn {
//  // constructed based on exception.error_code() then get translated into LifeStuff ReturnCode
//  ReturnCode return_code;
//  char* msg;  // exception.what()
//};
//
//enum ContactOrder { kAlphabetical, kPopular, kLastContacted };
//
///// Contact Related Return Types
//typedef uint16_t ContactRank;
//enum ContactPresence { kOffline, kOnline };
//enum ContactStatus {
//  kAll = 0x00,
//  kUninitialised = 0x01,
//  kRequestSent = 0x02,
//  kPendingResponse = 0x04,
//  kConfirmed = 0x08,
//  kBlocked = 0x10,
//  kSpamer = 0x20
//};
//typedef std::map<NonEmptyString, std::pair<ContactStatus, ContactPresence> > ContactMap;
//
///// State Related Return Types
//enum LifeStuffState { kZeroth, kInitialised, kConnected, kLoggedIn };
//enum LoggedInState {
//  kBaseState = 0x00,
//  kCredentialsLoggedIn = 0x01,
//  kDriveMounted = 0x02,
//  kMessagesAndIntrosStarted = 0x04
//};
//
///// Share levels
//enum ShareLevel {
//  kOwner = 0,
//  kGroup,
//  kWorld
//};
//
///// Constants
//const size_t kMaxChatMessageSize(1 * 1024 * 1024);
//const uint32_t kFileRecontructionLimit(20 * 1024 * 1024);
//const uint8_t kThreads(5);
//const uint8_t kSecondsInterval(5);
//const size_t kMinWordSize(5);
//const size_t kMaxWordSize(30);
//const size_t kMaxPublicIdSize(30);
//const size_t kPinSize(4);
//const std::string kLiteralOnline("kOnline");
//const std::string kLiteralOffline("kOffline");
//const NonEmptyString kBlankProfilePicture("BlankPicture");
//const std::string kAppHomeDirectory(".lifestuff");
//const std::string kMyStuff("My Stuff");
//const std::string kDownloadStuff("Accepted Files");
//const std::string kHiddenFileExtension(".ms_hidden");
//
///// Operation Result
//// success or failure for SendMsg, ShareElement, AddContact, ShareVault and SendFile
//enum class LifeStuffOperation : int {
//  kAddContact = 1,
//  kSendMsg,
//  kSendFile,
//  kShareElement,
//  kShareVault
//};
//
//// Own public ID, Contact public ID, LifeStuffOpertion, request_id, result
//typedef std::function<void(const NonEmptyString&,
//                           const NonEmptyString&,
//                           LifeStuffOperation,
//                           const NonEmptyString&,
//                           int)> OpertionResultFunction;
//
///// Message Received : notification, chat and email
//// Own public ID, Contact public ID, request_id, Message, Timestamp
//typedef std::function<void(const NonEmptyString&,  // NOLINT (Fraser)
//                           const NonEmptyString&,
//                           const NonEmptyString&,
//                           const NonEmptyString&,
//                           const NonEmptyString&)> MsgFunction;
//
///// Element shared
//// Own public ID, Contact public ID, request_id, element_path, data_map_hash, Timestamp
//typedef std::function<void(const NonEmptyString&,  // NOLINT (Fraser)
//                           const NonEmptyString&,
//                           const NonEmptyString&,
//                           const NonEmptyString&,
//                           const NonEmptyString&,
//                           const NonEmptyString&)> ElementShareFunction;
//
///// File transfer
//// Own public ID, Contact public ID, request_id, file_name, data_map_hash, Timestamp
//typedef ElementShareFunction FileTransferFunction;
//
///// Vault shared
//struct VaultUsageInfo {
//  NonEmptyString id;
//  uint64_t size_in_KB;
//  uint64_t free_space_in_KB;
//  int rank;
//  // include owner id(s)?
//};
//
//// Own public ID, Contact public ID, request_id, vault_info, Timestamp
//typedef std::function<void(const NonEmptyString&,
//                           const NonEmptyString&,
//                           const NonEmptyString&,
//                           const VaultUsageInfo&,
//                           const NonEmptyString&)> VaultShareFunction;
//
///// Contact
//// Own public ID, Contact public ID, request_id, introduction_msg, Timestamp
//typedef std::function<void(const NonEmptyString&,  // NOLINT (Fraser)
//                           const NonEmptyString&,
//                           const NonEmptyString&,
//                           const NonEmptyString&,
//                           const NonEmptyString&)> ContactRequestFunction;
//
//// Own public ID, Contact public ID, Timestamp, contact_presence
//typedef std::function<void(const NonEmptyString&,          // Own public ID
//                           const NonEmptyString&,          // Contact public ID
//                           const NonEmptyString&,          // Timestamp
//                           ContactPresence presence)>      // online/offline
//        ContactPresenceFunction;
//
//// Own public ID, Contact public ID, Message, Timestamp
//typedef std::function<void(const NonEmptyString&,          // Own public ID
//                           const NonEmptyString&,          // Contact public ID
//                           const std::string&,             // Message
//                           const NonEmptyString&)> ContactDeletionFunction;

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_H_
