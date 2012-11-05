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

namespace maidsafe {

namespace lifestuff {

enum DefConLevels { kDefCon1 = 1, kDefCon2, kDefCon3 };
enum ContactOrder { kAlphabetical, kPopular, kLastContacted };
enum ContactPresence { kOffline, kOnline };
enum LifeStuffState { kZeroth, kInitialised, kConnected, kLoggedIn };

enum ContactStatus {
  kAll = 0x00,
  kUninitialised = 0x01,
  kRequestSent = 0x02,
  kPendingResponse = 0x04,
  kConfirmed = 0x08,
  kBlocked = 0x10
};

enum LoggedInState {
  kBaseState = 0x00,
  kCredentialsLoggedIn = 0x01,
  kDriveMounted = 0x02,
  kMessagesAndIntrosStarted = 0x04
};

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

/// General
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

typedef std::function<void(int)> VoidFunctionOneInt;  // NOLINT (Dan)
typedef std::function<void(bool)> VoidFunctionOneBool;  // NOLINT (Dan)
typedef std::map<std::string, int> StringIntMap;
typedef std::map<NonEmptyString, std::string> SocialInfoMap;
typedef std::map<NonEmptyString, std::pair<ContactStatus, ContactPresence> > ContactMap;
typedef std::function<bool(const NonEmptyString&, std::string&)> ValidatedMessageFunction;


/// Chat
// Own public ID, Contact public ID, Message, Timestamp
typedef FourStringsFunction ChatFunction;

/// File transfer
// Own public ID, Contact public ID, Timestamp
typedef ThreeStringsFunction FileTransferFailureFunction;
// Own public ID, Contact public ID, File name, File ID, Timestamp
typedef FiveStringsFunction FileTransferSuccessFunction;

/// Contact info
// Own & other public ID, Timestamp
typedef ThreeStringsFunction ContactConfirmationFunction;
// Own & other public ID, Timestamp
typedef ThreeStringsFunction ContactProfilePictureFunction;
typedef std::function<void(const NonEmptyString&,          // Own public ID
                           const NonEmptyString&,          // Contact public ID
                           const NonEmptyString&,          // Timestamp
                           ContactPresence presence)>      // online/offline
        ContactPresenceFunction;
// Own public ID, Contact public ID, Message, Timestamp
typedef std::function<void(const NonEmptyString&,          // Own public ID
                           const NonEmptyString&,          // Contact public ID
                           const std::string&,             // Message
                           const NonEmptyString&)> ContactDeletionReceivedFunction;
// Own public ID, Contact public ID, Message, Timestamp  // For when deletion has been processed
typedef std::function<void(const NonEmptyString&,          // Own public ID
                           const NonEmptyString&,          // Contact public ID
                           const std::string&,             // Message
                           const NonEmptyString&)> ContactDeletionFunction;
// Own & other public ID, Message, Timestamp
typedef std::function<void(const NonEmptyString&,          // Own public ID
                           const NonEmptyString&,          // Contact public ID
                           const std::string&,             // Message
                           const NonEmptyString&)> NewContactFunction;
// Lifestuff Card change: Own & other public ID, Timestamp
typedef ThreeStringsFunction LifestuffCardUpdateFunction;

/// New version update
typedef std::function<void(NonEmptyString)> UpdateAvailableFunction;  // NOLINT (Dan)

/// Network health
typedef std::function<void(const int&)> NetworkHealthFunction;  // NOLINT (Dan)

/// Quitting
typedef std::function<void()> ImmediateQuitRequiredFunction;
}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_H_
