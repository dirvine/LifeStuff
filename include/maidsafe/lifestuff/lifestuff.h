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

#include "maidsafe/drive/config.h"
#include "maidsafe/lifestuff/version.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 400
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif


namespace maidsafe {

namespace lifestuff {

class Message;

enum DefConLevels {
  kDefCon1 = 1,
  kDefCon2,
  kDefCon3
};

enum ContactStatus {
  kAll = 0x00,
  kUnitialised = 0x01,
  kRequestSent = 0x02,
  kPendingResponse = 0x04,
  kConfirmed = 0x08,
  kBlocked = 0x10
};

enum ContactOrder {
  kAlphabetical,
  kPopular,
  kLastContacted
};

enum ContactPresence {
  kOffline,
  kOnline
};

enum LifeStuffState {
  kZeroth,
  kInitialised,
  kConnected,
  kLoggedIn,
  kLoggedOut
};

enum PrivateShareRoles {
  kShareRemover = drive::kShareRemover,
  kShareReadOnly = drive::kShareReadOnly,
  kShareReadWrite = drive::kShareReadWrite,
  kShareOwner = drive::kShareOwner
};

const size_t kMaxChatMessageSize(1 * 1024 * 1024);
const uint32_t kFileRecontructionLimit(20 * 1024 * 1024);
const uint16_t kIntervalSeconds(5000);
const uint8_t kThreads(10);
const uint8_t kSecondsInterval(5);
const size_t kMinWordSize(5);
const size_t kMaxWordSize(30);
const size_t kPinSize(4);
const std::string kLiteralOnline("kOnline");
const std::string kLiteralOffline("kOffline");
const std::string kAppHomeDirectory(".lifestuff");
const std::string kMyStuff("My Stuff");
const std::string kDownloadStuff("Accepted Files");
const std::string kSharedStuff("Shared Stuff");
const std::string kBlankProfilePicture("BlankPicture");

/// General
typedef std::function<void(const std::string&, const std::string&)>
        TwoStringsFunction;
typedef std::function<void(const std::string&,
                           const std::string&,
                           const std::string&)>
        ThreeStringsFunction;
typedef std::function<void(int)> VoidFunctionOneInt;  // NOLINT (Dan)
typedef std::function<void(bool)> VoidFunctionOneBool;  // NOLINT (Dan)
typedef std::map<std::string, int> StringIntMap;
typedef std::map<std::string, std::pair<ContactStatus, ContactPresence>>
        ContactMap;

/// Shares
typedef std::function<void(const std::string&,    // Own public ID
                           const std::string&,    // Contact public ID
                           const std::string&,    // Share Tag (share_name)
                           const std::string&)>   // Unique ID (share_id)
        ShareInvitationFunction;
typedef TwoStringsFunction ShareDeletionFunction;  // own public ID, share name
typedef std::function<void(const std::string&,  // Own public ID
                           const std::string&,  // Contact public ID
                           const std::string&,  // Share name
                           int)>                // Access level
        MemberAccessLevelFunction;

/// Chat
// Own public ID, Contact public ID, Message
typedef ThreeStringsFunction ChatFunction;

/// File transfer
typedef std::function<void(const std::string&,    // Own public ID
                           const std::string&,    // Contact public ID
                           const std::string&,    // File name
                           const std::string&)>   // File ID
        FileTransferFunction;

/// Contact info
typedef TwoStringsFunction NewContactFunction;  // Own & other public ID
typedef TwoStringsFunction ContactConfirmationFunction;  // Own, other public ID
typedef TwoStringsFunction
        ContactProfilePictureFunction;  // Own & other public ID
typedef std::function<void(const std::string&,          // Own public ID
                           const std::string&,          // Contact public ID
                           ContactPresence presence)>   // online/offline
        ContactPresenceFunction;
// Own public ID, Contact public ID, Message
typedef ThreeStringsFunction ContactDeletionFunction;

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_H_
