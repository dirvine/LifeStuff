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

#include "maidsafe/common/rsa.h"

namespace maidsafe {

namespace lifestuff {

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

/// THIS ENUM MUST BE KEPT IN SYNC WITH THE ONE IN DRIVE'S CONFIG.H !!!
enum PrivateShareRoles {
  kShareRemover  = -1,
  kShareReadOnly = 0,
  kShareReadWrite = 1,
  kShareOwner = 2
};

extern const size_t kMaxChatMessageSize;
extern const uint32_t kFileRecontructionLimit;
extern const uint16_t kIntervalSeconds;
extern const uint8_t kThreads;
extern const uint8_t kSecondsInterval;
extern const size_t kMinWordSize;
extern const size_t kMaxWordSize;
extern const size_t kPinSize;
extern const std::string kLiteralOnline;
extern const std::string kLiteralOffline;
extern const std::string kAppHomeDirectory;
extern const std::string kMyStuff;
extern const std::string kDownloadStuff;
extern const std::string kSharedStuff;
extern const std::string kBlankProfilePicture;
extern const std::string kHiddenFileExtension;

/// General
typedef std::function<void(const std::string&,
                           const std::string&,
                           const std::string&)>
        ThreeStringsFunction;
typedef std::function<void(const std::string&,
                           const std::string&,
                           const std::string&,
                           const std::string&)>
        FourStringsFunction;
typedef std::function<void(const std::string&,
                           const std::string&,
                           const std::string&,
                           const std::string&,
                           const std::string&)>
        FiveStringsFunction;

typedef std::function<void(int)> VoidFunctionOneInt;  // NOLINT (Dan)
typedef std::function<void(bool)> VoidFunctionOneBool;  // NOLINT (Dan)
typedef std::map<std::string, int> StringIntMap;
typedef std::map<std::string, std::pair<ContactStatus, ContactPresence>> ContactMap;

/// Private Shares
// Own ID, Contact ID, Share Name, Share ID, Access Level, Timestamp
typedef std::function<void(const std::string&,    // Own public ID
                           const std::string&,    // Contact public ID
                           const std::string&,    // Share name
                           const std::string&,    // Share ID
                           int,                   // Access level
                           const std::string&)>   // Timestamp
        PrivateShareInvitationFunction;

// Own public ID, Contact public ID, Share Name, Share ID, Timestamp
typedef FiveStringsFunction PrivateShareDeletionFunction;

typedef std::function<void(const std::string&,    // Own public ID
                           const std::string&,    // Contact public ID
                           const std::string&,    // Share name
                           const std::string&,    // Share ID
                           const std::string&,    // Directory ID
                           const std::string&,    // New Share ID
                           const asymm::Keys&,    // Key ring
                           int,                   // Access level
                           const std::string&)>   // Timestamp
        PrivateMemberAccessLevelFunction;

/// Open Shares
// Own public ID, Contact public ID, Share name, Share ID, Timestamp
typedef FiveStringsFunction OpenShareInvitationFunction;

/// Common for Private and Open Shares
// Old ShareName, New ShareName
typedef std::function<void(const std::string&, const std::string&)> ShareRenamedFunction;

/// Chat
// Own public ID, Contact public ID, Message, Timestamp
typedef FourStringsFunction ChatFunction;

/// File transfer
// Own public ID, Contact public ID, File name, File ID, Timestamp
typedef FiveStringsFunction FileTransferFunction;

/// Contact info
// Own & other public ID, Timestamp
typedef ThreeStringsFunction NewContactFunction;
// Own & other public ID, Timestamp
typedef ThreeStringsFunction ContactConfirmationFunction;
// Own & other public ID, Timestamp
typedef ThreeStringsFunction ContactProfilePictureFunction;
typedef std::function<void(const std::string&,          // Own public ID
                           const std::string&,          // Contact public ID
                           const std::string&,          // Timestamp
                           ContactPresence presence)>   // online/offline
        ContactPresenceFunction;
// Own public ID, Contact public ID, Message, Timestamp
typedef FourStringsFunction ContactDeletionFunction;

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_H_
