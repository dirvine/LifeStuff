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

/// THIS ENUM MUST BE KEPT IN SYNC WITH THE ONE IN DRIVE'S CONFIG.H !!!
enum OpType { kCreated, kRenamed, kAdded, kRemoved, kMoved, kModified };

const size_t kMaxChatMessageSize(1 * 1024 * 1024);
const uint32_t kFileRecontructionLimit(20 * 1024 * 1024);
const uint8_t kThreads(10);
const uint8_t kSecondsInterval(5);
const size_t kMinWordSize(5);
const size_t kMaxWordSize(30);
const size_t kPinSize(4);
const std::string kLiteralOnline("kOnline");
const std::string kLiteralOffline("kOffline");
const std::string kBlankProfilePicture("BlankPicture");
const std::string kAppHomeDirectory(".lifestuff");
const std::string kMyStuff("My Stuff");
const std::string kDownloadStuff("Accepted Files");

const std::string kSharedStuff("Shared Stuff");
const std::string kHiddenFileExtension(".ms_hidden");

/// General
typedef std::function<void(const std::string&, const std::string&, const std::string&)>
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

typedef PrivateShareInvitationFunction PrivateMemberAccessChangeFunction;

/// Open Shares
// Own public ID, Contact public ID, Share name, Share ID, Timestamp
typedef FiveStringsFunction OpenShareInvitationFunction;

/// Common for Private and Open Shares
// Old ShareName, New ShareName
typedef std::function<void(const std::string&, const std::string&)> ShareRenamedFunction;

// share_name,
// target path relative to the Share's root,
// num_of_entries (normally 1, only greater in case of Add and Delete children)
// old path relative to the Share's root (only for Rename and Move),
// new path relative to the Share's root (only for Rename and Move),
// and operation type.
typedef std::function<void(const std::string&,
                           const boost::filesystem::path&,
                           const uint32_t&,
                           const boost::filesystem::path&,
                           const boost::filesystem::path&,
                           const int&)>
        ShareChangedFunction;

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
