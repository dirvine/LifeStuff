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
#include <string>
#include <vector>

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

enum InboxItemType {
  kChat,
  kFileTransfer,
  kSharedDirectory,
  kContactPresence,
  kContactProfilePicture,

  // First and last markers
  kInboxItemTypeFirst = kChat,
  kInboxItemTypeLast = kContactProfilePicture
};

struct InboxItem {
  explicit InboxItem(InboxItemType inbox_item_type = kChat)
      : item_type(inbox_item_type),
        sender_public_id(),
        receiver_public_id(),
        content(),
        timestamp() {}
  InboxItemType item_type;
  std::string sender_public_id;
  std::string receiver_public_id;
  std::vector<std::string> content;
  std::string timestamp;
};

const uint32_t kFileRecontructionLimit(20 * 1024 * 1024);
const uint16_t kIntervalSeconds(5000);
const uint8_t kThreads(10);
const uint8_t kSecondsInterval(5);
const std::string kLiteralOnline("kOnline");
const std::string kLiteralOffline("kOffline");

typedef std::function<void(const InboxItem&)> InboxItemFunction;
typedef InboxItemFunction ChatFunction;
typedef InboxItemFunction FileTransferFunction;
typedef InboxItemFunction ShareFunction;

typedef std::function<void(int)> VoidFunctionOneInt;  // NOLINT (Dan)
typedef std::function<void(const std::string&)> OneStringFunction;

typedef std::function<void(const std::string&, const std::string&)>
        TwoStringsFunction;
typedef TwoStringsFunction NewContactFunction;
typedef TwoStringsFunction ContactConfirmationFunction;
typedef TwoStringsFunction ContactProfilePictureFunction;

typedef std::function<void(const std::string&,
                           const std::string&,
                           ContactPresence presence)> ContactPresenceFunction;
namespace args = std::placeholders;

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_H_
