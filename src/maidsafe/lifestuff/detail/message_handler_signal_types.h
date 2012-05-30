/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_MESSAGE_HANDLER_SIGNAL_TYPES_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_MESSAGE_HANDLER_SIGNAL_TYPES_H_


#include <functional>
#include <memory>
#include <string>

#include "boost/signals2.hpp"

namespace bs2 = boost::signals2;


namespace maidsafe {

namespace lifestuff {

/// Extra library signals
typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                         const std::string&,
                         const std::string&,
                         const std::string&)> ChatMessageSignal;

typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                         const std::string&,
                         const std::string&,
                         const std::string&,
                         const std::string&)> FileTransferSignal;

typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                         const std::string&,
                         const std::string&,
                         ContactPresence presence)> ContactPresenceSignal;

typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                         const std::string&,
                         const std::string&)> ContactProfilePictureSignal;

typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                         const std::string&,
                         const std::string&,
                         const std::string&,
                         int,
                         const std::string&)> PrivateShareInvitationSignal;

typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                         const std::string&,
                         const std::string&,
                         const std::string&,
                         const std::string&)> PrivateShareDeletionSignal;

typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                         const std::string&,
                         const std::string&,
                         const std::string&,
                         const std::string&,
                         const std::string&,
                         const asymm::Keys&,
                         int,
                         const std::string&)> PrivateMemberAccessLevelSignal;

typedef bs2::signal<void(const std::string&,  // NOLINT
                         const std::string&,
                         const std::string&,
                         const std::string&,
                         const std::string&)> OpenShareInvitationSignal;

/// Intra and extra library signals2
typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                         const std::string&,
                         const std::string&,
                         const std::string&)> ContactDeletionSignal;

typedef bs2::signal<void(const std::string&,  // share name
                         const std::string&,  // share id
                         const std::string&)> PrivateShareUserLeavingSignal;  // user_id  // NOLINT (Dan)

/// Intra library signals
typedef bs2::signal<bool(const std::string&,  // NOLINT (Dan)
                         const std::string&,
                         std::string*)> ParseAndSaveDataMapSignal;

typedef bs2::signal<int(const std::string&, fs::path*)>  // NOLINT (Dan)
        PrivateShareDetailsSignal;

typedef bs2::signal<void(const std::string&,  // share id
                         std::string*,  // directory id
                         std::string*,  // new share id
                         asymm::Keys*,  // new key
                         int*)> PrivateShareUpdateSignal;  // access right

typedef bs2::signal<bool(const std::string&,  // NOLINT (Dan)
                         const std::string&)> SavePrivateShareDataSignal;

typedef bs2::signal<bool(const std::string&)> DeletePrivateShareDataSignal;  // NOLINT (Dan)

typedef bs2::signal<bool(const std::string&,  // NOLINT
                         const std::string&)> SaveOpenShareDataSignal;

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_MESSAGE_HANDLER_SIGNAL_TYPES_H_
