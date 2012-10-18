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

#include "maidsafe/common/types.h"

namespace bs2 = boost::signals2;


namespace maidsafe {

namespace lifestuff {

/// Extra library signals
typedef bs2::signal<void(const NonEmptyString&,  // NOLINT (Dan)
                         const NonEmptyString&,
                         const NonEmptyString&,
                         const NonEmptyString&)> ChatMessageSignal;

typedef bs2::signal<void(const NonEmptyString&,  // NOLINT (Dan)
                         const NonEmptyString&,
                         const NonEmptyString&,
                         const NonEmptyString&,
                         const NonEmptyString&)> FileTransferSuccessSignal;

typedef bs2::signal<void(const NonEmptyString&,  // NOLINT (Dan)
                         const NonEmptyString&,
                         const NonEmptyString&)> FileTransferFailureSignal;

typedef bs2::signal<void(const NonEmptyString&,  // NOLINT (Dan)
                         const NonEmptyString&,
                         const NonEmptyString&,
                         ContactPresence presence)> ContactPresenceSignal;

typedef bs2::signal<void(const NonEmptyString&,  // NOLINT (Dan)
                         const NonEmptyString&,
                         const NonEmptyString&)> ContactProfilePictureSignal;

/// Intra library signals
typedef bs2::signal<bool(const NonEmptyString&,  // NOLINT (Dan)
                         const NonEmptyString&,
                         std::string&)> ParseAndSaveDataMapSignal;

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_MESSAGE_HANDLER_SIGNAL_TYPES_H_
