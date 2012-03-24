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

enum DefConLevels { kDefCon1 = 1, kDefCon2, kDefCon3 };
typedef std::function<void(int)> VoidFuncOneInt;  // NOLINT (Dan)

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

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_H_
