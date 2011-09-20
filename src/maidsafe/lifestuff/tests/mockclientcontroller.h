/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Mock ClientController
* Created:      2010-02-18
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

#ifndef MAIDSAFE_LIFESTUFF_TESTS_MOCKCLIENTCONTROLLER_H_
#define MAIDSAFE_LIFESTUFF_TESTS_MOCKCLIENTCONTROLLER_H_

#include "maidsafe/lifestuff/clientcontroller.h"
#include "maidsafe/lifestuff/tests/mocksessionsingleton.h"

namespace maidsafe {

namespace lifestuff {

class MockClientController : public ClientController {
 public:
  MockClientController() : ClientController() {
    ss_ = std::shared_ptr<SessionSingleton>(new MockSessionSingleton);
  }
  ~MockClientController() {
    ss_.reset();
  }
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_TESTS_MOCKCLIENTCONTROLLER_H_