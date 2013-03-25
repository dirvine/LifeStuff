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

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/lifestuff_api.h"

namespace maidsafe {
namespace lifestuff {
namespace test {

class UserInputTest : public testing::Test {
 public:
  typedef std::unique_ptr<LifeStuff> LifeStuffPtr;

  UserInputTest()
    : lifestuff_() {}

 protected:
  void SetUp() {
    Slots slots;
    UpdateAvailableFunction update_available([](const std::string&) {});
    NetworkHealthFunction network_health([](int32_t) {});
    OperationsPendingFunction operations_pending([](bool) {});
    slots.update_available = update_available;
    slots.network_health = network_health;
    slots.operations_pending = operations_pending;
    lifestuff_.reset(new LifeStuff(slots));
  }

  void TearDown() {}

  LifeStuffPtr lifestuff_;
};

TEST_F(UserInputTest, BEH_ValidKeyword) {
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, 'k', kKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, 'e', kKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, 'y', kKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(3, 'w', kKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(4, 'o', kKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(5, 'r', kKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(6, 'd', kKeyword));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kKeyword));
}


}  // namespace test
}  // namespace lifestuff
}  // namespace maidsafe
