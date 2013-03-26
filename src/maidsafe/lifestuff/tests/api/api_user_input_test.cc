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

TEST_F(UserInputTest, BEH_ValidPin) {
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, '0', kPin));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, '1', kPin));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, '2', kPin));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(3, '3', kPin));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kPin));
}

TEST_F(UserInputTest, BEH_ValidPassword) {
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, 'p', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, 'a', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, 's', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(3, 's', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(4, 'w', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(5, 'o', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(6, 'r', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(7, 'd', kPassword));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kPassword));
}

TEST_F(UserInputTest, BEH_ValidConfirmationKeyword) {
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, 'k', kKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, 'e', kKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, 'y', kKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(3, 'w', kKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(4, 'o', kKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(5, 'r', kKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(6, 'd', kKeyword));

  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(6, 'd', kConfirmationKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(5, 'r', kConfirmationKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(4, 'o', kConfirmationKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(3, 'w', kConfirmationKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, 'y', kConfirmationKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, 'e', kConfirmationKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, 'k', kConfirmationKeyword));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kConfirmationKeyword));
}

TEST_F(UserInputTest, BEH_ValidConfirmationPin) {
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, '0', kPin));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, '1', kPin));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, '2', kPin));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(3, '3', kPin));

  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(3, '3', kConfirmationPin));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, '2', kConfirmationPin));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, '1', kConfirmationPin));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, '0', kConfirmationPin));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kConfirmationPin));
}

TEST_F(UserInputTest, BEH_ValidConfirmationPassword) {
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, 'p', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, 'a', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, 's', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(3, 's', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(4, 'w', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(5, 'o', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(6, 'r', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(7, 'd', kPassword));

  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(7, 'd', kConfirmationPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(6, 'r', kConfirmationPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(5, 'o', kConfirmationPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(4, 'w', kConfirmationPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(3, 's', kConfirmationPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, 's', kConfirmationPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, 'a', kConfirmationPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, 'p', kConfirmationPassword));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kConfirmationPassword));
}

TEST_F(UserInputTest, BEH_PasswordClearRedo) {
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, 'p', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, 'a', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, 's', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(3, 's', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(4, 'w', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(5, 'o', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(6, 'r', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(7, 'd', kPassword));

  EXPECT_EQ(kSuccess, lifestuff_->ClearUserInput(kPassword));

  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(7, 'd', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(6, 'r', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(5, 'o', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(4, 'w', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(3, 's', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, 's', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, 'a', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, 'p', kPassword));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kPassword));
}

TEST_F(UserInputTest, BEH_PasswordInsertRemove) {
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, 'p', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, 'a', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, 's', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(3, 's', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(4, 'w', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(5, 'o', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(6, 'r', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(7, 'd', kPassword));

  EXPECT_EQ(kSuccess, lifestuff_->RemoveUserInput(7, 1, kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->RemoveUserInput(6, 1, kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->RemoveUserInput(5, 1, kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->RemoveUserInput(4, 1, kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->RemoveUserInput(3, 1, kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->RemoveUserInput(2, 1, kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->RemoveUserInput(1, 1, kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->RemoveUserInput(0, 1, kPassword));

  EXPECT_FALSE(lifestuff_->ConfirmUserInput(kPassword));

  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, 'p', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, 'a', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, 's', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(3, 's', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(4, 'w', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(5, 'o', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(6, 'r', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(7, 'd', kPassword));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kPassword));
}

TEST_F(UserInputTest, BEH_InvalidKeyword) {
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, 'k', kKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, 'e', kKeyword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, 'y', kKeyword));

  EXPECT_FALSE(lifestuff_->ConfirmUserInput(kKeyword));
}

TEST_F(UserInputTest, BEH_InvalidPin) {
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, '0', kPin));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, '1', kPin));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, '2', kPin));

  EXPECT_FALSE(lifestuff_->ConfirmUserInput(kPin));

  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(3, '3', kPin));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(4, '4', kPin));

  EXPECT_FALSE(lifestuff_->ConfirmUserInput(kPin));

  EXPECT_EQ(kSuccess, lifestuff_->RemoveUserInput(4, 1, kPin));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kPin));
}

TEST_F(UserInputTest, BEH_InvalidConfirmationPassword) {
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, 'p', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, 'a', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, 's', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(3, 's', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(4, 'w', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(5, 'o', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(6, 'r', kPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(7, 'd', kPassword));

  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(7, 'd', kConfirmationPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(6, 'r', kConfirmationPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(5, 'o', kConfirmationPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(4, 'w', kConfirmationPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(3, 's', kConfirmationPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(2, 's', kConfirmationPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(1, 'a', kConfirmationPassword));
  EXPECT_EQ(kSuccess, lifestuff_->InsertUserInput(0, 'q', kConfirmationPassword));

  EXPECT_FALSE(lifestuff_->ConfirmUserInput(kConfirmationPassword));
}

}  // namespace test
}  // namespace lifestuff
}  // namespace maidsafe
