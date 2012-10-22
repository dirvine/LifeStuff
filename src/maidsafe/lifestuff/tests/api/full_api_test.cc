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

#include <functional>
#include <sstream>

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/lifestuff_api.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/message_handler.h"
#include "maidsafe/lifestuff/detail/public_id.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/user_credentials.h"
#include "maidsafe/lifestuff/detail/user_storage.h"
#include "maidsafe/lifestuff/tests/api/api_test_resources.h"

namespace args = std::placeholders;
namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

namespace test {

TEST_F(OneUserApiTest, FUNC_LoggedInState) {
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));

  EXPECT_EQ(test_elements_.state(), kConnected);
  EXPECT_EQ(test_elements_.logged_in_state(), kBaseState);

  // full login and logout (without public ID)
  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
  EXPECT_EQ(test_elements_.state(), kLoggedIn);
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(kSuccess, test_elements_.MountDrive());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
  EXPECT_EQ(kStartMessagesAndContactsNoPublicIds, test_elements_.StartMessagesAndIntros());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
  EXPECT_EQ(kSuccess, test_elements_.StopMessagesAndIntros());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
  EXPECT_EQ(kSuccess, test_elements_.UnMountDrive());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(kSuccess, test_elements_.LogOut());

  EXPECT_EQ(test_elements_.state(), kConnected);
  EXPECT_EQ(test_elements_.logged_in_state(), kBaseState);

  NonEmptyString keyword2(RandomAlphaNumericString(6));
  NonEmptyString pin2(CreatePin());
  NonEmptyString password2(RandomAlphaNumericString(6));
  NonEmptyString public_id2(RandomAlphaNumericString(5));

  // full login, create public ID, full logout
  EXPECT_EQ(kSuccess, test_elements_.CreateUser(keyword2, pin2, password2));
  EXPECT_EQ(test_elements_.state(), kLoggedIn);
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(kSuccess, test_elements_.MountDrive());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
  EXPECT_EQ(kStartMessagesAndContactsNoPublicIds, test_elements_.StartMessagesAndIntros());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
  EXPECT_EQ(kSuccess, test_elements_.CreatePublicId(public_id2));
  EXPECT_EQ(test_elements_.logged_in_state(),
            kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);
  EXPECT_EQ(kSuccess, test_elements_.StopMessagesAndIntros());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
  EXPECT_EQ(kSuccess, test_elements_.UnMountDrive());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(kSuccess, test_elements_.LogOut());

  EXPECT_EQ(test_elements_.state(), kConnected);
  EXPECT_EQ(test_elements_.logged_in_state(), kBaseState);

  // full login and logout (with public ID)
  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword2, pin2, password2));
  EXPECT_EQ(test_elements_.state(), kLoggedIn);
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(kSuccess, test_elements_.MountDrive());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
  EXPECT_EQ(kSuccess, test_elements_.StartMessagesAndIntros());
  EXPECT_EQ(test_elements_.logged_in_state(),
            kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);
  EXPECT_EQ(kSuccess, test_elements_.StopMessagesAndIntros());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
  EXPECT_EQ(kSuccess, test_elements_.UnMountDrive());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(kSuccess, test_elements_.LogOut());

  EXPECT_EQ(test_elements_.state(), kConnected);
  EXPECT_EQ(test_elements_.logged_in_state(), kBaseState);

  // log credentials in and out
  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
  EXPECT_EQ(test_elements_.state(), kLoggedIn);
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(kSuccess, test_elements_.LogOut());
  EXPECT_EQ(test_elements_.state(), kConnected);
  EXPECT_EQ(test_elements_.logged_in_state(), kBaseState);

  // do and undo credentials and drive aspects
  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
  EXPECT_EQ(test_elements_.state(), kLoggedIn);
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(kSuccess, test_elements_.MountDrive());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
  EXPECT_EQ(kSuccess, test_elements_.UnMountDrive());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(kSuccess, test_elements_.LogOut());
  EXPECT_EQ(test_elements_.state(), kConnected);
  EXPECT_EQ(test_elements_.logged_in_state(), kBaseState);

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, pin_, password_));
}

TEST_F(OneUserApiTest, FUNC_IncorrectLoginLogoutSequences) {
  // Logged in with no public ID
  NonEmptyString public_id(RandomAlphaNumericString(5));
  EXPECT_EQ(test_elements_.state(), kLoggedIn);
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
  EXPECT_EQ(kSuccess, test_elements_.CreatePublicId(public_id));

  // Try logout components in wrong order
  EXPECT_EQ(test_elements_.logged_in_state(),
            kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);
  EXPECT_EQ(kWrongLoggedInState, test_elements_.UnMountDrive());
  EXPECT_EQ(test_elements_.logged_in_state(),
            kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);
  EXPECT_EQ(kWrongLoggedInState, test_elements_.LogOut());
  EXPECT_EQ(test_elements_.logged_in_state(),
            kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);
  EXPECT_EQ(kSuccess, test_elements_.StopMessagesAndIntros());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
  EXPECT_EQ(kWrongLoggedInState, test_elements_.LogOut());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
  EXPECT_EQ(kSuccess, test_elements_.UnMountDrive());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(kSuccess, test_elements_.LogOut());

  EXPECT_EQ(test_elements_.state(), kConnected);
  EXPECT_EQ(test_elements_.logged_in_state(), kBaseState);

  // try login components in wrong order
  EXPECT_EQ(kWrongLoggedInState, test_elements_.MountDrive());
  EXPECT_EQ(test_elements_.state(), kConnected);
  EXPECT_EQ(test_elements_.logged_in_state(), kBaseState);
  EXPECT_EQ(kWrongLoggedInState, test_elements_.StartMessagesAndIntros());
  EXPECT_EQ(test_elements_.state(), kConnected);
  EXPECT_EQ(test_elements_.logged_in_state(), kBaseState);
  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
  EXPECT_EQ(test_elements_.state(), kLoggedIn);
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(kWrongLoggedInState, test_elements_.StartMessagesAndIntros());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(kSuccess, test_elements_.MountDrive());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
  EXPECT_EQ(kSuccess, test_elements_.StartMessagesAndIntros());
  EXPECT_EQ(test_elements_.logged_in_state(),
            kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);

  // try repeating logout components
  EXPECT_EQ(kSuccess, test_elements_.StopMessagesAndIntros());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
  EXPECT_EQ(kSuccess, test_elements_.UnMountDrive());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(kWrongLoggedInState, test_elements_.UnMountDrive());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(kSuccess, test_elements_.LogOut());
  EXPECT_EQ(test_elements_.state(), kConnected);
  EXPECT_EQ(test_elements_.logged_in_state(), kBaseState);
  EXPECT_EQ(kWrongState, test_elements_.LogOut());

  EXPECT_EQ(test_elements_.state(), kConnected);
  EXPECT_EQ(test_elements_.logged_in_state(), kBaseState);

  // try repeating login components
  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
  EXPECT_EQ(test_elements_.state(), kLoggedIn);
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(kWrongState, test_elements_.LogIn(keyword_, pin_, password_));
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(kSuccess, test_elements_.MountDrive());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
  EXPECT_EQ(kWrongLoggedInState, test_elements_.MountDrive());
  EXPECT_EQ(test_elements_.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
  EXPECT_EQ(kSuccess, test_elements_.StartMessagesAndIntros());
  EXPECT_EQ(test_elements_.logged_in_state(),
            kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);
  EXPECT_EQ(kWrongLoggedInState, test_elements_.StartMessagesAndIntros());
  EXPECT_EQ(test_elements_.logged_in_state(),
            kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);
}

TEST_F(TwoUsersApiTest, FUNC_DriveNotMountedTryOperations) {
  EXPECT_EQ(test_elements_1_.logged_in_state(), kBaseState);
  EXPECT_EQ(test_elements_2_.logged_in_state(), kBaseState);
  EXPECT_EQ(test_elements_1_.state(), kConnected);
  EXPECT_EQ(test_elements_2_.state(), kConnected);

  testing_variables_1_.newly_contacted = false;
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
  EXPECT_EQ(test_elements_2_.logged_in_state(),
            kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);
  EXPECT_EQ(test_elements_2_.state(), kLoggedIn);
  NonEmptyString public_id_3(RandomAlphaNumericString(5));
  NonEmptyString message(RandomAlphaNumericString(5));
  EXPECT_EQ(kSuccess, test_elements_2_.CreatePublicId(public_id_3));
  EXPECT_EQ(kSuccess, test_elements_2_.AddContact(public_id_3, public_id_1_, message));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
  EXPECT_EQ(test_elements_2_.logged_in_state(), kBaseState);
  EXPECT_EQ(test_elements_2_.state(), kConnected);

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
  int i(0);
  while (!testing_variables_1_.newly_contacted && i < 100) {
    ++i;
    Sleep(bptime::milliseconds(100));
  }
  EXPECT_TRUE(testing_variables_1_.newly_contacted);
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));

  EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
  EXPECT_EQ(test_elements_1_.logged_in_state(), kCredentialsLoggedIn);
  EXPECT_EQ(test_elements_1_.state(), kLoggedIn);

  NonEmptyString public_id_4(RandomAlphaNumericString(5));
  EXPECT_EQ(kWrongLoggedInState, test_elements_1_.CreatePublicId(public_id_4));
  EXPECT_EQ(kWrongLoggedInState, test_elements_1_.CheckPassword(password_1_));
  EXPECT_EQ(kWrongLoggedInState, test_elements_1_.ChangeKeyword(NonEmptyString(
      RandomAlphaNumericString(5)), password_1_));
  EXPECT_EQ(kWrongLoggedInState, test_elements_1_.ChangePin(CreatePin(), password_1_));
  EXPECT_EQ(kWrongLoggedInState, test_elements_1_.ChangePassword(
      NonEmptyString(RandomAlphaNumericString(5)), password_1_));
  EXPECT_EQ(kWrongLoggedInState, test_elements_1_.AddContact(
      public_id_1_, NonEmptyString(RandomAlphaNumericString(5)),
      NonEmptyString(RandomAlphaNumericString(5))));
  EXPECT_EQ(kWrongLoggedInState, test_elements_1_.ConfirmContact(public_id_1_, public_id_3));
  EXPECT_EQ(kWrongLoggedInState, test_elements_1_.DeclineContact(public_id_1_, public_id_3));
  EXPECT_EQ(kWrongLoggedInState, test_elements_1_.RemoveContact(
      public_id_1_, public_id_2_, message));
  // TODO(Alison) - check that other functions in API aren't accessible when drive not mounted.

  EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  EXPECT_EQ(test_elements_1_.logged_in_state(), kBaseState);
  EXPECT_EQ(test_elements_1_.state(), kConnected);
}

TEST_F(OneUserApiTest, FUNC_CreateDirectoryLogoutLoginCheckDirectory) {
  // Create directory
  std::string tail;
  fs::path test(CreateTestDirectory(test_elements_.mount_path(), &tail));
  EXPECT_TRUE(fs::exists(test, error_code_));
  EXPECT_EQ(0, error_code_.value());

  // Log out - Log in
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, pin_, password_));

  // Check directory exists
  fs::path new_path(test_elements_.mount_path() / tail);
  EXPECT_TRUE(fs::exists(new_path, error_code_));
  EXPECT_EQ(0, error_code_.value());
}

TEST_F(OneUserApiTest, FUNC_LargeFileForMemoryCheck) {
  // Create directory
  std::string tail;
  EXPECT_EQ(kSuccess, CreateTestFile(test_elements_.mount_path(), 500, &tail));
  EXPECT_TRUE(fs::exists(test_elements_.mount_path() / tail, error_code_));
  EXPECT_EQ(0, error_code_.value());

  // Log out - Log in
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, pin_, password_));

  // Check directory exists
  EXPECT_TRUE(fs::exists(test_elements_.mount_path() / tail, error_code_));
  EXPECT_EQ(0, error_code_.value());
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
