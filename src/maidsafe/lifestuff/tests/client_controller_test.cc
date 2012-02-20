/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Functional tests for Client Controller operations
* Version:      1.0
* Created:      2009-01-29-02.29.46
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

#include <list>
#include <string>
#include <vector>

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/client_controller.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/session.h"

namespace args = std::placeholders;
namespace fs = boost::filesystem;


namespace maidsafe {

namespace lifestuff {

namespace test {

class ClientControllerTest : public testing::TestWithParam<std::string> {
 public:
  ClientControllerTest()
      : test_dir_(maidsafe::test::CreateTestPath()),
        session_(new Session),
        asio_service_(),
        asio_service2_(),
        cc_(),
        username_(RandomAlphaNumericString(8)),
        pin_("1234"),
        password_(RandomAlphaNumericString(8)) {}

 protected:
  void SetUp() {
    asio_service_.Start(10);
    asio_service2_.Start(10);
    cc_.reset(new ClientController(asio_service_.service(), session_));
    session_->ResetSession();
    bool local(GetParam() == "Local Storage");
    if (!local && GetParam() != "Network Storage")
      FAIL() << "Invalid test value parameter";

    cc_->Init(local, *test_dir_);
  }

  void TearDown() {
    asio_service_.Stop();
    asio_service2_.Stop();
    cc_->initialised_ = false;
  }

  std::shared_ptr<ClientController> CreateSecondClientController() {
    std::shared_ptr<Session> ss2(new Session);
    std::shared_ptr<ClientController> cc2(
        new ClientController(asio_service2_.service(), ss2));
    ss2->ResetSession();
    bool local(GetParam() == "Local Storage");
    cc2->Init(local, *test_dir_);
    return cc2;
  }

  std::shared_ptr<fs::path> test_dir_;
  std::shared_ptr<Session> session_;
  AsioService asio_service_, asio_service2_;
  std::shared_ptr<ClientController> cc_;
  std::string username_, pin_, password_;

 private:
  ClientControllerTest(const ClientControllerTest&);
  ClientControllerTest &operator=(const ClientControllerTest&);
};

TEST_P(ClientControllerTest, FUNC_DirectCreate) {
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_TRUE(cc_->CreateUser(username_, pin_, password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "User created.\n===================\n";
}

TEST_P(ClientControllerTest, FUNC_LoginSequence) {
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username_, pin_));
  ASSERT_TRUE(cc_->CreateUser(username_, pin_, password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "User created.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username_, pin_));
  ASSERT_TRUE(cc_->ValidateUser(password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "Logged in.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_NE(kUserExists, cc_->CheckUserExists(RandomAlphaNumericString(9),
                                              pin_));
  DLOG(INFO) << "Can't log in with fake details.";
}

TEST_P(ClientControllerTest, FUNC_RepeatedValidateUser) {
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username_, pin_));
  ASSERT_TRUE(cc_->CreateUser(username_, pin_, password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "User created.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username_, pin_));

  DLOG(INFO) << "\n\n\n\n";
  ASSERT_FALSE(cc_->ValidateUser(password_ + "aaaa"));
  DLOG(INFO) << "\n\n\n\n";
  ASSERT_TRUE(cc_->ValidateUser(password_));
  DLOG(INFO) << "\n\n\n\n";
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "Logged in.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";
}

TEST_P(ClientControllerTest, FUNC_ChangeDetails) {
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  ASSERT_NE(kUserExists, cc_->CheckUserExists(username_, pin_));
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_TRUE(cc_->CreateUser(username_, pin_, password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "User created.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username_, pin_));

  ASSERT_TRUE(cc_->ValidateUser(password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());

  DLOG(INFO) << "Logged in.\n===================\n";
  const std::string kNewUser(RandomAlphaNumericString(9));
  ASSERT_TRUE(cc_->ChangeUsername(kNewUser));
  ASSERT_EQ(kNewUser, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "Changed username.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(kNewUser, pin_));
  ASSERT_TRUE(cc_->ValidateUser(password_));
  ASSERT_EQ(kNewUser, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "Logged in.\n===================\n";

  const std::string kNewPin("2207");
  ASSERT_TRUE(cc_->ChangePin(kNewPin));
  ASSERT_EQ(kNewUser, session_->username());
  ASSERT_EQ(kNewPin, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "Changed pin.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(kNewUser, kNewPin));
  ASSERT_TRUE(cc_->ValidateUser(password_));
  ASSERT_EQ(kNewUser, session_->username());
  ASSERT_EQ(kNewPin, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "Logged in.\n===================\n";

  const std::string kNewPassword(RandomAlphaNumericString(9));
  ASSERT_TRUE(cc_->ChangePassword(kNewPassword));
  ASSERT_EQ(kNewUser, session_->username());
  ASSERT_EQ(kNewPin, session_->pin());
  ASSERT_EQ(kNewPassword, session_->password());
  DLOG(INFO) << "Changed password.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(kNewUser, kNewPin));
  std::string new_pwd(kNewPassword);
  ASSERT_TRUE(cc_->ValidateUser(new_pwd));
  ASSERT_EQ(kNewUser, session_->username());
  ASSERT_EQ(kNewPin, session_->pin());
  ASSERT_EQ(new_pwd, session_->password());
  DLOG(INFO) << "Logged in. New u/p/w.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username_, pin_));
  ASSERT_NE(kUserExists, cc_->CheckUserExists(kNewUser, pin_));
  ASSERT_NE(kUserExists, cc_->CheckUserExists(username_, kNewPin));
  ASSERT_FALSE(cc_->ValidateUser(password_))
               << "old details still work, damn it, damn the devil to hell";
  session_->ResetSession();
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Can't log in with old u/p/w.";
}

TEST_P(ClientControllerTest, FUNC_LeaveNetwork) {
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username_, pin_));
  ASSERT_TRUE(cc_->CreateUser(username_, pin_, password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "User created.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username_, pin_));
  ASSERT_TRUE(cc_->ValidateUser(password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "Logged in.\n===================\n";

  ASSERT_TRUE(cc_->LeaveMaidsafeNetwork());
  DLOG(INFO) << "Left maidsafe ='(.\n===================\n";

  ASSERT_EQ(kUserDoesntExist, cc_->CheckUserExists(username_, pin_));
  DLOG(INFO) << "User no longer exists.\n===================\n";

  ASSERT_TRUE(cc_->CreateUser(username_, pin_, password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "User created again.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.";
}

TEST_P(ClientControllerTest, FUNC_ParallelLogin) {
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username_, pin_));
  ASSERT_TRUE(cc_->CreateUser(username_, pin_, password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "User created.\n===================\n";

  std::shared_ptr<ClientController> cc2 = CreateSecondClientController();
  ASSERT_EQ(kUserExists, cc2->CheckUserExists(username_, pin_));
  ASSERT_TRUE(cc2->ValidateUser(password_));
  DLOG(INFO) << "Successful parallel log in.";
}

TEST_P(ClientControllerTest, FUNC_MultiClientControllerLoginandLogout) {
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username_, pin_));
  ASSERT_TRUE(cc_->CreateUser(username_, pin_, password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "User created.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  std::shared_ptr<ClientController> cc2 = CreateSecondClientController();
  ASSERT_EQ(kUserExists, cc2->CheckUserExists(username_, pin_));
  ASSERT_TRUE(cc2->ValidateUser(password_));
  DLOG(INFO) << "Successful parallel log in.";
  ASSERT_TRUE(cc2->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";
}

INSTANTIATE_TEST_CASE_P(LocalAndNetwork, ClientControllerTest,
                        testing::Values("Local Storage", "Network Storage"));

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
