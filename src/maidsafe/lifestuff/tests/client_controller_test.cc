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

#include "boost/filesystem/fstream.hpp"
#include "boost/progress.hpp"

#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/test.h"

#include "maidsafe/lifestuff/authentication.h"
#include "maidsafe/lifestuff/client_utils.h"
#include "maidsafe/lifestuff/client_controller.h"
#include "maidsafe/lifestuff/local_store_manager.h"
#include "maidsafe/lifestuff/session.h"


namespace arg = std::placeholders;
namespace fs = boost::filesystem;


namespace maidsafe {

namespace lifestuff {

namespace test {

class ClientControllerTest : public testing::Test {
 public:
  ClientControllerTest()
      : test_dir_(maidsafe::test::CreateTestPath()),
        cc_(new ClientController()),
        ss_(cc_->ss_),
        local_sm_(new LocalStoreManager(*test_dir_, ss_)) {}

 protected:
  void SetUp() {
    ss_->ResetSession();
    local_sm_->Init(std::bind(&ClientControllerTest::InitAndCloseCallback,
                              this, arg::_1));
    cc_->auth_.reset(new Authentication(ss_));
    cc_->auth_->Init(local_sm_);
    cc_->local_sm_ = local_sm_;
    cc_->initialised_ = true;
  }
  void TearDown() {
    local_sm_->Close(true);
    ss_->passport_->StopCreatingKeyPairs();
    cc_->initialised_ = false;
  }

  void InitAndCloseCallback(int /*i*/) {}

  std::shared_ptr<ClientController> CreateSecondClientController() {
    std::shared_ptr<ClientController> cc2(new ClientController());
    std::shared_ptr<Session> ss2 = cc2->ss_;
    std::shared_ptr<LocalStoreManager>
        local_sm2(new LocalStoreManager(*test_dir_, ss2));
    ss2->ResetSession();
    local_sm2->Init(std::bind(&ClientControllerTest::InitAndCloseCallback,
                              this, arg::_1));
    cc2->auth_.reset(new Authentication(ss2));
    cc2->auth_->Init(local_sm2);
    cc2->local_sm_ = local_sm2;
    cc2->initialised_ = true;
    return cc2;
  }

  std::shared_ptr<fs::path> test_dir_;
  std::shared_ptr<ClientController> cc_;
  std::shared_ptr<Session> ss_;
  std::shared_ptr<LocalStoreManager> local_sm_;

 private:
  ClientControllerTest(const ClientControllerTest&);
  ClientControllerTest &operator=(const ClientControllerTest&);
};

TEST_F(ClientControllerTest, FUNC_LoginSequence) {
  std::string username("User1");
  std::string pin("1234");
  std::string password("The beagle has landed.");
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.";

  DLOG(INFO) << "\n";

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin));
  ASSERT_TRUE(cc_->CreateUser(username, pin, password));
  ASSERT_EQ(username, ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  DLOG(INFO) << "User created.";

  DLOG(INFO) << "\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  DLOG(INFO) << "Logged out.";

  DLOG(INFO) << "\n";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username, pin));

  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  DLOG(INFO) << "Logged in.";

  DLOG(INFO) << "\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  DLOG(INFO) << "Logged out.";

  DLOG(INFO) << "\n";

  ASSERT_NE(kUserExists, cc_->CheckUserExists("juan.smer", pin));
  DLOG(INFO) << "Can't log in with fake details.";
}

TEST_F(ClientControllerTest, FUNC_ChangeDetails) {
  std::string username("User2");
  std::string pin("2345");
  std::string password("The axolotl has landed.");
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin));
  DLOG(INFO) << "Preconditions fulfilled.";

  ASSERT_TRUE(cc_->CreateUser(username, pin, password));
  ASSERT_EQ(username, ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  DLOG(INFO) << "User created.";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  DLOG(INFO) << "Logged out.";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username, pin));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  DLOG(INFO) << "Logged in.";
  ASSERT_TRUE(cc_->ChangeUsername("juan.smer"));
  ASSERT_EQ("juan.smer", ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  DLOG(INFO) << "Changed username.";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  DLOG(INFO) << "Logged out.";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists("juan.smer", pin));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ("juan.smer", ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  DLOG(INFO) << "Logged in.";
  ASSERT_TRUE(cc_->ChangePin("2207"));
  ASSERT_EQ("juan.smer", ss_->username());
  ASSERT_EQ("2207", ss_->pin());
  ASSERT_EQ(password, ss_->password());
  DLOG(INFO) << "Changed pin.";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  DLOG(INFO) << "Logged out.";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists("juan.smer", "2207"));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ("juan.smer", ss_->username());
  ASSERT_EQ("2207", ss_->pin());
  ASSERT_EQ(password, ss_->password());
  DLOG(INFO) << "Logged in.";

  ASSERT_TRUE(cc_->ChangePassword("elpasguor"));
  ASSERT_EQ("juan.smer", ss_->username());
  ASSERT_EQ("2207", ss_->pin());
  ASSERT_EQ("elpasguor", ss_->password());
  DLOG(INFO) << "Changed password.";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  DLOG(INFO) << "Logged out.";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists("juan.smer", "2207"));
  std::string new_pwd("elpasguor");
  ASSERT_TRUE(cc_->ValidateUser(new_pwd));
  ASSERT_EQ("juan.smer", ss_->username());
  ASSERT_EQ("2207", ss_->pin());
  ASSERT_EQ(new_pwd, ss_->password());
  DLOG(INFO) << "Logged in. New u/p/w.";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  DLOG(INFO) << "Logged out.";

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin));
  ASSERT_NE(kUserExists, cc_->CheckUserExists("juan.smer", pin));
  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, "2207"));
  ASSERT_FALSE(cc_->ValidateUser(password))
               << "old details still work, damn it, damn the devil to hell";
  ss_->ResetSession();
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  DLOG(INFO) << "Can't log in with old u/p/w.";
}

TEST_F(ClientControllerTest, FUNC_LeaveNetwork) {
  std::string username("User4");
  std::string pin("4567");
  std::string password("The chubster has landed.");
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.";

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin));
  ASSERT_TRUE(cc_->CreateUser(username, pin, password));
  ASSERT_EQ(username, ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  DLOG(INFO) << "User created.\n=============\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  DLOG(INFO) << "Logged out.\n===========\n";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username, pin));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  DLOG(INFO) << "Logged in.\n==========\n";

  ASSERT_TRUE(cc_->LeaveMaidsafeNetwork());
  DLOG(INFO) << "Left maidsafe ='(.\n==================\n";

  ASSERT_EQ(kUserDoesntExist, cc_->CheckUserExists(username, pin));
  DLOG(INFO) << "User no longer exists.\n======================\n";

  ASSERT_TRUE(cc_->CreateUser(username, pin, password));
  ASSERT_EQ(username, ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  DLOG(INFO) << "User created again.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  DLOG(INFO) << "Logged out.\n===========\n";
}

TEST_F(ClientControllerTest, FUNC_ParallelLogin) {
  std::string username("User1");
  std::string pin("1234");
  std::string password("The beagle has landed.");
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.";

  DLOG(INFO) << "\n";

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin));
  ASSERT_TRUE(cc_->CreateUser(username, pin, password));
  ASSERT_EQ(username, ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  DLOG(INFO) << "User created.";

  DLOG(INFO) << "\n";

  std::shared_ptr<ClientController> cc2 = CreateSecondClientController();
  ASSERT_EQ(kUserExists, cc2->CheckUserExists(username, pin));
  ASSERT_TRUE(cc2->ValidateUser(password));
  DLOG(INFO) << "Successful Parallel Log in.";

  DLOG(INFO) << "\n";
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe