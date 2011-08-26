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

#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/self_encryption.h"

#include "maidsafe/lifestuff/client/authentication.h"
#include "maidsafe/lifestuff/client/clientutils.h"
#include "maidsafe/lifestuff/client/clientcontroller.h"
#include "maidsafe/lifestuff/client/localstoremanager.h"
#include "maidsafe/lifestuff/client/sessionsingleton.h"
#include "maidsafe/lifestuff/sharedtest/mockclientcontroller.h"


namespace arg = std::placeholders;
namespace fs = boost::filesystem;

namespace test_cc {

#ifdef MS_NETWORK_TEST
void Sleep(const int &millisecs) {
  Sleep(boost::posix_time::milliseconds(millisecs));
#else
void Sleep(const int&) {
#endif
}

}  // namespace test_cc

namespace maidsafe {

namespace lifestuff {

namespace test {

class ClientControllerTest : public testing::Test {
 public:
  ClientControllerTest()
      : test_dir_(maidsafe::test::CreateTestPath()),
        cc_(new ClientController()),
        ss_(SessionSingleton::getInstance()),
        local_sm_(new LocalStoreManager(*test_dir_)) {}

 protected:
  void SetUp() {
    ss_->ResetSession();
    local_sm_->Init(std::bind(&ClientControllerTest::InitAndCloseCallback,
                              this, arg::_1),
                    0);
    cc_->auth_.reset(new Authentication);
    cc_->auth_->Init(local_sm_);
    cc_->local_sm_ = local_sm_;
    cc_->ss_ = ss_;
    cc_->initialised_ = true;
  }
  void TearDown() {
    local_sm_->Close(std::bind(&ClientControllerTest::InitAndCloseCallback,
                               this, arg::_1),
               true);
    ss_->passport_->StopCreatingKeyPairs();
    cc_->initialised_ = false;
  }

  void InitAndCloseCallback(const ReturnCode&) {}

  std::shared_ptr<fs::path> test_dir_;
  std::shared_ptr<ClientController> cc_;
  SessionSingleton *ss_;
  std::shared_ptr<LocalStoreManager> local_sm_;

 private:
  ClientControllerTest(const ClientControllerTest&);
  ClientControllerTest &operator=(const ClientControllerTest&);
};

TEST_F(ClientControllerTest, FUNC_MAID_LoginSequence) {
  std::string username("User1");
  std::string pin("1234");
  std::string password("The beagle has landed.");
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  printf("Preconditions fulfilled.");

  printf("\n\n");

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin));
  ASSERT_TRUE(cc_->CreateUser(username, pin, password));
  ASSERT_EQ(username, ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  printf("User created.");

  printf("\n\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  printf("Logged out.");

  printf("\n\n");

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username, pin));

  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  printf("Logged in.");

  printf("\n\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  printf("Logged out.");

  printf("\n\n");

  ASSERT_NE(kUserExists, cc_->CheckUserExists("juan.smer", pin));
  printf("Can't log in with fake details.\n");
}

TEST_F(ClientControllerTest, FUNC_MAID_ChangeDetails) {
  std::string username("User2");
  std::string pin("2345");
  std::string password("The axolotl has landed.");
  ss_ = SessionSingleton::getInstance();
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin));
  printf("Preconditions fulfilled.\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password));
  ASSERT_EQ(username, ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  printf("User created.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  printf("Logged out.\n");

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username, pin));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  printf("Logged in.\n");
  ASSERT_TRUE(cc_->ChangeUsername("juan.smer"));
  ASSERT_EQ("juan.smer", ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  printf("Changed username.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  printf("Logged out.\n");

  ASSERT_EQ(kUserExists, cc_->CheckUserExists("juan.smer", pin));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ("juan.smer", ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  printf("Logged in.\n");
  ASSERT_TRUE(cc_->ChangePin("2207"));
  ASSERT_EQ("juan.smer", ss_->username());
  ASSERT_EQ("2207", ss_->pin());
  ASSERT_EQ(password, ss_->password());
  printf("Changed pin.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  printf("Logged out.\n");

  ASSERT_EQ(kUserExists, cc_->CheckUserExists("juan.smer", "2207"));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ("juan.smer", ss_->username());
  ASSERT_EQ("2207", ss_->pin());
  ASSERT_EQ(password, ss_->password());
  printf("Logged in.\n");

  ASSERT_TRUE(cc_->ChangePassword("elpasguor"));
  ASSERT_EQ("juan.smer", ss_->username());
  ASSERT_EQ("2207", ss_->pin());
  ASSERT_EQ("elpasguor", ss_->password());
  printf("Changed password.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  printf("Logged out.\n");

  ASSERT_EQ(kUserExists, cc_->CheckUserExists("juan.smer", "2207"));
  std::string new_pwd("elpasguor");
  ASSERT_TRUE(cc_->ValidateUser(new_pwd));
  ASSERT_EQ("juan.smer", ss_->username());
  ASSERT_EQ("2207", ss_->pin());
  ASSERT_EQ(new_pwd, ss_->password());
  printf("Logged in. New u/p/w.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  printf("Logged out.\n");

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin));
  ASSERT_NE(kUserExists, cc_->CheckUserExists("juan.smer", pin));
  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, "2207"));
  ASSERT_FALSE(cc_->ValidateUser(password))
               << "old details still work, damn it, damn the devil to hell";
  ss_->ResetSession();
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  printf("Can't log in with old u/p/w.\n");
}

TEST_F(ClientControllerTest, FUNC_MAID_LeaveNetwork) {
  std::string username("User4");
  std::string pin("4567");
  std::string password("The chubster has landed.");
  ss_ = SessionSingleton::getInstance();
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  printf("Preconditions fulfilled.\n");

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin));
  ASSERT_TRUE(cc_->CreateUser(username, pin, password));
  ASSERT_EQ(username, ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  test_cc::Sleep(30000);
  printf("User created.\n=============\n\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  test_cc::Sleep(60);
  printf("Logged out.\n===========\n\n");

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username, pin));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
//  ASSERT_EQ("el.mambo.tonnnnnto", ss_->PublicUsername());
  test_cc::Sleep(30000);
  printf("Logged in.\n==========\n\n");

  ASSERT_TRUE(cc_->LeaveMaidsafeNetwork());
  test_cc::Sleep(60);
  printf("Left maidsafe ='(.\n==================\n\n");

  ASSERT_EQ(kUserDoesntExist, cc_->CheckUserExists(username, pin));
  printf("User no longer exists.\n======================\n\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password));
  ASSERT_EQ(username, ss_->username());
  ASSERT_EQ(pin, ss_->pin());
  ASSERT_EQ(password, ss_->password());
  test_cc::Sleep(30000);
  printf("User created again.\n===================\n\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->username().empty());
  ASSERT_TRUE(ss_->pin().empty());
  ASSERT_TRUE(ss_->password().empty());
  printf("Logged out.\n===========\n\n");
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
