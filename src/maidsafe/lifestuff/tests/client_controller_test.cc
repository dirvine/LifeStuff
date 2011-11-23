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
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/authentication.h"
#include "maidsafe/lifestuff/client_controller.h"
#include "maidsafe/lifestuff/session.h"
#if defined AMAZON_WEB_SERVICE_STORE
#  include "maidsafe/lifestuff/store_components/aws_store_manager.h"
#else
#  include "maidsafe/lifestuff/store_components/local_store_manager.h"
#endif


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
        session_(cc_->session_),
#if defined AMAZON_WEB_SERVICE_STORE
        packet_manager_(new AWSStoreManager(session_, *test_dir_)) {}
#else
        packet_manager_(new LocalStoreManager(session_, test_dir_->string())) {}
#endif

 protected:
  void SetUp() {
    session_->ResetSession();
    packet_manager_->Init(std::bind(&ClientControllerTest::InitAndCloseCallback,
                                    this, arg::_1));
    cc_->auth_.reset(new Authentication(session_));
    cc_->auth_->Init(packet_manager_);
    cc_->packet_manager_ = packet_manager_;
    cc_->initialised_ = true;
  }
  void TearDown() {
    packet_manager_->Close(true);
    cc_->initialised_ = false;
  }

  void InitAndCloseCallback(int /*i*/) {}

  std::shared_ptr<ClientController> CreateSecondClientController() {
    std::shared_ptr<ClientController> cc2(new ClientController());
    std::shared_ptr<Session> ss2 = cc2->session_;
#if defined AMAZON_WEB_SERVICE_STORE
    std::shared_ptr<PacketManager>
        packet_manager2(new AWSStoreManager(ss2, *test_dir_));
#else
    std::shared_ptr<PacketManager>
        packet_manager2(new LocalStoreManager(ss2, test_dir_->string()));
#endif
    ss2->ResetSession();
    packet_manager2->Init(std::bind(&ClientControllerTest::InitAndCloseCallback,
                                    this, arg::_1));
    cc2->auth_.reset(new Authentication(ss2));
    cc2->auth_->Init(packet_manager2);
    cc2->packet_manager_ = packet_manager2;
    cc2->initialised_ = true;
    return cc2;
  }

  std::shared_ptr<fs::path> test_dir_;
  std::shared_ptr<ClientController> cc_;
  std::shared_ptr<Session> session_;
  std::shared_ptr<PacketManager> packet_manager_;

 private:
  ClientControllerTest(const ClientControllerTest&);
  ClientControllerTest &operator=(const ClientControllerTest&);
};

TEST_F(ClientControllerTest, FUNC_LoginSequence) {
  std::string username("User1");
  std::string pin("1234");
  std::string password("The beagle has landed.");
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin));
  ASSERT_TRUE(cc_->CreateUser(username, pin, password));
  ASSERT_EQ(username, session_->username());
  ASSERT_EQ(pin, session_->pin());
  ASSERT_EQ(password, session_->password());
  DLOG(INFO) << "User created.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username, pin));

  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, session_->username());
  ASSERT_EQ(pin, session_->pin());
  ASSERT_EQ(password, session_->password());
  DLOG(INFO) << "Logged in.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_NE(kUserExists, cc_->CheckUserExists("juan.smer", pin));
  DLOG(INFO) << "Can't log in with fake details.";
}

TEST_F(ClientControllerTest, FUNC_ChangeDetails) {
  std::string username("User2");
  std::string pin("2345");
  std::string password("The axolotl has landed.");
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin));
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_TRUE(cc_->CreateUser(username, pin, password));
  ASSERT_EQ(username, session_->username());
  ASSERT_EQ(pin, session_->pin());
  ASSERT_EQ(password, session_->password());
  DLOG(INFO) << "User created.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username, pin));

  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, session_->username());
  ASSERT_EQ(pin, session_->pin());
  ASSERT_EQ(password, session_->password());

  DLOG(INFO) << "Logged in.\n===================\n";
  ASSERT_TRUE(cc_->ChangeUsername("juan.smer"));
  ASSERT_EQ("juan.smer", session_->username());
  ASSERT_EQ(pin, session_->pin());
  ASSERT_EQ(password, session_->password());
  DLOG(INFO) << "Changed username.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists("juan.smer", pin));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ("juan.smer", session_->username());
  ASSERT_EQ(pin, session_->pin());
  ASSERT_EQ(password, session_->password());
  DLOG(INFO) << "Logged in.\n===================\n";

  ASSERT_TRUE(cc_->ChangePin("2207"));
  ASSERT_EQ("juan.smer", session_->username());
  ASSERT_EQ("2207", session_->pin());
  ASSERT_EQ(password, session_->password());
  DLOG(INFO) << "Changed pin.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists("juan.smer", "2207"));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ("juan.smer", session_->username());
  ASSERT_EQ("2207", session_->pin());
  ASSERT_EQ(password, session_->password());
  DLOG(INFO) << "Logged in.\n===================\n";

  ASSERT_TRUE(cc_->ChangePassword("elpasguor"));
  ASSERT_EQ("juan.smer", session_->username());
  ASSERT_EQ("2207", session_->pin());
  ASSERT_EQ("elpasguor", session_->password());
  DLOG(INFO) << "Changed password.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists("juan.smer", "2207"));
  std::string new_pwd("elpasguor");
  ASSERT_TRUE(cc_->ValidateUser(new_pwd));
  ASSERT_EQ("juan.smer", session_->username());
  ASSERT_EQ("2207", session_->pin());
  ASSERT_EQ(new_pwd, session_->password());
  DLOG(INFO) << "Logged in. New u/p/w.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin));
  ASSERT_NE(kUserExists, cc_->CheckUserExists("juan.smer", pin));
  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, "2207"));
  ASSERT_FALSE(cc_->ValidateUser(password))
               << "old details still work, damn it, damn the devil to hell";
  session_->ResetSession();
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Can't log in with old u/p/w.";
}

TEST_F(ClientControllerTest, FUNC_LeaveNetwork) {
  std::string username("User4");
  std::string pin("4567");
  std::string password("The chubster has landed.");
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin));
  ASSERT_TRUE(cc_->CreateUser(username, pin, password));
  ASSERT_EQ(username, session_->username());
  ASSERT_EQ(pin, session_->pin());
  ASSERT_EQ(password, session_->password());
  DLOG(INFO) << "User created.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username, pin));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, session_->username());
  ASSERT_EQ(pin, session_->pin());
  ASSERT_EQ(password, session_->password());
  DLOG(INFO) << "Logged in.\n===================\n";

  ASSERT_TRUE(cc_->LeaveMaidsafeNetwork());
  DLOG(INFO) << "Left maidsafe ='(.\n===================\n";

  ASSERT_EQ(kUserDoesntExist, cc_->CheckUserExists(username, pin));
  DLOG(INFO) << "User no longer exists.\n===================\n";

  ASSERT_TRUE(cc_->CreateUser(username, pin, password));
  ASSERT_EQ(username, session_->username());
  ASSERT_EQ(pin, session_->pin());
  ASSERT_EQ(password, session_->password());
  DLOG(INFO) << "User created again.\n===================\n";

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.";
}

TEST_F(ClientControllerTest, FUNC_ParallelLogin) {
  std::string username("User1");
  std::string pin("1234");
  std::string password("The beagle has landed.");
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin));
  ASSERT_TRUE(cc_->CreateUser(username, pin, password));
  ASSERT_EQ(username, session_->username());
  ASSERT_EQ(pin, session_->pin());
  ASSERT_EQ(password, session_->password());
  DLOG(INFO) << "User created.\n===================\n";

  std::shared_ptr<ClientController> cc2 = CreateSecondClientController();
  ASSERT_EQ(kUserExists, cc2->CheckUserExists(username, pin));
  ASSERT_TRUE(cc2->ValidateUser(password));
  DLOG(INFO) << "Successful parallel log in.";
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
