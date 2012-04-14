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

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/user_credentials.h"
#include "maidsafe/lifestuff/utils.h"

namespace args = std::placeholders;
namespace fs = boost::filesystem;


namespace maidsafe {

namespace lifestuff {

namespace test {

class UserCredentialsTest : public testing::Test {
 public:
  UserCredentialsTest()
      : test_dir_(maidsafe::test::CreateTestPath()),
        session_(new Session),
        session2_(),
        asio_service_(),
        asio_service2_(),
#ifndef LOCAL_TARGETS_ONLY
        client_container_(),
        client_container2_(),
#endif
        remote_chunk_store_(),
        remote_chunk_store2_(),
        user_credentials_(),
        user_credentials2_(),
        username_(RandomAlphaNumericString(8)),
        pin_("1234"),
        password_(RandomAlphaNumericString(8)) {}

 protected:
  void SetUp() {
    asio_service_.Start(10);
    asio_service2_.Start(10);
#ifdef LOCAL_TARGETS_ONLY
  remote_chunk_store_ = BuildChunkStore(*test_dir_, asio_service_.service());
#else
  remote_chunk_store_ = BuildChunkStore(*test_dir_, client_container_);
#endif
    user_credentials_.reset(new UserCredentials(remote_chunk_store_, session_));
    session_->Reset();
  }

  void TearDown() {
    asio_service_.Stop();
    asio_service2_.Stop();
  }

  void CreateSecondUserCredentials() {
#ifdef LOCAL_TARGETS_ONLY
    remote_chunk_store2_ = BuildChunkStore(*test_dir_,
                                           asio_service2_.service());
#else
    remote_chunk_store2_ = BuildChunkStore(*test_dir_, client_container2_);
#endif
    session2_.reset(new Session);
    user_credentials2_.reset(new UserCredentials(remote_chunk_store2_,
                                                 session2_));
    session2_->Reset();
  }

  std::shared_ptr<fs::path> test_dir_;
  std::shared_ptr<Session> session_, session2_;
  AsioService asio_service_, asio_service2_;
#ifndef LOCAL_TARGETS_ONLY
  std::shared_ptr<pd::ClientContainer> client_container_, client_container2_;
#endif
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store_,
                                         remote_chunk_store2_;
  std::shared_ptr<UserCredentials> user_credentials_, user_credentials2_;
  std::string username_, pin_, password_;

 private:
  UserCredentialsTest(const UserCredentialsTest&);
  UserCredentialsTest &operator=(const UserCredentialsTest&);
};

TEST_F(UserCredentialsTest, FUNC_DirectCreate) {
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_TRUE(user_credentials_->CreateUser(username_, pin_, password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "User created.\n===================\n";
}

TEST_F(UserCredentialsTest, FUNC_LoginSequence) {
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_NE(kUserExists, user_credentials_->CheckUserExists(username_, pin_));
  ASSERT_TRUE(user_credentials_->CreateUser(username_, pin_, password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "User created.\n===================\n";

  ASSERT_TRUE(user_credentials_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, user_credentials_->CheckUserExists(username_, pin_));
  ASSERT_TRUE(user_credentials_->ValidateUser(password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "Logged in.\n===================\n";

  ASSERT_TRUE(user_credentials_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_NE(kUserExists,
            user_credentials_->CheckUserExists(RandomAlphaNumericString(9),
                                              pin_));
  DLOG(INFO) << "Can't log in with fake details.";
}

TEST_F(UserCredentialsTest, FUNC_RepeatedValidateUser) {
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_NE(kUserExists, user_credentials_->CheckUserExists(username_, pin_));
  ASSERT_TRUE(user_credentials_->CreateUser(username_, pin_, password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "User created.\n===================\n";

  ASSERT_TRUE(user_credentials_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, user_credentials_->CheckUserExists(username_, pin_));

  DLOG(INFO) << "\n\n\n\n";
  ASSERT_FALSE(user_credentials_->ValidateUser(password_ + "aaaa"));
  DLOG(INFO) << "\n\n\n\n";
  ASSERT_TRUE(user_credentials_->ValidateUser(password_));
  DLOG(INFO) << "\n\n\n\n";
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "Logged in.\n===================\n";

  ASSERT_TRUE(user_credentials_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";
}

TEST_F(UserCredentialsTest, FUNC_ChangeDetails) {
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  ASSERT_NE(kUserExists, user_credentials_->CheckUserExists(username_, pin_));
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_TRUE(user_credentials_->CreateUser(username_, pin_, password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "User created.\n===================\n";

  ASSERT_TRUE(user_credentials_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, user_credentials_->CheckUserExists(username_, pin_));

  ASSERT_TRUE(user_credentials_->ValidateUser(password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());

  DLOG(INFO) << "Logged in.\n===================\n";
  const std::string kNewUser(RandomAlphaNumericString(9));
  ASSERT_TRUE(user_credentials_->ChangeUsername(kNewUser));
  ASSERT_EQ(kNewUser, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "Changed username.\n===================\n";

  ASSERT_TRUE(user_credentials_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, user_credentials_->CheckUserExists(kNewUser, pin_));
  ASSERT_TRUE(user_credentials_->ValidateUser(password_));
  ASSERT_EQ(kNewUser, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "Logged in.\n===================\n";

  const std::string kNewPin("2207");
  ASSERT_TRUE(user_credentials_->ChangePin(kNewPin));
  ASSERT_EQ(kNewUser, session_->username());
  ASSERT_EQ(kNewPin, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "Changed pin.\n===================\n";

  ASSERT_TRUE(user_credentials_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, user_credentials_->CheckUserExists(kNewUser, kNewPin));
  ASSERT_TRUE(user_credentials_->ValidateUser(password_));
  ASSERT_EQ(kNewUser, session_->username());
  ASSERT_EQ(kNewPin, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "Logged in.\n===================\n";

  const std::string kNewPassword(RandomAlphaNumericString(9));
  ASSERT_TRUE(user_credentials_->ChangePassword(kNewPassword));
  ASSERT_EQ(kNewUser, session_->username());
  ASSERT_EQ(kNewPin, session_->pin());
  ASSERT_EQ(kNewPassword, session_->password());
  DLOG(INFO) << "Changed password.\n===================\n";

  ASSERT_TRUE(user_credentials_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserExists, user_credentials_->CheckUserExists(kNewUser, kNewPin));
  std::string new_pwd(kNewPassword);
  ASSERT_TRUE(user_credentials_->ValidateUser(new_pwd));
  ASSERT_EQ(kNewUser, session_->username());
  ASSERT_EQ(kNewPin, session_->pin());
  ASSERT_EQ(new_pwd, session_->password());
  DLOG(INFO) << "Logged in. New u/p/w.\n===================\n";

  ASSERT_TRUE(user_credentials_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  ASSERT_NE(kUserExists, user_credentials_->CheckUserExists(username_, pin_));
  ASSERT_NE(kUserExists, user_credentials_->CheckUserExists(kNewUser, pin_));
  ASSERT_NE(kUserExists, user_credentials_->CheckUserExists(username_,
                                                            kNewPin));
  ASSERT_FALSE(user_credentials_->ValidateUser(password_))
               << "old details still work, damn it, damn the devil to hell";
  session_->Reset();
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Can't log in with old u/p/w.";
}

TEST_F(UserCredentialsTest, FUNC_ParallelLogin) {
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_NE(kUserExists, user_credentials_->CheckUserExists(username_, pin_));
  ASSERT_TRUE(user_credentials_->CreateUser(username_, pin_, password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "User created.\n===================\n";

  CreateSecondUserCredentials();
  ASSERT_EQ(kUserExists, user_credentials2_->CheckUserExists(username_, pin_));
  ASSERT_TRUE(user_credentials2_->ValidateUser(password_));
  DLOG(INFO) << "Successful parallel log in.";
}

TEST_F(UserCredentialsTest, FUNC_MultiUserCredentialsLoginandLogout) {
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Preconditions fulfilled.\n===================\n";

  ASSERT_NE(kUserExists, user_credentials_->CheckUserExists(username_, pin_));
  ASSERT_TRUE(user_credentials_->CreateUser(username_, pin_, password_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
  DLOG(INFO) << "User created.\n===================\n";

  ASSERT_TRUE(user_credentials_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";

  CreateSecondUserCredentials();
  ASSERT_EQ(kUserExists, user_credentials2_->CheckUserExists(username_, pin_));
  ASSERT_TRUE(user_credentials2_->ValidateUser(password_));
  DLOG(INFO) << "Successful parallel log in.";
  ASSERT_TRUE(user_credentials2_->Logout());
  ASSERT_TRUE(session_->username().empty());
  ASSERT_TRUE(session_->pin().empty());
  ASSERT_TRUE(session_->password().empty());
  DLOG(INFO) << "Logged out.\n===================\n";
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
