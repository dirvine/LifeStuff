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
#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_store/remote_chunk_store.h"
#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk.pb.h"
#include "maidsafe/private/chunk_actions/chunk_id.h"

#include "maidsafe/lifestuff/detail/routings_handler.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/user_credentials.h"
#include "maidsafe/lifestuff/detail/utils.h"


namespace pca = maidsafe::priv::chunk_actions;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

namespace test {

class CredentialsTest : public testing::Test {
 public:
  CredentialsTest()
      : test_dir_(maidsafe::test::CreateTestPath()),
        session_(),
        session2_(),
        asio_service_(10),
        asio_service2_(10),
        remote_chunk_store_(),
        remote_chunk_store2_(),
        routings_handler_(),
        routings_handler2_(),
        user_credentials_(),
        user_credentials2_(),
        keyword_(RandomAlphaNumericString(8)),
        pin_(CreatePin()),
        password_(RandomAlphaNumericString(8)),
        immediate_quit_required_(false) {}

  void ImmediateQuitRequiredSlot() { immediate_quit_required_ = true; }

 protected:
  void SetUp() {
    asio_service_.Start();
    asio_service2_.Start();

    std::string dir1(RandomAlphaNumericString(8));
    remote_chunk_store_ = priv::chunk_store::CreateLocalChunkStore(*test_dir_ / dir1 / "buffer",
                                                                   *test_dir_ / "simulation",
                                                                   *test_dir_ / dir1 / "lock",
                                                                   asio_service_.service());

    user_credentials_ = std::make_shared<UserCredentials>(*remote_chunk_store_,
                                                          session_,
                                                          asio_service_.service(),
                                                          *routings_handler_,
                                                          true);
  }

  void TearDown() {
    asio_service_.Stop();
    asio_service2_.Stop();
  }

  void SetUpSecondUserCredentials() {
    std::string dir2(RandomAlphaNumericString(8));
    remote_chunk_store2_ = priv::chunk_store::CreateLocalChunkStore(*test_dir_ / dir2 / "buffer",
                                                                    *test_dir_ / "simulation",
                                                                    *test_dir_ / dir2 / "lock",
                                                                    asio_service2_.service());
    user_credentials2_ = std::make_shared<UserCredentials>(*remote_chunk_store2_,
                                                           session2_,
                                                           asio_service2_.service(),
                                                           *routings_handler2_,
                                                           true);
  }

  void DoPreChecks(const NonEmptyString& keyword,
                   const NonEmptyString& pin,
                   const NonEmptyString& password,
                   std::shared_ptr<UserCredentials>& user_credentials,
                   Session& session) {
    ASSERT_THROW(session.keyword().string(), std::exception);
    ASSERT_THROW(session.pin().string(), std::exception);
    ASSERT_THROW(session.password().string(), std::exception);
    ASSERT_EQ(kLoginUserNonExistence, user_credentials->LogIn(keyword, pin, password));
    LOG(kSuccess) << "Preconditions fulfilled.\n===================\n";
  }

  void DoCredentialsCheck(const NonEmptyString& keyword,
                          const NonEmptyString& pin,
                          const NonEmptyString& password,
                          Session& session) {
    ASSERT_EQ(keyword, session.keyword());
    ASSERT_EQ(pin, session.pin());
    ASSERT_EQ(password, session.password());
  }

  void DoCreateUser(const NonEmptyString& keyword,
                    const NonEmptyString& pin,
                    const NonEmptyString& password,
                    std::shared_ptr<UserCredentials>& user_credentials,
                    Session& session) {
    ASSERT_EQ(kSuccess, user_credentials->CreateUser(keyword, pin, password));
    LOG(kSuccess) << "User credentials created.\n===================\n";

    ASSERT_EQ(keyword, session.keyword());
    ASSERT_EQ(pin, session.pin());
    ASSERT_EQ(password, session.password());
    LOG(kSuccess) << "User created.\n===================\n";
  }

  void DoLogOut(std::shared_ptr<UserCredentials>& user_credentials, Session& session) {
    EXPECT_EQ(kSuccess, user_credentials->Logout());
    session.Reset();
    LOG(kInfo) << "Credentials logged out.\n===================\n";
  }

  void DoLogIn(const NonEmptyString& keyword,
               const NonEmptyString& pin,
               const NonEmptyString& password,
               std::shared_ptr<UserCredentials>& user_credentials) {
    ASSERT_EQ(kSuccess, user_credentials->LogIn(keyword, pin, password));
    LOG(kInfo) << "Credentials logged in.\n===================\n";
  }

  std::shared_ptr<fs::path> test_dir_;
  Session session_, session2_;
  AsioService asio_service_, asio_service2_;
  std::shared_ptr<priv::chunk_store::RemoteChunkStore> remote_chunk_store_, remote_chunk_store2_;
  std::shared_ptr<RoutingsHandler> routings_handler_, routings_handler2_;
  std::shared_ptr<UserCredentials> user_credentials_, user_credentials2_;
  NonEmptyString keyword_, pin_, password_;
  bool immediate_quit_required_;

 private:
  CredentialsTest(const CredentialsTest&);
  CredentialsTest &operator=(const CredentialsTest&);
};

TEST_F(CredentialsTest, FUNC_DoCreateUserDoLogOut) {
  DoPreChecks(keyword_, pin_, password_, user_credentials_, session_);
  DoCreateUser(keyword_, pin_, password_, user_credentials_, session_);
  DoLogOut(user_credentials_, session_);
}

TEST_F(CredentialsTest, FUNC_LoginSequence) {
  DoPreChecks(keyword_, pin_, password_, user_credentials_, session_);
  DoCreateUser(keyword_, pin_, password_, user_credentials_, session_);
  DoLogOut(user_credentials_, session_);
  DoLogIn(keyword_, pin_, password_, user_credentials_);
  DoLogOut(user_credentials_, session_);
}

TEST_F(CredentialsTest, FUNC_ChangeDetails) {
  DoPreChecks(keyword_, pin_, password_, user_credentials_, session_);
  DoCreateUser(keyword_, pin_, password_, user_credentials_, session_);
  DoLogOut(user_credentials_, session_);
  DoLogIn(keyword_, pin_, password_, user_credentials_);

  LOG(kInfo) << "Logged in.\n===================\n";
  const NonEmptyString kNewKeyword(RandomAlphaNumericString(9));
  ASSERT_EQ(kSuccess, user_credentials_->ChangeKeyword(kNewKeyword));
  DoCredentialsCheck(kNewKeyword, pin_, password_, session_);
  LOG(kInfo) << "Changed keyword.\n===================\n";

  DoLogOut(user_credentials_, session_);
  DoLogIn(kNewKeyword, pin_, password_, user_credentials_);

  const NonEmptyString kNewPin(CreatePin());
  ASSERT_EQ(kSuccess, user_credentials_->ChangePin(kNewPin));
  DoCredentialsCheck(kNewKeyword, kNewPin, password_, session_);
  LOG(kInfo) << "Changed pin.\n===================\n";

  DoLogOut(user_credentials_, session_);
  DoLogIn(kNewKeyword, kNewPin, password_, user_credentials_);

  const NonEmptyString kNewPassword(RandomAlphaNumericString(9));
  ASSERT_EQ(kSuccess, user_credentials_->ChangePassword(kNewPassword));
  DoCredentialsCheck(kNewKeyword, kNewPin, kNewPassword, session_);
  LOG(kInfo) << "Changed password.\n===================\n";

  DoLogOut(user_credentials_, session_);
  DoLogIn(kNewKeyword, kNewPin, kNewPassword, user_credentials_);
  DoLogOut(user_credentials_, session_);

  ASSERT_EQ(kLoginUserNonExistence, user_credentials_->LogIn(keyword_, pin_, password_));
  ASSERT_EQ(kLoginUserNonExistence, user_credentials_->LogIn(kNewKeyword, pin_, password_));
  ASSERT_EQ(kLoginAccountCorrupted, user_credentials_->LogIn(kNewKeyword, kNewPin, password_));
  ASSERT_EQ(kLoginUserNonExistence, user_credentials_->LogIn(kNewKeyword, pin_, kNewPassword));
  ASSERT_EQ(kLoginUserNonExistence, user_credentials_->LogIn(keyword_, kNewPin, kNewPassword));
  LOG(kInfo) << "Can't log in with old u/p/w.";
}

TEST_F(CredentialsTest, DISABLED_FUNC_ParallelLogin) {
  DoPreChecks(keyword_, pin_, password_, user_credentials_, session_);
  ASSERT_EQ(kLoginUserNonExistence, user_credentials_->LogIn(keyword_, pin_, password_));

  ASSERT_EQ(kSuccess, user_credentials_->CreateUser(keyword_, pin_, password_));
  DoCredentialsCheck(keyword_, pin_, password_, session_);
  ASSERT_EQ(kFullAccess, session_.session_access_level());
  ASSERT_EQ(kSuccess, user_credentials_->Logout());

  ASSERT_EQ(kSuccess, user_credentials_->LogIn(keyword_, pin_, password_));

  SetUpSecondUserCredentials();
  immediate_quit_required_ = false;

  int result(kGeneralError);
  boost::thread login_thread([&] () {
                               result = user_credentials2_->LogIn(keyword_, pin_, password_);
                             });

  boost::thread wait_thread([&] () {
                              int i(0);
                              while (!immediate_quit_required_ && i < 15) {
                                ++i;
                                Sleep(bptime::seconds(1));
                              };
                            });

  login_thread.join();
  wait_thread.join();

  EXPECT_EQ(result, kSuccess);

  ASSERT_EQ(keyword_, session2_.keyword());
  ASSERT_EQ(pin_, session2_.pin());
  ASSERT_EQ(password_, session2_.password());
  ASSERT_EQ(kFullAccess, session2_.session_access_level());

  EXPECT_FALSE(session_.changed());
  EXPECT_EQ(session_.session_access_level(), kMustDie);
  EXPECT_EQ(kSuccess, user_credentials_->Logout());

  EXPECT_THROW(session_.keyword().string(), std::exception);
  EXPECT_THROW(session_.pin().string(), std::exception);
  EXPECT_THROW(session_.password().string(), std::exception);
  EXPECT_EQ(session_.session_access_level(), kNoAccess);

  ASSERT_EQ(kSuccess, user_credentials2_->Logout());

  EXPECT_THROW(session2_.keyword().string(), std::exception);
  EXPECT_THROW(session2_.pin().string(), std::exception);
  EXPECT_THROW(session2_.password().string(), std::exception);
  EXPECT_EQ(session2_.session_access_level(), kNoAccess);
}

TEST_F(CredentialsTest, FUNC_MultiUserCredentialsLoginAndLogout) {
  DoPreChecks(keyword_, pin_, password_, user_credentials_, session_);
  DoCreateUser(keyword_, pin_, password_, user_credentials_, session_);
  DoLogOut(user_credentials_, session_);
  SetUpSecondUserCredentials();
  DoLogIn(keyword_, pin_, password_, user_credentials2_);
  DoLogOut(user_credentials2_, session2_);
}

TEST_F(CredentialsTest, FUNC_UserCredentialsDeletion) {
  DoPreChecks(keyword_, pin_, password_, user_credentials_, session_);
  DoCreateUser(keyword_, pin_, password_, user_credentials_, session_);
  passport::Passport& pass(session_.passport());
  priv::ChunkId anmid_name(
      SignaturePacketName(pass.SignaturePacketDetails(passport::kAnmid, true).identity));
  priv::ChunkId ansmid_name(
      SignaturePacketName(pass.SignaturePacketDetails(passport::kAnsmid, true).identity));
  priv::ChunkId antmid_name(
      SignaturePacketName(pass.SignaturePacketDetails(passport::kAntmid, true).identity));
  priv::ChunkId anmaid_name(
      SignaturePacketName(pass.SignaturePacketDetails(passport::kAnmaid, true).identity));
  priv::ChunkId maid_name(
      SignaturePacketName(pass.SignaturePacketDetails(passport::kMaid, true).identity));
  priv::ChunkId pmid_name(
      SignaturePacketName(pass.SignaturePacketDetails(passport::kPmid, true).identity));
  priv::ChunkId mid_name(ModifiableName(pass.IdentityPacketName(passport::kMid, true)));
  priv::ChunkId smid_name(ModifiableName(pass.IdentityPacketName(passport::kSmid, true)));
  priv::ChunkId tmid_name(ModifiableName(pass.IdentityPacketName(passport::kTmid, true)));
  priv::ChunkId stmid_name(ModifiableName(pass.IdentityPacketName(passport::kStmid, true)));

  ASSERT_NE("", remote_chunk_store_->Get(anmid_name, Fob()));
  ASSERT_NE("", remote_chunk_store_->Get(ansmid_name, Fob()));
  ASSERT_NE("", remote_chunk_store_->Get(antmid_name, Fob()));
  ASSERT_NE("", remote_chunk_store_->Get(anmaid_name, Fob()));
  ASSERT_NE("", remote_chunk_store_->Get(maid_name, Fob()));
  ASSERT_NE("", remote_chunk_store_->Get(pmid_name, Fob()));
  ASSERT_NE("", remote_chunk_store_->Get(mid_name, Fob()));
  ASSERT_NE("", remote_chunk_store_->Get(smid_name, Fob()));
  ASSERT_NE("", remote_chunk_store_->Get(tmid_name, Fob()));
  ASSERT_NE("", remote_chunk_store_->Get(stmid_name, Fob()));

  ASSERT_EQ(kSuccess, user_credentials_->DeleteUserCredentials());
  LOG(kInfo) << "Deleted user credentials.\n=================\n";

  ASSERT_EQ("", remote_chunk_store_->Get(anmid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store_->Get(ansmid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store_->Get(antmid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store_->Get(anmaid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store_->Get(maid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store_->Get(pmid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store_->Get(mid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store_->Get(smid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store_->Get(tmid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store_->Get(stmid_name, Fob()));

  ASSERT_NE(kSuccess, user_credentials_->Logout());

  LOG(kInfo) << "Recreating deleted account...\n===================\n";
  SetUpSecondUserCredentials();
  DoCreateUser(keyword_, pin_, password_, user_credentials2_, session2_);
  DoLogOut(user_credentials2_, session2_);
  DoLogIn(keyword_, pin_, password_, user_credentials2_);
  passport::Passport& pass2(session2_.passport());

  anmid_name = SignaturePacketName(pass2.SignaturePacketDetails(passport::kAnmid, true).identity);
  ansmid_name = SignaturePacketName(pass2.SignaturePacketDetails(passport::kAnsmid, true).identity);
  antmid_name = SignaturePacketName(pass2.SignaturePacketDetails(passport::kAntmid, true).identity);
  anmaid_name = SignaturePacketName(pass2.SignaturePacketDetails(passport::kAnmaid, true).identity);
  maid_name = SignaturePacketName(pass2.SignaturePacketDetails(passport::kMaid, true).identity);
  pmid_name = SignaturePacketName(pass2.SignaturePacketDetails(passport::kPmid, true).identity);
  mid_name = ModifiableName(pass2.IdentityPacketName(passport::kMid, true));
  smid_name = ModifiableName(pass2.IdentityPacketName(passport::kSmid, true));
  tmid_name = ModifiableName(pass2.IdentityPacketName(passport::kTmid, true));
  stmid_name = ModifiableName(pass2.IdentityPacketName(passport::kStmid, true));

  ASSERT_NE("", remote_chunk_store2_->Get(anmid_name, Fob()));
  ASSERT_NE("", remote_chunk_store2_->Get(ansmid_name, Fob()));
  ASSERT_NE("", remote_chunk_store2_->Get(antmid_name, Fob()));
  ASSERT_NE("", remote_chunk_store2_->Get(anmaid_name, Fob()));
  ASSERT_NE("", remote_chunk_store2_->Get(maid_name, Fob()));
  ASSERT_NE("", remote_chunk_store2_->Get(pmid_name, Fob()));
  ASSERT_NE("", remote_chunk_store2_->Get(mid_name, Fob()));
  ASSERT_NE("", remote_chunk_store2_->Get(smid_name, Fob()));
  ASSERT_NE("", remote_chunk_store2_->Get(tmid_name, Fob()));
  ASSERT_NE("", remote_chunk_store2_->Get(stmid_name, Fob()));

  ASSERT_EQ(kSuccess, user_credentials2_->DeleteUserCredentials());

  ASSERT_EQ("", remote_chunk_store2_->Get(anmid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store2_->Get(ansmid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store2_->Get(antmid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store2_->Get(anmaid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store2_->Get(maid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store2_->Get(pmid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store2_->Get(mid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store2_->Get(smid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store2_->Get(tmid_name, Fob()));
  ASSERT_EQ("", remote_chunk_store2_->Get(stmid_name, Fob()));

  ASSERT_NE(kSuccess, user_credentials2_->Logout());
  ASSERT_NE(kSuccess, user_credentials2_->LogIn(keyword_, pin_, password_));
}

TEST_F(CredentialsTest, DISABLED_FUNC_SessionSaverTimer) {
  ASSERT_THROW(session_.keyword().string(), std::exception);
  ASSERT_THROW(session_.pin().string(), std::exception);
  ASSERT_THROW(session_.password().string(), std::exception);
  LOG(kInfo) << "Preconditions fulfilled.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->CreateUser(keyword_, pin_, password_));
  LOG(kInfo) << "Created user.\n===================\n";
  Sleep(bptime::seconds(3));
  LOG(kInfo) << "Slept 3.\n===================\n";
  NonEmptyString public_id(RandomAlphaNumericString(5));
  Identity info(RandomString(64));
  ASSERT_EQ(kSuccess, session_.AddPublicId(public_id, info));
  LOG(kInfo) << "Modified session.\n===================\n";
  Sleep(bptime::seconds(/*kSecondsInterval * 12*/5));
  LOG(kInfo) << "Slept 3.\n===================\n";
  ASSERT_EQ(kSuccess, user_credentials_->Logout());
  LOG(kInfo) << "Logout.\n===================\n";
  Sleep(bptime::seconds(5));
  LOG(kInfo) << "Slept 5.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->LogIn(keyword_, pin_, password_));
  LOG(kInfo) << "Log in.\n===================\n";
  Sleep(bptime::seconds(3));
  LOG(kInfo) << "Slept 3.\n===================\n";
  public_id = NonEmptyString(RandomAlphaNumericString(5));
  info = Identity(RandomString(64));
  ASSERT_EQ(kSuccess, session_.AddPublicId(public_id, info));
  LOG(kInfo) << "Modified session.\n===================\n";
  Sleep(bptime::seconds(/*kSecondsInterval * 12*/5));
  LOG(kInfo) << "Slept 3.\n===================\n";
  ASSERT_EQ(kSuccess, user_credentials_->Logout());
  LOG(kInfo) << "Logout.\n===================\n";
  Sleep(bptime::seconds(5));
  LOG(kInfo) << "Slept 5.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->LogIn(keyword_, pin_, password_));
  LOG(kInfo) << "Log in.\n===================\n";
  ASSERT_EQ(kSuccess, user_credentials_->Logout());
  LOG(kInfo) << "Logout.\n===================\n";
  Sleep(bptime::seconds(5));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
