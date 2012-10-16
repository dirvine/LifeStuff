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
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#include "maidsafe/pd/client/node.h"
#include "maidsafe/pd/client/utils.h"
#include "maidsafe/pd/vault/node.h"
#include "maidsafe/pd/common/rpc_handler.h"
#include "maidsafe/pd/common/timed_event_handler.h"
#include "maidsafe/pd/common/routing_message_handler.h"
#include "maidsafe/pd/common/key_manager.h"

#include "maidsafe/lifestuff/rcs_helper.h"
#include "maidsafe/lifestuff/detail/routings_handler.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/user_credentials.h"
#include "maidsafe/lifestuff/detail/utils.h"
#include "maidsafe/lifestuff/tests/network_helper.h"


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
        network_(),
        client_node_(),
        client_node2_(),
        vault_node_(),
        vault_node2_(),
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

  void ImmediateQuitRequiredSlot() {
    immediate_quit_required_ = true;
  }

 protected:
  void SetUp() {
    vault_node_.reset(new pd::vault::Node);
    vault_node2_.reset(new pd::vault::Node);
    asio_service_.Start();
    asio_service2_.Start();
    ASSERT_TRUE(network_.StartLocalNetwork(test_dir_, 10));
    std::vector<std::pair<std::string, uint16_t>> bootstrap_endpoints;
    remote_chunk_store_ = BuildChunkStore(*test_dir_,
                                          bootstrap_endpoints,
                                          client_node_,
                                          [] (const int&) {}/*NetworkHealthFunction()*/);

    routings_handler_ = std::make_shared<RoutingsHandler>(*remote_chunk_store_,
                                                          session_,
                                                          [] (const std::string&, std::string&) {
                                                            return false;
                                                          });

    user_credentials_ = std::make_shared<UserCredentials>(*remote_chunk_store_,
                                                          session_,
                                                          asio_service_.service(),
                                                          *routings_handler_);
  }

  void TearDown() {
    user_credentials_.reset();
    routings_handler_.reset();
    remote_chunk_store_.reset();
    {
      int result(client_node_->Stop());
      if (result != kSuccess)
        LOG(kError) << "Failed to stop client node, result : " << result;
      client_node_.reset();
    }
    {
      int result(vault_node_->Stop());
      if (result != kSuccess)
        LOG(kError) << "Failed to stop vault node, result : " << result;
      vault_node_.reset();
    }

    EXPECT_TRUE(network_.StopLocalNetwork());
    asio_service_.Stop();
    asio_service2_.Stop();
  }

  void SetUpSecondUserCredentials() {
    std::vector<std::pair<std::string, uint16_t>> bootstrap_endpoints;
    remote_chunk_store2_ = BuildChunkStore(*test_dir_,
                                           bootstrap_endpoints,
                                           client_node2_,
                                           NetworkHealthFunction());
    user_credentials2_ = std::make_shared<UserCredentials>(*remote_chunk_store2_,
                                                           session2_,
                                                           asio_service2_.service(),
                                                           *routings_handler2_);
  }

  int CreateVaultForClient(std::shared_ptr<pd::vault::Node>& vault_node, Session& session) {
    vault_node->set_do_backup_state(false);
    vault_node->set_do_synchronise(true);
    vault_node->set_do_check_integrity(false);
    vault_node->set_do_announce_chunks(false);
    std::string account_name(session.passport().SignaturePacketDetails(passport::kMaid,
                                                                       true).identity);
    LOG(kSuccess) << "Account name for vault " << Base32Substr(account_name);
    vault_node->set_account_name(account_name);
    vault_node->set_keys(session.passport().SignaturePacketDetails(passport::kPmid, true));

    return vault_node->Start(*test_dir_ / ("client_vault" + RandomAlphaNumericString(8)));
  }

  int MakeClientNode(std::shared_ptr<UserCredentials>& user_credentials,
                     std::shared_ptr<RoutingsHandler>& routings_handler,
                     std::shared_ptr<pd::Node>& client_node,
                     Session& session,
                     std::shared_ptr<pcs::RemoteChunkStore>& remote_chunk_store) {
    int result(client_node->Stop());
    if (result != kSuccess) {
      LOG(kError) << "Failed to stop client node.";
      return result;
    }
    asymm::Keys maid(session.passport().SignaturePacketDetails(passport::kMaid, true));
    client_node->set_keys(maid);
    client_node->set_account_name(maid.identity);
    result = client_node->Start(*test_dir_ / "buffered_chunk_store");
    if (result != kSuccess) {
      LOG(kError) << "Failed to start client node.";
      return result;
    }

    remote_chunk_store =
        std::make_shared<pcs::RemoteChunkStore>(client_node_->chunk_store(),
                                                client_node_->chunk_manager(),
                                                client_node_->chunk_action_authority());
    routings_handler->set_remote_chunk_store(*remote_chunk_store_);
    user_credentials->set_remote_chunk_store(*remote_chunk_store_);

    return kSuccess;
  }

  int MakeAnonymousNode(std::shared_ptr<UserCredentials>& user_credentials,
                        std::shared_ptr<RoutingsHandler>& routings_handler,
                        std::shared_ptr<pd::Node>& client_node,
                        std::shared_ptr<pcs::RemoteChunkStore>& remote_chunk_store,
                        const std::string& maid_id) {
    int result(client_node->Stop());
    if (result != kSuccess) {
      LOG(kError) << "Failed to stop client node.";
      return result;
    }

    if (!routings_handler->DeleteRoutingObject(maid_id)) {
      LOG(kError) << "Failed to delete MAID routing object.";
      return -1;
    }

    client_node->set_keys(asymm::Keys());
    client_node->set_account_name("");
    result = client_node->Start(*test_dir_ / "buffered_chunk_store");
    if (result != kSuccess) {
      LOG(kError) << "Failed to start client node.";
      return result;
    }

    remote_chunk_store =
        std::make_shared<pcs::RemoteChunkStore>(client_node_->chunk_store(),
                                                client_node_->chunk_manager(),
                                                client_node_->chunk_action_authority());
    routings_handler->set_remote_chunk_store(*remote_chunk_store_);
    user_credentials->set_remote_chunk_store(*remote_chunk_store_);

    return kSuccess;
  }

  void DoCreateUser(const std::string& keyword,
                    const std::string& pin,
                    const std::string& password,
                    std::shared_ptr<UserCredentials>& user_credentials,
                    std::shared_ptr<RoutingsHandler>& routings_handler,
                    std::shared_ptr<pd::Node>& client_node,
                    Session& session,
                    std::shared_ptr<pcs::RemoteChunkStore>& remote_chunk_store,
                    std::shared_ptr<pd::vault::Node>& vault_node) {
    LOG(kInfo) << "\n\nStarting DoCreateUser\n\n";
    ASSERT_EQ(kSuccess, user_credentials->CreateUser(keyword, pin, password));
    LOG(kSuccess) << "User credentials created.\n===================\n";

    ASSERT_EQ(kSuccess, CreateVaultForClient(vault_node, session));
    LOG(kSuccess) << "Constructed vault.\n===================\n";
    Sleep(bptime::seconds(15));
    ASSERT_EQ(kSuccess, MakeClientNode(user_credentials,
                                       routings_handler,
                                       client_node,
                                       session,
                                       remote_chunk_store));
    LOG(kSuccess) << "Constructed client node.\n===================\n";
    Sleep(bptime::seconds(15));

    ASSERT_EQ(keyword, session.keyword());
    ASSERT_EQ(pin, session.pin());
    ASSERT_EQ(password, session.password());
    LOG(kSuccess) << "User created.\n===================\n\n\n";
  }

  void DoLogOut(std::shared_ptr<UserCredentials>& user_credentials,
                std::shared_ptr<RoutingsHandler>& routings_handler,
                std::shared_ptr<pd::Node>& client_node,
                Session& session,
                std::shared_ptr<pcs::RemoteChunkStore>& remote_chunk_store) {
    LOG(kInfo) << "\n\nStarting DoLogOut\n\n";
    EXPECT_EQ(kSuccess, user_credentials->Logout());
    std::string maid_id(session.passport().SignaturePacketDetails(passport::kMaid, true).identity);
    session.Reset();
    LOG(kInfo) << "Credentials logged out.\n===================\n";

    ASSERT_EQ(kSuccess, MakeAnonymousNode(user_credentials,
                                          routings_handler,
                                          client_node,
                                          remote_chunk_store,
                                          maid_id));
    Sleep(bptime::seconds(15));
    LOG(kSuccess) << "Constructed anonymous node.\n===================\n";

    LOG(kInfo) << "Logged out.\n===================\n\n\n";
  }

  void DoLogIn(const std::string& keyword,
               const std::string& pin,
               const std::string& password,
               std::shared_ptr<UserCredentials>& user_credentials,
               std::shared_ptr<RoutingsHandler>& routings_handler,
               std::shared_ptr<pd::Node>& client_node,
               Session& session,
               std::shared_ptr<pcs::RemoteChunkStore>& remote_chunk_store) {
    LOG(kInfo) << "\n\nStarting DoLogIn\n\n";
    ASSERT_EQ(kSuccess, user_credentials->LogIn(keyword, pin, password));
    LOG(kInfo) << "Credentials logged in.\n===================\n";

    ASSERT_EQ(kSuccess, MakeClientNode(user_credentials,
                                       routings_handler,
                                       client_node,
                                       session,
                                       remote_chunk_store));
    LOG(kSuccess) << "Constructed client node.\n===================\n";
    Sleep(bptime::seconds(15));

    LOG(kInfo) << "Logged in.\n===================\n\n\n";
  }

  void DoLogOutAndStop(std::shared_ptr<UserCredentials>& user_credentials,
                       std::shared_ptr<pd::Node>& client_node,
                       std::shared_ptr<pd::vault::Node>& vault_node,
                       Session& session) {
    LOG(kInfo) << "\n\nStarting DoLogOutAndStop\n\n";
    ASSERT_EQ(kSuccess, user_credentials->Logout());
    LOG(kInfo) << "Credentials logged out.\n===================\n";

    ASSERT_EQ(kSuccess, client_node->Stop());
    ASSERT_EQ(kSuccess, vault_node->Stop());
    session.Reset();
    LOG(kInfo) << "Stopped nodes.\n===================\n";
  }

  std::shared_ptr<fs::path> test_dir_;
  Session session_, session2_;
  AsioService asio_service_, asio_service2_;
  NetworkHelper network_;
  std::shared_ptr<pd::Node> client_node_, client_node2_;
  std::shared_ptr<pd::vault::Node> vault_node_, vault_node2_;
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store_, remote_chunk_store2_;
  std::shared_ptr<RoutingsHandler> routings_handler_, routings_handler2_;
  std::shared_ptr<UserCredentials> user_credentials_, user_credentials2_;
  std::string keyword_, pin_, password_;
  bool immediate_quit_required_;

 private:
  CredentialsTest(const CredentialsTest&);
  CredentialsTest &operator=(const CredentialsTest&);
};

TEST_F(CredentialsTest, FUNC_DoCreateUserDoLogOutAndStop) {
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  ASSERT_EQ(kLoginUserNonExistence, user_credentials_->LogIn(keyword_, pin_, password_));
  LOG(kSuccess) << "Preconditions fulfilled.\n===================\n";

  DoCreateUser(keyword_,
               pin_,
               password_,
               user_credentials_,
               routings_handler_,
               client_node_,
               session_,
               remote_chunk_store_,
               vault_node_);
  DoLogOutAndStop(user_credentials_,
                  client_node_,
                  vault_node_,
                  session_);
}

TEST_F(CredentialsTest, FUNC_LoginSequence) {
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  ASSERT_EQ(kLoginUserNonExistence, user_credentials_->LogIn(keyword_, pin_, password_));
  LOG(kSuccess) << "Preconditions fulfilled.\n===================\n";

  DoCreateUser(keyword_,
               pin_,
               password_,
               user_credentials_,
               routings_handler_,
               client_node_,
               session_,
               remote_chunk_store_,
               vault_node_);

  DoLogOut(user_credentials_,
           routings_handler_,
           client_node_,
           session_,
           remote_chunk_store_);

  DoLogIn(keyword_,
          pin_,
          password_,
          user_credentials_,
          routings_handler_,
          client_node_,
          session_,
          remote_chunk_store_);

  DoLogOutAndStop(user_credentials_,
                  client_node_,
                  vault_node_,
                  session_);
}

TEST_F(CredentialsTest, FUNC_ChangeDetails) {
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  ASSERT_EQ(kLoginUserNonExistence, user_credentials_->LogIn(keyword_, pin_, password_));
  LOG(kInfo) << "Preconditions fulfilled.\n===================\n";

  DoCreateUser(keyword_,
               pin_,
               password_,
               user_credentials_,
               routings_handler_,
               client_node_,
               session_,
               remote_chunk_store_,
               vault_node_);

  DoLogOut(user_credentials_,
           routings_handler_,
           client_node_,
           session_,
           remote_chunk_store_);

  DoLogIn(keyword_,
          pin_,
          password_,
          user_credentials_,
          routings_handler_,
          client_node_,
          session_,
          remote_chunk_store_);

  LOG(kInfo) << "Logged in.\n===================\n";
  const std::string kNewKeyword(RandomAlphaNumericString(9));
  ASSERT_EQ(kSuccess, user_credentials_->ChangeKeyword(kNewKeyword));
  ASSERT_EQ(kNewKeyword, session_.keyword());
  ASSERT_EQ(pin_, session_.pin());
  ASSERT_EQ(password_, session_.password());
  LOG(kInfo) << "Changed keyword.\n===================\n";

  DoLogOut(user_credentials_,
           routings_handler_,
           client_node_,
           session_,
           remote_chunk_store_);

  DoLogIn(kNewKeyword,
          pin_,
          password_,
          user_credentials_,
          routings_handler_,
          client_node_,
          session_,
          remote_chunk_store_);

  const std::string kNewPin(CreatePin());
  ASSERT_EQ(kSuccess, user_credentials_->ChangePin(kNewPin));
  ASSERT_EQ(kNewKeyword, session_.keyword());
  ASSERT_EQ(kNewPin, session_.pin());
  ASSERT_EQ(password_, session_.password());
  LOG(kInfo) << "Changed pin.\n===================\n";

  DoLogOut(user_credentials_,
           routings_handler_,
           client_node_,
           session_,
           remote_chunk_store_);

  DoLogIn(kNewKeyword,
          kNewPin,
          password_,
          user_credentials_,
          routings_handler_,
          client_node_,
          session_,
          remote_chunk_store_);

  const std::string kNewPassword(RandomAlphaNumericString(9));
  ASSERT_EQ(kSuccess, user_credentials_->ChangePassword(kNewPassword));
  ASSERT_EQ(kNewKeyword, session_.keyword());
  ASSERT_EQ(kNewPin, session_.pin());
  ASSERT_EQ(kNewPassword, session_.password());
  LOG(kInfo) << "Changed password.\n===================\n";

  DoLogOut(user_credentials_,
           routings_handler_,
           client_node_,
           session_,
           remote_chunk_store_);

  DoLogIn(kNewKeyword,
          kNewPin,
          kNewPassword,
          user_credentials_,
          routings_handler_,
          client_node_,
          session_,
          remote_chunk_store_);

  DoLogOutAndStop(user_credentials_,
                  client_node_,
                  vault_node_,
                  session_);

  ASSERT_EQ(kLoginUserNonExistence, user_credentials_->LogIn(keyword_, pin_, password_));
  ASSERT_EQ(kLoginUserNonExistence, user_credentials_->LogIn(kNewKeyword, pin_, password_));
  ASSERT_EQ(kLoginAccountCorrupted, user_credentials_->LogIn(kNewKeyword, kNewPin, password_));
  ASSERT_EQ(kLoginUserNonExistence, user_credentials_->LogIn(kNewKeyword, pin_, kNewPassword));
  ASSERT_EQ(kLoginUserNonExistence, user_credentials_->LogIn(keyword_, kNewPin, kNewPassword));
  LOG(kInfo) << "Can't log in with old u/p/w.";
}

TEST_F(CredentialsTest, DISABLED_FUNC_ParallelLogin) {
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  LOG(kInfo) << "Preconditions fulfilled.\n===================\n";

  ASSERT_EQ(kLoginUserNonExistence, user_credentials_->LogIn(keyword_, pin_, password_));

  ASSERT_EQ(kSuccess, user_credentials_->CreateUser(keyword_, pin_, password_));
  session_.set_unique_user_id(RandomString(64));
  session_.set_root_parent_id(RandomString(64));
  ASSERT_EQ(keyword_, session_.keyword());
  ASSERT_EQ(pin_, session_.pin());
  ASSERT_EQ(password_, session_.password());
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

  EXPECT_TRUE(session_.keyword().empty());
  EXPECT_TRUE(session_.pin().empty());
  EXPECT_TRUE(session_.password().empty());
  EXPECT_EQ(session_.session_access_level(), kNoAccess);

  ASSERT_EQ(kSuccess, user_credentials2_->Logout());

  EXPECT_TRUE(session2_.keyword().empty());
  EXPECT_TRUE(session2_.pin().empty());
  EXPECT_TRUE(session2_.password().empty());
  EXPECT_EQ(session2_.session_access_level(), kNoAccess);
}

TEST_F(CredentialsTest, FUNC_MultiUserCredentialsLoginAndLogout) {
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  LOG(kInfo) << "Preconditions fulfilled.\n===================\n";

  ASSERT_EQ(kLoginUserNonExistence, user_credentials_->LogIn(keyword_, pin_, password_));
  DoCreateUser(keyword_,
               pin_,
               password_,
               user_credentials_,
               routings_handler_,
               client_node_,
               session_,
               remote_chunk_store_,
               vault_node_);

  DoLogOutAndStop(user_credentials_,
                  client_node_,
                  vault_node_,
                  session_);

  SetUpSecondUserCredentials();
  DoLogIn(keyword_,
          pin_,
          password_,
          user_credentials2_,
          routings_handler2_,
          client_node2_,
          session2_,
          remote_chunk_store2_);
  DoLogOutAndStop(user_credentials2_,
                  client_node2_,
                  vault_node2_,
                  session2_);
}

TEST_F(CredentialsTest, FUNC_UserCredentialsDeletion) {
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  ASSERT_EQ(kLoginUserNonExistence, user_credentials_->LogIn(keyword_, pin_, password_));
  LOG(kInfo) << "Preconditions fulfilled.\n===================\n";

  DoCreateUser(keyword_,
               pin_,
               password_,
               user_credentials_,
               routings_handler_,
               client_node_,
               session_,
               remote_chunk_store_,
               vault_node_);
  passport::Passport& pass(session_.passport());
  std::string anmid_name(pca::ApplyTypeToName(
                           pass.SignaturePacketDetails(passport::kAnmid, true).identity,
                           priv::ChunkType::kSignaturePacket));
  std::string ansmid_name(pca::ApplyTypeToName(
                    pass.SignaturePacketDetails(passport::kAnsmid, true).identity,
                    priv::ChunkType::kSignaturePacket));
  std::string antmid_name(pca::ApplyTypeToName(
                    pass.SignaturePacketDetails(passport::kAntmid, true).identity,
                    priv::ChunkType::kSignaturePacket));
  std::string anmaid_name(pca::ApplyTypeToName(
                    pass.SignaturePacketDetails(passport::kAnmaid, true).identity,
                    priv::ChunkType::kSignaturePacket));
  std::string maid_name(pca::ApplyTypeToName(
                          pass.SignaturePacketDetails(passport::kMaid, true).identity,
                          priv::ChunkType::kSignaturePacket));
  std::string pmid_name(pca::ApplyTypeToName(
                          pass.SignaturePacketDetails(passport::kPmid, true).identity,
                          priv::ChunkType::kSignaturePacket));
  std::string mid_name(pca::ApplyTypeToName(pass.IdentityPacketName(passport::kMid, true),
                                            priv::ChunkType::kModifiableByOwner));
  std::string smid_name(pca::ApplyTypeToName(pass.IdentityPacketName(passport::kSmid, true),
                                             priv::ChunkType::kModifiableByOwner));
  std::string tmid_name(pca::ApplyTypeToName(pass.IdentityPacketName(passport::kTmid, true),
                                             priv::ChunkType::kModifiableByOwner));
  std::string stmid_name(pca::ApplyTypeToName(pass.IdentityPacketName(passport::kStmid, true),
                                              priv::ChunkType::kModifiableByOwner));

  ASSERT_NE("", remote_chunk_store_->Get(anmid_name));
  ASSERT_NE("", remote_chunk_store_->Get(ansmid_name));
  ASSERT_NE("", remote_chunk_store_->Get(antmid_name));
  ASSERT_NE("", remote_chunk_store_->Get(anmaid_name));
  ASSERT_NE("", remote_chunk_store_->Get(maid_name));
  ASSERT_NE("", remote_chunk_store_->Get(pmid_name));
  ASSERT_NE("", remote_chunk_store_->Get(mid_name));
  ASSERT_NE("", remote_chunk_store_->Get(smid_name));
  ASSERT_NE("", remote_chunk_store_->Get(tmid_name));
  ASSERT_NE("", remote_chunk_store_->Get(stmid_name));

  ASSERT_EQ(kSuccess, user_credentials_->DeleteUserCredentials());
  LOG(kInfo) << "Deleted user credentials.\n=================\n";
  ASSERT_EQ(kSuccess, MakeAnonymousNode(user_credentials_,
                                        routings_handler_,
                                        client_node_,
                                        remote_chunk_store_,
                                        maid_name.substr(0, 64)));
  Sleep(bptime::seconds(15));
  LOG(kSuccess) << "Constructed anonymous node.\n===================\n";

  ASSERT_EQ("", remote_chunk_store_->Get(anmid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(ansmid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(antmid_name));
//  ASSERT_EQ("", remote_chunk_store_->Get(anmaid_name));
//  ASSERT_EQ("", remote_chunk_store_->Get(maid_name));
//  ASSERT_EQ("", remote_chunk_store_->Get(pmid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(mid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(smid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(tmid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(stmid_name));

  ASSERT_NE(kSuccess, user_credentials_->Logout());

  LOG(kInfo) << "Recreating deleted account...\n===================\n";
  SetUpSecondUserCredentials();
  DoCreateUser(keyword_,
               pin_,
               password_,
               user_credentials2_,
               routings_handler2_,
               client_node2_,
               session2_,
               remote_chunk_store2_,
               vault_node2_);

  DoLogOut(user_credentials2_,
           routings_handler2_,
           client_node2_,
           session2_,
           remote_chunk_store2_);
  DoLogIn(keyword_,
          pin_,
          password_,
          user_credentials2_,
          routings_handler2_,
          client_node2_,
          session2_,
          remote_chunk_store2_);
  passport::Passport& pass2(session2_.passport());

  anmid_name = pca::ApplyTypeToName(pass2.SignaturePacketDetails(passport::kAnmid, true).identity,
                                    priv::ChunkType::kSignaturePacket);
  ansmid_name = pca::ApplyTypeToName(pass2.SignaturePacketDetails(passport::kAnsmid, true).identity,
                                     priv::ChunkType::kSignaturePacket);
  antmid_name = pca::ApplyTypeToName(pass2.SignaturePacketDetails(passport::kAntmid, true).identity,
                                     priv::ChunkType::kSignaturePacket);
  anmaid_name = pca::ApplyTypeToName(pass2.SignaturePacketDetails(passport::kAnmaid, true).identity,
                                     priv::ChunkType::kSignaturePacket);
  maid_name = pca::ApplyTypeToName(pass2.SignaturePacketDetails(passport::kMaid, true).identity,
                                   priv::ChunkType::kSignaturePacket);
  pmid_name = pca::ApplyTypeToName(pass2.SignaturePacketDetails(passport::kPmid, true).identity,
                                   priv::ChunkType::kSignaturePacket);
  mid_name = pca::ApplyTypeToName(pass2.IdentityPacketName(passport::kMid, true),
                                  priv::ChunkType::kModifiableByOwner);
  smid_name = pca::ApplyTypeToName(pass2.IdentityPacketName(passport::kSmid, true),
                                   priv::ChunkType::kModifiableByOwner);
  tmid_name = pca::ApplyTypeToName(pass2.IdentityPacketName(passport::kTmid, true),
                                   priv::ChunkType::kModifiableByOwner);
  stmid_name = pca::ApplyTypeToName(pass2.IdentityPacketName(passport::kStmid, true),
                                    priv::ChunkType::kModifiableByOwner);

  ASSERT_NE("", remote_chunk_store2_->Get(anmid_name));
  ASSERT_NE("", remote_chunk_store2_->Get(ansmid_name));
  ASSERT_NE("", remote_chunk_store2_->Get(antmid_name));
  ASSERT_NE("", remote_chunk_store2_->Get(anmaid_name));
  ASSERT_NE("", remote_chunk_store2_->Get(maid_name));
  ASSERT_NE("", remote_chunk_store2_->Get(pmid_name));
  ASSERT_NE("", remote_chunk_store2_->Get(mid_name));
  ASSERT_NE("", remote_chunk_store2_->Get(smid_name));
  ASSERT_NE("", remote_chunk_store2_->Get(tmid_name));
  ASSERT_NE("", remote_chunk_store2_->Get(stmid_name));

  ASSERT_EQ(kSuccess, user_credentials2_->DeleteUserCredentials());
  ASSERT_EQ(kSuccess, MakeAnonymousNode(user_credentials2_,
                                        routings_handler2_,
                                        client_node2_,
                                        remote_chunk_store2_,
                                        maid_name.substr(0, 64)));
  Sleep(bptime::seconds(15));
  LOG(kSuccess) << "Constructed anonymous node.\n===================\n";
  ASSERT_EQ("", remote_chunk_store2_->Get(anmid_name));
  ASSERT_EQ("", remote_chunk_store2_->Get(ansmid_name));
  ASSERT_EQ("", remote_chunk_store2_->Get(antmid_name));
//  ASSERT_EQ("", remote_chunk_store2_->Get(anmaid_name));
//  ASSERT_EQ("", remote_chunk_store2_->Get(maid_name));
//  ASSERT_EQ("", remote_chunk_store2_->Get(pmid_name));
  ASSERT_EQ("", remote_chunk_store2_->Get(mid_name));
  ASSERT_EQ("", remote_chunk_store2_->Get(smid_name));
  ASSERT_EQ("", remote_chunk_store2_->Get(tmid_name));
  ASSERT_EQ("", remote_chunk_store2_->Get(stmid_name));

  ASSERT_NE(kSuccess, user_credentials2_->Logout());
  ASSERT_NE(kSuccess, user_credentials2_->LogIn(keyword_, pin_, password_));
}

TEST_F(CredentialsTest, DISABLED_FUNC_SessionSaverTimer) {
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  LOG(kInfo) << "Preconditions fulfilled.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->CreateUser(keyword_, pin_, password_));
  session_.set_unique_user_id(RandomString(64));
  session_.set_root_parent_id(RandomString(64));
  LOG(kInfo) << "Created user.\n===================\n";
  Sleep(bptime::seconds(3));
  LOG(kInfo) << "Slept 3.\n===================\n";
  ASSERT_EQ(kSuccess, session_.AddPublicId(RandomAlphaNumericString(5), RandomString(64)));
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
  ASSERT_EQ(kSuccess, session_.AddPublicId(RandomAlphaNumericString(5), RandomString(64)));
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
