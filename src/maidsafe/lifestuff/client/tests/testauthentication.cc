/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Unit tests for Authentication
* Version:      1.0
* Created:      2009-01-29-03.19.59
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

#include "gtest/gtest.h"

#include "maidsafe/common/utils.h"
#include "maidsafe/lifestuff/shared/filesystem.h"
#include "maidsafe/lifestuff/client/authentication.h"
#include "maidsafe/lifestuff/client/localstoremanager.h"
#include "maidsafe/lifestuff/client/sessionsingleton.h"
#include "maidsafe/lifestuff/client/lifestuff_messages.pb.h"
#include "maidsafe/lifestuff/client/filesystem/dataatlashandler.h"
#include "maidsafe/lifestuff/sharedtest/testcallback.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

namespace test {

class AuthenticationTest : public testing::Test {
 public:
  AuthenticationTest()
      : test_dir_(maidsafe::test::CreateTestPath()),
        ss_(SessionSingleton::getInstance()),
        sm_(new LocalStoreManager(*test_dir_)),
        authentication_(),
        username_("user"),
        pin_("1234"),
        password_("password1"),
        ser_dm_(RandomString(10000)),
        test_keys_() {}
 protected:
  void SetUp() {
    ss_->ResetSession();
    sm_->Init(boost::bind(&AuthenticationTest::InitAndCloseCallback, this, _1),
              0);
    authentication_.Init(sm_);
    ss_ = SessionSingleton::getInstance();
    ss_->ResetSession();
  }

  void TearDown() {
    sm_->Close(boost::bind(&AuthenticationTest::InitAndCloseCallback, this, _1),
               true);
  }

  int GetMasterDataMap(std::string *ser_dm_login) {
    return GetMasterDataMap(ser_dm_login, password_);
  }

  int GetMasterDataMap(std::string *ser_dm_login, const std::string &password) {
    std::shared_ptr<boost::mutex> login_mutex(new boost::mutex);
    std::shared_ptr<boost::condition_variable> login_cond_var(
        new boost::condition_variable);
    std::shared_ptr<int> result(new int(kPendingResult));
    std::shared_ptr<std::string> serialised_master_datamap(new std::string);
    std::shared_ptr<std::string> surrogate_serialised_master_datamap(
        new std::string);
    boost::thread(&Authentication::GetMasterDataMap,
                  &authentication_,
                  password,
                  login_mutex,
                  login_cond_var,
                  result,
                  serialised_master_datamap,
                  surrogate_serialised_master_datamap);
    try {
      boost::mutex::scoped_lock lock(*login_mutex);
      while (*result == kPendingResult)
        login_cond_var->wait(lock);
    }
    catch(const std::exception &e) {
      printf("GetMasterDataMap: %s\n", e.what());
      return kPasswordFailure;
    }

    if (!serialised_master_datamap->empty()) {
      *ser_dm_login = *serialised_master_datamap;
    } else if (!surrogate_serialised_master_datamap->empty()) {
      *ser_dm_login = *surrogate_serialised_master_datamap;
    } else {
      ser_dm_login->clear();
      return kPasswordFailure;
    }
    return kSuccess;
  }

  void InitAndCloseCallback(const ReturnCode&) {}

  std::shared_ptr<fs::path> test_dir_;
  SessionSingleton *ss_;
  std::shared_ptr<LocalStoreManager> sm_;
  Authentication authentication_;
  std::string username_, pin_, password_, ser_dm_;
  std::vector<crypto::RsaKeyPair> test_keys_;

 private:
  explicit AuthenticationTest(const AuthenticationTest&);
  AuthenticationTest &operator=(const AuthenticationTest&);
};

TEST_F(AuthenticationTest, FUNC_MAID_CreateUserSysPackets) {
  username_ += "01";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
}

TEST_F(AuthenticationTest, FUNC_MAID_GoodLogin) {
  username_ += "02";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));

  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));
  std::string ser_dm_login;
  ASSERT_EQ(kSuccess, GetMasterDataMap(&ser_dm_login));
  ASSERT_EQ(ser_dm_, ser_dm_login);
  ASSERT_EQ(username_, ss_->Username());
  ASSERT_EQ(pin_, ss_->Pin());
  ASSERT_EQ(password_, ss_->Password());

  ASSERT_EQ(kSuccess, authentication_.SaveSession(ser_dm_));
  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));
  ser_dm_login.clear();
  ASSERT_EQ(kSuccess, GetMasterDataMap(&ser_dm_login));
  ASSERT_EQ(ser_dm_, ser_dm_login);
  ASSERT_EQ(username_, ss_->Username());
  ASSERT_EQ(pin_, ss_->Pin());
}

TEST_F(AuthenticationTest, FUNC_MAID_LoginNoUser) {
  username_ += "03";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));
  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));
  std::string ser_dm_login;
  password_ = "password_tonto";
  ASSERT_EQ(kSuccess, GetMasterDataMap(&ser_dm_login));
  ASSERT_NE(ser_dm_, ser_dm_login);
}

TEST_F(AuthenticationTest, FUNC_MAID_RegisterUserOnce) {
  username_ += "04";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));
  ASSERT_EQ(username_, ss_->Username());
  ASSERT_EQ(pin_, ss_->Pin());
//  boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(password_, ss_->Password());
}

TEST_F(AuthenticationTest, FUNC_MAID_RegisterUserTwice) {
  username_ += "05";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));
  ss_->ResetSession();
  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));
}

TEST_F(AuthenticationTest, FUNC_MAID_RepeatedSaveSessionBlocking) {
  username_ += "06";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));
  std::string original_tmidname;
  ss_->GetKey(passport::TMID, &original_tmidname, NULL, NULL, NULL);
  EXPECT_FALSE(original_tmidname.empty());

  // store current mid, smid and tmid details to check later whether they remain
  // on the network
  ser_dm_ = RandomString(1000);
  ASSERT_EQ(kSuccess, authentication_.SaveSession(ser_dm_));

  ser_dm_ = RandomString(1000);
  ASSERT_EQ(kSuccess, authentication_.SaveSession(ser_dm_));
  std::string tmidname, stmidname;
  ss_->GetKey(passport::TMID, &tmidname, NULL, NULL, NULL);
  ss_->GetKey(passport::STMID, &stmidname, NULL, NULL, NULL);

  EXPECT_TRUE(sm_->KeyUnique(original_tmidname, false));
  EXPECT_FALSE(sm_->KeyUnique(stmidname, false));
  EXPECT_FALSE(sm_->KeyUnique(tmidname, false));
}

TEST_F(AuthenticationTest, FUNC_MAID_RepeatedSaveSessionCallbacks) {
  username_ += "07";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));
  std::string original_tmidname;
  ss_->GetKey(passport::TMID, &original_tmidname, NULL, NULL, NULL);
  EXPECT_FALSE(original_tmidname.empty());

  // store current mid, smid and tmid details to check later whether they remain
  // on the network
  ser_dm_ = RandomString(1000);
  CallbackObject cb;
  authentication_.SaveSession(ser_dm_, boost::bind(
      &CallbackObject::ReturnCodeCallback, &cb, _1));
  ASSERT_EQ(kSuccess, cb.WaitForReturnCodeResult());

  ser_dm_ = RandomString(1000);
  cb.Reset();
  authentication_.SaveSession(ser_dm_, boost::bind(
      &CallbackObject::ReturnCodeCallback, &cb, _1));
  ASSERT_EQ(kSuccess, cb.WaitForReturnCodeResult());
  EXPECT_TRUE(sm_->KeyUnique(original_tmidname, false));
}

TEST_F(AuthenticationTest, FUNC_MAID_ChangeUsername) {
  username_ += "08";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));
  // Save the session to create different TMIDs for MID and SMID
  ASSERT_EQ(kSuccess, authentication_.SaveSession(ser_dm_));
  std::string original_tmidname, original_stmidname;
  ss_->GetKey(passport::TMID, &original_tmidname, NULL, NULL, NULL);
  ss_->GetKey(passport::STMID, &original_stmidname, NULL, NULL, NULL);
  EXPECT_FALSE(original_tmidname.empty());
  EXPECT_FALSE(original_stmidname.empty());

  ASSERT_EQ(kSuccess, authentication_.ChangeUsername(ser_dm_, "el iuserneim"));
  ASSERT_EQ("el iuserneim", ss_->Username());

  ASSERT_EQ(kUserExists, authentication_.GetUserInfo("el iuserneim", pin_));
  std::string ser_dm_login;
  ASSERT_EQ(kSuccess, GetMasterDataMap(&ser_dm_login));
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));

  // Check the TMIDs are gone
  ASSERT_TRUE(sm_->KeyUnique(original_tmidname, false));
  ASSERT_TRUE(sm_->KeyUnique(original_stmidname, false));
}

TEST_F(AuthenticationTest, FUNC_MAID_ChangePin) {
  username_ += "09";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));

  // Save the session to create different TMIDs for MID and SMID
  ASSERT_EQ(kSuccess, authentication_.SaveSession(ser_dm_));
  std::string original_tmidname, original_stmidname;
  ss_->GetKey(passport::TMID, &original_tmidname, NULL, NULL, NULL);
  ss_->GetKey(passport::STMID, &original_stmidname, NULL, NULL, NULL);
  EXPECT_FALSE(original_tmidname.empty());
  EXPECT_FALSE(original_stmidname.empty());

  ASSERT_EQ(kSuccess, authentication_.ChangePin(ser_dm_, "7894"));
  ASSERT_EQ("7894", ss_->Pin());

  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, "7894"));
  std::string ser_dm_login;
  ASSERT_EQ(kSuccess, GetMasterDataMap(&ser_dm_login));
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));

  // Check the TMIDs are gone
  ASSERT_TRUE(sm_->KeyUnique(original_tmidname, false));
  ASSERT_TRUE(sm_->KeyUnique(original_stmidname, false));
}

TEST_F(AuthenticationTest, FUNC_MAID_ChangePassword) {
  username_ += "10";
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));
  // Save the session
  ASSERT_EQ(kSuccess, authentication_.SaveSession(ser_dm_));
  std::string original_tmidname, original_stmidname;

  ASSERT_EQ(kSuccess, authentication_.ChangePassword(ser_dm_, "password_new"));
  ASSERT_EQ("password_new", ss_->Password());

  std::string ser_dm_login;
  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, GetMasterDataMap(&ser_dm_login));
  ASSERT_NE(ser_dm_, ser_dm_login);

  ser_dm_login.clear();
  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, GetMasterDataMap(&ser_dm_login, "password_new"));
  ASSERT_EQ(ser_dm_, ser_dm_login);
}

/*
TEST_F(AuthenticationTest, FUNC_MAID_CreatePublicName) {
  username_ += "11";
  ASSERT_EQ(kSuccess, authentication_.CreatePublicName("el public iuserneim"));
  ASSERT_EQ(kPublicUsernameAlreadySet,
            authentication_.CreatePublicName("el public iuserneim"));
  // Reset PublicUsername to allow attempt to save same public name to network.
//  ASSERT_TRUE(ss_->SetPublicUsername(""));
//  ASSERT_EQ(kPublicUsernameExists,
//            authentication_.CreatePublicName("el public iuserneim"));
  authentication_.tmid_op_status_ = Authentication::kFailed;
  authentication_.stmid_op_status_ = Authentication::kFailed;
}

TEST_F(AuthenticationTest, FUNC_MAID_CreateMSIDPacket) {
  username_ += "12";
  std::string msid_name, pub_key, priv_key;
  ASSERT_EQ(kSuccess,
            authentication_.CreateMsidPacket(&msid_name, &pub_key, &priv_key));
  ASSERT_FALSE(msid_name.empty());
  ASSERT_FALSE(priv_key.empty());
  ASSERT_FALSE(pub_key.empty());

  // Check the packet exits
  std::vector<std::string> packet_content;
  ASSERT_EQ(kSuccess, sm_->LoadPacket(msid_name, &packet_content));
  ASSERT_EQ(size_t(1), packet_content.size());
  GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(packet_content[0]));

  // Check packet is correct and signed
  ASSERT_EQ(pub_key, gp.data());
  ASSERT_TRUE(crypto::AsymCheckSig(gp.data(), gp.signature(), pub_key));
  ASSERT_EQ(crypto::Hash<crypto::SHA512>(pub_key + gp.signature()), msid_name);
  authentication_.tmid_op_status_ = Authentication::kFailed;
  authentication_.stmid_op_status_ = Authentication::kFailed;
}
*/

TEST_F(AuthenticationTest, FUNC_MAID_RegisterLeaveRegister) {
  username_ += "13";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));

  //  Remove user.
  ASSERT_EQ(kSuccess, authentication_.RemoveMe());
  try {
    fs::remove_all(file_system::MaidsafeDir(ss_->SessionName()));
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }

  //  Check user no longer registered.
  ss_->ResetSession();
  ASSERT_NE(kUserExists, authentication_.GetUserInfo(username_, pin_));

  ss_->ResetSession();
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
