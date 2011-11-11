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

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/authentication.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/lifestuff_messages_pb.h"
#include "maidsafe/lifestuff/tests/test_callback.h"
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

class AuthenticationTest : public testing::Test {
 public:
  AuthenticationTest()
      : test_dir_(maidsafe::test::CreateTestPath()),
        session_(new Session),
#if defined AMAZON_WEB_SERVICE_STORE
        packet_manager_(new AWSStoreManager(session_)),
#else
        packet_manager_(new LocalStoreManager(session_, test_dir_->string())),
#endif
        authentication_(session_),
        username_("user"),
        pin_("1234"),
        password_("password1"),
        ser_dm_(RandomString(10000)),
        test_keys_() {}

 protected:
  void SetUp() {
    session_->ResetSession();
    packet_manager_->Init(std::bind(&AuthenticationTest::InitAndCloseCallback,
                                    this, arg::_1));
    authentication_.Init(packet_manager_);
  }

  void TearDown() {
    packet_manager_->Close(true);
  }

  int GetMasterDataMap(std::string *ser_dm_login) {
    return GetMasterDataMap(ser_dm_login, password_);
  }

  int GetMasterDataMap(std::string *ser_dm_login, const std::string &password) {
    std::shared_ptr<std::string> serialised_master_datamap(new std::string);
    std::shared_ptr<std::string> surrogate_serialised_master_datamap(
        new std::string);
    int res =
        authentication_.GetMasterDataMap(password,
                                         serialised_master_datamap,
                                         surrogate_serialised_master_datamap);
    if (res != 0) {
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

  void InitAndCloseCallback(int /*i*/) {}

  std::shared_ptr<fs::path> test_dir_;
  std::shared_ptr<Session> session_;
  std::shared_ptr<PacketManager> packet_manager_;
  Authentication authentication_;
  std::string username_, pin_, password_, ser_dm_;
  std::vector<crypto::RsaKeyPair> test_keys_;

 private:
  explicit AuthenticationTest(const AuthenticationTest&);
  AuthenticationTest &operator=(const AuthenticationTest&);
};

TEST_F(AuthenticationTest, FUNC_CreateUserSysPackets) {
  username_ += "01";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
}

TEST_F(AuthenticationTest, FUNC_GoodLogin) {
  username_ += "02";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));
  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));
  std::string ser_dm_login;
  ASSERT_EQ(kSuccess, GetMasterDataMap(&ser_dm_login));
  ASSERT_EQ(ser_dm_, ser_dm_login);
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());

  ASSERT_EQ(kSuccess, authentication_.SaveSession(ser_dm_));
  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));
  ser_dm_login.clear();
  ASSERT_EQ(kSuccess, GetMasterDataMap(&ser_dm_login));
  ASSERT_EQ(ser_dm_, ser_dm_login);
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
}

TEST_F(AuthenticationTest, FUNC_LoginNoUser) {
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

TEST_F(AuthenticationTest, FUNC_RegisterUserOnce) {
  username_ += "04";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
//  Sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(password_, session_->password());
}

TEST_F(AuthenticationTest, FUNC_RegisterUserTwice) {
  username_ += "05";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));
  session_->ResetSession();
  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));
}

TEST_F(AuthenticationTest, FUNC_RepeatedSaveSessionBlocking) {
  username_ += "06";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));
  std::string original_tmidname;
  session_->GetKey(passport::TMID, &original_tmidname, NULL, NULL, NULL);
  EXPECT_FALSE(original_tmidname.empty());

  // store current mid, smid and tmid details to check later whether they remain
  // on the network
  ser_dm_ = RandomString(1000);
  ASSERT_EQ(kSuccess, authentication_.SaveSession(ser_dm_));

  ser_dm_ = RandomString(1000);
  ASSERT_EQ(kSuccess, authentication_.SaveSession(ser_dm_));
  std::string tmidname, stmidname;
  session_->GetKey(passport::TMID, &tmidname, NULL, NULL, NULL);
  session_->GetKey(passport::STMID, &stmidname, NULL, NULL, NULL);

  EXPECT_TRUE(packet_manager_->KeyUnique(original_tmidname));
  EXPECT_FALSE(packet_manager_->KeyUnique(stmidname));
  EXPECT_FALSE(packet_manager_->KeyUnique(tmidname));
}

TEST_F(AuthenticationTest, FUNC_RepeatedSaveSessionCallbacks) {
  username_ += "07";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));
  std::string original_tmidname;
  session_->GetKey(passport::TMID, &original_tmidname, NULL, NULL, NULL);
  EXPECT_FALSE(original_tmidname.empty());

  // store current mid, smid and tmid details to check later whether they remain
  // on the network
  ser_dm_ = RandomString(1000);
  CallbackObject cb;
  authentication_.SaveSession(ser_dm_, std::bind(&CallbackObject::IntCallback,
                                                 &cb, arg::_1));
  ASSERT_EQ(kSuccess, cb.WaitForIntResult());

  ser_dm_ = RandomString(1000);
  cb.Reset();
  authentication_.SaveSession(ser_dm_, std::bind(&CallbackObject::IntCallback,
                                                 &cb, arg::_1));
  ASSERT_EQ(kSuccess, cb.WaitForIntResult());
  EXPECT_TRUE(packet_manager_->KeyUnique(original_tmidname));
}

TEST_F(AuthenticationTest, FUNC_ChangeUsername) {
  username_ += "08";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));
  // Save the session to create different TMIDs for MID and SMID
  ASSERT_EQ(kSuccess, authentication_.SaveSession(ser_dm_));
  std::string original_tmidname, original_stmidname;
  session_->GetKey(passport::TMID, &original_tmidname, NULL, NULL, NULL);
  session_->GetKey(passport::STMID, &original_stmidname, NULL, NULL, NULL);
  EXPECT_FALSE(original_tmidname.empty());
  EXPECT_FALSE(original_stmidname.empty());

  ASSERT_EQ(kSuccess, authentication_.ChangeUsername(ser_dm_, "el iuserneim"));
  ASSERT_EQ("el iuserneim", session_->username());

  ASSERT_EQ(kUserExists, authentication_.GetUserInfo("el iuserneim", pin_));
  std::string ser_dm_login;
  ASSERT_EQ(kSuccess, GetMasterDataMap(&ser_dm_login));
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));

  // Check the TMIDs are gone
  ASSERT_TRUE(packet_manager_->KeyUnique(original_tmidname));
  ASSERT_TRUE(packet_manager_->KeyUnique(original_stmidname));
}

TEST_F(AuthenticationTest, FUNC_ChangePin) {
  username_ += "09";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));

  // Save the session to create different TMIDs for MID and SMID
  ASSERT_EQ(kSuccess, authentication_.SaveSession(ser_dm_));
  std::string original_tmidname, original_stmidname;
  session_->GetKey(passport::TMID, &original_tmidname, NULL, NULL, NULL);
  session_->GetKey(passport::STMID, &original_stmidname, NULL, NULL, NULL);
  EXPECT_FALSE(original_tmidname.empty());
  EXPECT_FALSE(original_stmidname.empty());

  ASSERT_EQ(kSuccess, authentication_.ChangePin(ser_dm_, "7894"));
  ASSERT_EQ("7894", session_->pin());

  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, "7894"));
  std::string ser_dm_login;
  ASSERT_EQ(kSuccess, GetMasterDataMap(&ser_dm_login));
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));

  // Check the TMIDs are gone
  ASSERT_TRUE(packet_manager_->KeyUnique(original_tmidname));
  ASSERT_TRUE(packet_manager_->KeyUnique(original_stmidname));
}

TEST_F(AuthenticationTest, FUNC_ChangePassword) {
  username_ += "10";
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));
  // Save the session
  ASSERT_EQ(kSuccess, authentication_.SaveSession(ser_dm_));
  std::string original_tmidname, original_stmidname;

  ASSERT_EQ(kSuccess, authentication_.ChangePassword(ser_dm_, "password_new"));
  ASSERT_EQ("password_new", session_->password());

  std::string ser_dm_login;
  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, GetMasterDataMap(&ser_dm_login));
  ASSERT_NE(ser_dm_, ser_dm_login);

  ser_dm_login.clear();
  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, GetMasterDataMap(&ser_dm_login, "password_new"));
  ASSERT_EQ(ser_dm_, ser_dm_login);
}

TEST_F(AuthenticationTest, FUNC_RegisterLeaveRegister) {
  username_ += "13";
  EXPECT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));

  //  Remove user.
  ASSERT_EQ(kSuccess, authentication_.RemoveMe());

  //  Check user no longer registered.
  session_->ResetSession();
  ASSERT_NE(kUserExists, authentication_.GetUserInfo(username_, pin_));

  session_->ResetSession();
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(username_, pin_,
                                                       password_, ser_dm_));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
