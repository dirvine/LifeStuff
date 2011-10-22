/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Version:      1.0
* Created:      2009-01-28-10.59.46
* Revision:     none
* Compiler:     gcc
* Author:       Team
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
#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/crypto.h"

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "boost/signals2/connection.hpp"
#include "maidsafe/lifestuff/lifestuff_messages.pb.h"

#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "maidsafe/lifestuff/localstoremanager.h"
#include "maidsafe/lifestuff/tests/mocksessionsingleton.h"
#include "maidsafe/lifestuff/tests/testcallback.h"

namespace arg = std::placeholders;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

namespace test {

boost::system::error_code error_code;

class LocalStoreManagerTest : public testing::Test {
 public:
  LocalStoreManagerTest()
      : test_root_dir_(maidsafe::test::CreateTestPath()),
        ss_(new SessionSingleton),
        sm_(new LocalStoreManager(*test_root_dir_, ss_)),
        cb_(),
        functor_(),
        anmaid_private_key_(),
        anmaid_public_key_(),
        mpid_public_key_() {}

  ~LocalStoreManagerTest() {}

 protected:
  void SetUp() {
    ss_->ResetSession();

    sm_->Init(std::bind(&CallbackObject::IntCallback, &cb_, arg::_1), 0);
    if (cb_.WaitForIntResult() != kSuccess) {
      FAIL();
      return;
    }

    ss_->ResetSession();
    ASSERT_TRUE(ss_->CreateTestPackets("Me"));
    cb_.Reset();
    functor_ = std::bind(&CallbackObject::IntCallback, &cb_, arg::_1);
    anmaid_private_key_ = ss_->PrivateKey(passport::ANMAID, true);
    anmaid_public_key_ = ss_->PublicKey(passport::ANMAID, true);
    mpid_public_key_ = ss_->PublicKey(passport::MPID, true);
  }

  void TearDown() {
    ss_->ResetSession();
    cb_.Reset();
    sm_->Close(true);
    ss_->passport_->StopCreatingKeyPairs();
  }

  std::shared_ptr<fs::path> test_root_dir_;
  std::shared_ptr<SessionSingleton> ss_;
  std::shared_ptr<LocalStoreManager> sm_;
  test::CallbackObject cb_;
  std::function<void(int)> functor_;  // NOLINT
  std::string anmaid_private_key_, anmaid_public_key_, mpid_public_key_;

 private:
  LocalStoreManagerTest(const LocalStoreManagerTest&);
  LocalStoreManagerTest &operator=(const LocalStoreManagerTest&);
};

TEST_F(LocalStoreManagerTest, BEH_RemoveAllPacketsFromKey) {
  SignedValue gp;
  std::string gp_name;

  // Store packets with same key, different values
  gp_name = crypto::Hash<crypto::SHA512>("aaa");
//  for (int i = 0; i < 5; ++i) {
    gp.set_value("Generic System Packet Data");  // +
//                  boost::lexical_cast<std::string>(i));
    cb_.Reset();
    sm_->StorePacket(gp_name, gp.value(), passport::MAID, PRIVATE, "",
                     functor_);
    ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
//  }

  // Remove said packets
  cb_.Reset();
  sm_->DeletePacket(gp_name, std::vector<std::string>(), passport::MAID,
                    PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
  // Ensure they're all gone
  ASSERT_TRUE(sm_->KeyUnique(gp_name, false));
}

TEST_F(LocalStoreManagerTest, BEH_StoreSystemPacket) {
  SignedValue gp;
  gp.set_value("Generic System Packet Data");
  gp.set_value_signature(crypto::AsymSign(gp.value(), anmaid_private_key_));
  std::string gp_name = crypto::Hash<crypto::SHA512>(gp.value() +
                                                     gp.value_signature());
  ASSERT_TRUE(sm_->KeyUnique(gp_name, false));
  cb_.Reset();
  sm_->StorePacket(gp_name, gp.value(), passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
  ASSERT_FALSE(sm_->KeyUnique(gp_name, false));
  std::vector<std::string> res;
  ASSERT_EQ(kSuccess, sm_->GetPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  SignedValue gp_res;
  ASSERT_TRUE(gp_res.ParseFromString(res[0]));
  ASSERT_EQ(gp.value(), gp_res.value());
  ASSERT_TRUE(crypto::AsymCheckSig(gp.value(),
                                   gp_res.value_signature(),
                                   anmaid_public_key_));
}

TEST_F(LocalStoreManagerTest, BEH_DeleteSystemPacketOwner) {
  SignedValue gp;
  gp.set_value("Generic System Packet Data");
  gp.set_value_signature(crypto::AsymSign(gp.value(), anmaid_private_key_));
  std::string gp_name = crypto::Hash<crypto::SHA512>(gp.value() +
                                                     gp.value_signature());

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.value(), passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  ASSERT_FALSE(sm_->KeyUnique(gp_name, false));

  std::vector<std::string> values(1, gp.value());
  cb_.Reset();
  sm_->DeletePacket(gp_name, values, passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  ASSERT_TRUE(sm_->KeyUnique(gp_name, false));
}

TEST_F(LocalStoreManagerTest, BEH_DeleteSystemPacketNotOwner) {
  SignedValue gp;
  gp.set_value("Generic System Packet Data");
  gp.set_value_signature(crypto::AsymSign(gp.value(), anmaid_private_key_));
  std::string gp_name = crypto::Hash<crypto::SHA512>(gp.value() +
                                                     gp.value_signature());

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.value(), passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
  ASSERT_FALSE(sm_->KeyUnique(gp_name, false));

  std::vector<std::string> values(1, gp.value());

  // Overwrite original signature packets
//  ss_->passport_ = std::shared_ptr<passport::Passport>(
//                       new passport::Passport(io_service_, kRsaKeySize));
//  ss_->passport_->Init();
  ss_->CreateTestPackets("");

  cb_.Reset();
  sm_->DeletePacket(gp_name, values, passport::MAID, PRIVATE, "", functor_);
  ASSERT_NE(kSuccess, cb_.WaitForIntResult());
  ASSERT_FALSE(sm_->KeyUnique(gp_name, false));
}

TEST_F(LocalStoreManagerTest, BEH_UpdatePacket) {
  // Store one packet
  SignedValue gp;
  gp.set_value("Generic System Packet Data");
  gp.set_value_signature(crypto::AsymSign(gp.value(), anmaid_private_key_));
  std::string gp_name(crypto::Hash<crypto::SHA512>(gp.value() +
                                                   gp.value_signature()));

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.value(), passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  std::vector<std::string> res;
  ASSERT_EQ(kSuccess, sm_->GetPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  SignedValue gp_res;
  ASSERT_TRUE(gp_res.ParseFromString(res[0]));
  ASSERT_EQ(gp.value(), gp_res.value());
  ASSERT_TRUE(crypto::AsymCheckSig(gp.value(),
                                   gp_res.value_signature(),
                                   anmaid_public_key_));

  // Update the packet
  SignedValue new_gp;
  new_gp.set_value("First value change");
  new_gp.set_value_signature(crypto::AsymSign(new_gp.value(),
                                              anmaid_private_key_));
  cb_.Reset();
  sm_->UpdatePacket(gp_name, gp.value(), new_gp.value(), passport::MAID,
                    PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
  res.clear();
  ASSERT_EQ(kSuccess, sm_->GetPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  gp_res.Clear();
  ASSERT_TRUE(gp_res.ParseFromString(res[0]));
  ASSERT_EQ(new_gp.value(), gp_res.value());
  ASSERT_TRUE(crypto::AsymCheckSig(new_gp.value(),
                                   gp_res.value_signature(),
                                   anmaid_public_key_));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
