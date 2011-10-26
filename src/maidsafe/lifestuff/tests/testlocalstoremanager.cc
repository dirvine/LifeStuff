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

#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

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
#include "maidsafe/lifestuff/session.h"
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
        ss_(new Session),
        sm_(new LocalStoreManager(*test_root_dir_, ss_)),
        cb_(),
        functor_(),
        anmaid_private_key_(),
        anmaid_public_key_(),
        mpid_public_key_() {
    DLOG(INFO) << "-1";
  }

  ~LocalStoreManagerTest() {}

 protected:
  void SetUp() {
    ss_->ResetSession();

    DLOG(INFO) << "00000000";
    sm_->Init(std::bind(&CallbackObject::IntCallback, &cb_, arg::_1), 0);
    if (cb_.WaitForIntResult() != kSuccess) {
      FAIL();
      return;
    }
    DLOG(INFO) << "11111111";

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
  std::shared_ptr<Session> ss_;
  std::shared_ptr<LocalStoreManager> sm_;
  CallbackObject cb_;
  std::function<void(int)> functor_;  // NOLINT
  std::string anmaid_private_key_, anmaid_public_key_, mpid_public_key_;

 private:
  LocalStoreManagerTest(const LocalStoreManagerTest&);
  LocalStoreManagerTest &operator=(const LocalStoreManagerTest&);
};

TEST_F(LocalStoreManagerTest, BEH_KeyUnique) {
  GenericPacket gp;
  std::string gp_name(crypto::Hash<crypto::SHA512>("aaa"));
  DLOG(INFO) << "CCCCCCC";
  ASSERT_TRUE(sm_->KeyUnique(gp_name, false));
  sm_->KeyUnique(gp_name, false, functor_);
  DLOG(INFO) << "AAAAAAA";
  ASSERT_EQ(kKeyUnique, cb_.WaitForIntResult());
  DLOG(INFO) << "BBBBBBB";

  gp.set_data("Generic System Packet Data");
  cb_.Reset();
  sm_->StorePacket(gp_name, gp.data(), passport::MAID, PRIVATE, "",
                   functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  ASSERT_FALSE(sm_->KeyUnique(gp_name, false));
  sm_->KeyUnique(gp_name, false, functor_);
  ASSERT_EQ(kKeyNotUnique, cb_.WaitForIntResult());
}

TEST_F(LocalStoreManagerTest, BEH_StoreSystemPacket) {
  GenericPacket gp;
  gp.set_data("Generic System Packet Data");
  gp.set_signature(crypto::AsymSign(gp.data(), anmaid_private_key_));
  std::string gp_name = crypto::Hash<crypto::SHA512>(gp.data() +
                                                     gp.signature());
  ASSERT_TRUE(sm_->KeyUnique(gp_name, false));
  cb_.Reset();
  sm_->StorePacket(gp_name, gp.data(), passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
  ASSERT_FALSE(sm_->KeyUnique(gp_name, false));

  std::vector<std::string> res;
  ASSERT_EQ(kSuccess, sm_->GetPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  GenericPacket gp_res;
  ASSERT_TRUE(gp_res.ParseFromString(res[0]));
  ASSERT_EQ(gp.data(), gp_res.data());
  ASSERT_TRUE(crypto::AsymCheckSig(gp.data(),
                                   gp_res.signature(),
                                   anmaid_public_key_));
}

TEST_F(LocalStoreManagerTest, BEH_DeleteSystemPacketOwner) {
  GenericPacket gp;
  gp.set_data("Generic System Packet Data");
  gp.set_signature(crypto::AsymSign(gp.data(), anmaid_private_key_));
  std::string gp_name = crypto::Hash<crypto::SHA512>(gp.data() +
                                                     gp.signature());

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.data(), passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  ASSERT_FALSE(sm_->KeyUnique(gp_name, false));

  std::vector<std::string> values(1, gp.data());
  cb_.Reset();
  sm_->DeletePacket(gp_name, values, passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  ASSERT_TRUE(sm_->KeyUnique(gp_name, false));
}

TEST_F(LocalStoreManagerTest, BEH_DeleteSystemPacketNotOwner) {
  GenericPacket gp;
  gp.set_data("Generic System Packet Data");
  gp.set_signature(crypto::AsymSign(gp.data(), anmaid_private_key_));
  std::string gp_name = crypto::Hash<crypto::SHA512>(gp.data() +
                                                     gp.signature());

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.data(), passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
  ASSERT_FALSE(sm_->KeyUnique(gp_name, false));

  std::vector<std::string> values(1, gp.data());

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

TEST_F(LocalStoreManagerTest, BEH_UpdateSystemPacket) {
  // Store one packet
  GenericPacket gp;
  gp.set_data("Generic System Packet Data");
  gp.set_signature(crypto::AsymSign(gp.data(), anmaid_private_key_));
  std::string gp_name(crypto::Hash<crypto::SHA512>(gp.data() +
                                                   gp.signature()));

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.data(), passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  std::vector<std::string> res;
  ASSERT_EQ(kSuccess, sm_->GetPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  GenericPacket gp_res;
  ASSERT_TRUE(gp_res.ParseFromString(res[0]));
  ASSERT_EQ(gp.data(), gp_res.data());
  ASSERT_TRUE(crypto::AsymCheckSig(gp.data(),
                                   gp_res.signature(),
                                   anmaid_public_key_));

  // Update the packet
  GenericPacket new_gp;
  new_gp.set_data("First value change");
  new_gp.set_signature(crypto::AsymSign(new_gp.data(),
                                              anmaid_private_key_));
  cb_.Reset();
  sm_->UpdatePacket(gp_name, gp.data(), new_gp.data(), passport::MAID,
                    PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
  res.clear();
  ASSERT_EQ(kSuccess, sm_->GetPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  gp_res.Clear();
  ASSERT_TRUE(gp_res.ParseFromString(res[0]));
  ASSERT_EQ(new_gp.data(), gp_res.data());
  ASSERT_TRUE(crypto::AsymCheckSig(new_gp.data(),
                                   gp_res.signature(),
                                   anmaid_public_key_));
}

TEST_F(LocalStoreManagerTest, BEH_UpdateSystemPacketNotOwner) {
  // Store one packet
  GenericPacket gp;
  gp.set_data("Generic System Packet Data");
  gp.set_signature(crypto::AsymSign(gp.data(), anmaid_private_key_));
  std::string gp_name(crypto::Hash<crypto::SHA512>(gp.data() +
                                                   gp.signature()));

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.data(), passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  std::vector<std::string> res;
  ASSERT_EQ(kSuccess, sm_->GetPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  GenericPacket gp_res;
  ASSERT_TRUE(gp_res.ParseFromString(res[0]));
  ASSERT_EQ(gp.data(), gp_res.data());
  ASSERT_TRUE(crypto::AsymCheckSig(gp.data(),
                                   gp_res.signature(),
                                   anmaid_public_key_));

  // Create different credentials
  ss_->CreateTestPackets("");

  // Update the packet
  GenericPacket new_gp;
  new_gp.set_data("First value change");
  new_gp.set_signature(crypto::AsymSign(new_gp.data(),
                                              anmaid_private_key_));
  cb_.Reset();
  sm_->UpdatePacket(gp_name, gp.data(), new_gp.data(), passport::MAID,
                    PRIVATE, "", functor_);
  ASSERT_EQ(kStoreManagerError, cb_.WaitForIntResult());

  res.clear();
  ASSERT_EQ(kSuccess, sm_->GetPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  gp_res.Clear();
  ASSERT_TRUE(gp_res.ParseFromString(res[0]));
  ASSERT_EQ(gp.data(), gp_res.data());
  ASSERT_TRUE(crypto::AsymCheckSig(gp.data(),
                                   gp_res.signature(),
                                   anmaid_public_key_));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
