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

#include "boost/signals2/connection.hpp"

#include "maidsafe/lifestuff/lifestuff_messages_pb.h"
#include "maidsafe/lifestuff/data_handler.h"
#include "maidsafe/lifestuff/store_components/local_store_manager.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/tests/test_callback.h"

namespace args = std::placeholders;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

namespace test {

class LocalStoreManagerTest : public testing::Test {
 public:
  LocalStoreManagerTest()
      : test_root_dir_(maidsafe::test::CreateTestPath()),
        session_(new Session),
        sm_(new LocalStoreManager(session_, test_root_dir_->string())),
        cb_(),
        functor_(),
        get_functor_(),
        anmaid_public_key_(),
        encoded_anmaid_public_key_() {}

  ~LocalStoreManagerTest() {}

 protected:
  void SetUp() {
    session_->ResetSession();

    sm_->Init(std::bind(&CallbackObject::IntCallback, &cb_, args::_1));
    if (cb_.WaitForIntResult() != kSuccess) {
      FAIL();
      return;
    }

    session_->ResetSession();
    ASSERT_TRUE(session_->CreateTestPackets());
    cb_.Reset();
    functor_ = std::bind(&CallbackObject::IntCallback, &cb_, args::_1);
    get_functor_ = std::bind(&CallbackObject::GetPacketCallback,
                             &cb_,
                             args::_1,
                             args::_2);
    anmaid_public_key_ =
        session_->passport_->SignaturePacketValue(passport::kAnmaid, true);
    asymm::EncodePublicKey(anmaid_public_key_, &encoded_anmaid_public_key_);
    ASSERT_FALSE(encoded_anmaid_public_key_.empty());
  }

  void TearDown() {
    session_->ResetSession();
    cb_.Reset();
    sm_->Close(true);
  }

  void GeneratePacket(bool hashable, std::string *name, GenericPacket *gp) {
    gp->set_data(encoded_anmaid_public_key_);
    gp->set_signature(session_->passport_->PacketSignature(passport::kAnmaid,
                                                           true));
    if (hashable)
      gp->set_type(0);
    else
      gp->set_type(1);
    *name = session_->passport_->PacketName(passport::kAnmaid, true);
    gp->set_signing_id(session_->passport_->PacketName(passport::kAnmaid,
                                                       true));
  }

  void CreateTestPacketsInSession() { session_->CreateTestPackets(); }

  std::shared_ptr<fs::path> test_root_dir_;
  std::shared_ptr<Session> session_;
  std::shared_ptr<LocalStoreManager> sm_;
  CallbackObject cb_;
  std::function<void(int)> functor_;  // NOLINT (Dan)
  std::function<void(const std::vector<std::string>&, int)> get_functor_;
  asymm::PublicKey anmaid_public_key_;
  std::string encoded_anmaid_public_key_;

 private:
  LocalStoreManagerTest(const LocalStoreManagerTest&);
  LocalStoreManagerTest &operator=(const LocalStoreManagerTest&);
};

TEST_F(LocalStoreManagerTest, BEH_KeyUnique) {
  GenericPacket gp;
  std::string gp_name;
  GeneratePacket(false, &gp_name, &gp);

  ASSERT_TRUE(sm_->KeyUnique(gp_name));
  sm_->KeyUnique(gp_name, functor_);
  ASSERT_EQ(kKeyUnique, cb_.WaitForIntResult());

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.SerializeAsString(), functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  ASSERT_FALSE(sm_->KeyUnique(gp_name));
  sm_->KeyUnique(gp_name, functor_);
  ASSERT_EQ(kKeyNotUnique, cb_.WaitForIntResult());
}

TEST_F(LocalStoreManagerTest, BEH_GetPacket) {
  GenericPacket gp;
  std::string gp_name;
  GeneratePacket(false, &gp_name, &gp);
  ASSERT_TRUE(sm_->KeyUnique(gp_name));

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.SerializeAsString(), functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
  ASSERT_FALSE(sm_->KeyUnique(gp_name));
  std::vector<std::string> res;

  // Test Blocking GetPacket Func
  ASSERT_EQ(kSuccess, sm_->GetPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  GenericPacket gp_res;
  ASSERT_TRUE(gp_res.ParseFromString(res[0]));
  ASSERT_EQ(gp.data(), gp_res.data());
  ASSERT_EQ(kSuccess, asymm::CheckSignature(gp.data(),
                                          gp_res.signature(),
                                          anmaid_public_key_));

  // Test Non-Blocking GetPacket Func
  sm_->GetPacket(gp_name, get_functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForGetPacketCallbackResult());
  std::vector<std::string> results(cb_.get_packet_results());
  ASSERT_EQ(size_t(1), results.size());
  GenericPacket gp_res2;
  ASSERT_TRUE(gp_res2.ParseFromString(results[0]));
  ASSERT_EQ(gp.data(), gp_res2.data());
  ASSERT_EQ(kSuccess, asymm::CheckSignature(gp.data(),
                                          gp_res2.signature(),
                                          anmaid_public_key_));
}

TEST_F(LocalStoreManagerTest, BEH_StoreSystemPacket) {
  GenericPacket gp;
  std::string gp_name;
  GeneratePacket(false, &gp_name, &gp);
  ASSERT_TRUE(sm_->KeyUnique(gp_name));

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.SerializeAsString(), functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
  ASSERT_FALSE(sm_->KeyUnique(gp_name));

  std::vector<std::string> res;
  ASSERT_EQ(kSuccess, sm_->GetPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  GenericPacket gp_res;
  ASSERT_TRUE(gp_res.ParseFromString(res[0]));
  ASSERT_EQ(gp.data(), gp_res.data());
  ASSERT_EQ(kSuccess, asymm::CheckSignature(gp.data(),
                                          gp_res.signature(),
                                          anmaid_public_key_));
}

TEST_F(LocalStoreManagerTest, BEH_DeleteSystemPacketOwner) {
  GenericPacket gp;
  std::string gp_name;
  GeneratePacket(false, &gp_name, &gp);

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.SerializeAsString(), functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  ASSERT_FALSE(sm_->KeyUnique(gp_name));

  std::vector<std::string> values(1, gp.data());
  cb_.Reset();
  sm_->DeletePacket(gp_name, gp.SerializeAsString(), functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  ASSERT_TRUE(sm_->KeyUnique(gp_name));
}

TEST_F(LocalStoreManagerTest, BEH_DeleteSystemPacketNotOwner) {
  GenericPacket gp;
  std::string gp_name;
  GeneratePacket(false, &gp_name, &gp);

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.SerializeAsString(), functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
  ASSERT_FALSE(sm_->KeyUnique(gp_name));

  std::vector<std::string> values(1, gp.data());

  // Overwrite original signature packets
  CreateTestPacketsInSession();

  cb_.Reset();
  sm_->DeletePacket(gp_name, gp.SerializeAsString(), functor_);
  ASSERT_NE(kSuccess, cb_.WaitForIntResult());
  ASSERT_FALSE(sm_->KeyUnique(gp_name));
}

TEST_F(LocalStoreManagerTest, BEH_UpdateSystemPacket) {
  // Store one packet
  GenericPacket gp;
  std::string gp_name;
  GeneratePacket(false, &gp_name, &gp);

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.SerializeAsString(), functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  std::vector<std::string> res;
  ASSERT_EQ(kSuccess, sm_->GetPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  GenericPacket gp_res;
  ASSERT_TRUE(gp_res.ParseFromString(res[0]));
  ASSERT_EQ(gp.data(), gp_res.data());
  ASSERT_EQ(kSuccess, asymm::CheckSignature(gp.data(),
                                          gp_res.signature(),
                                          anmaid_public_key_));

  // Update the packet
  cb_.Reset();
  GenericPacket new_gp;
  std::string s;
  GeneratePacket(false, &s, &new_gp);
  sm_->UpdatePacket(gp_name,
                    gp.SerializeAsString(),
                    new_gp.SerializeAsString(),
                    functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
  res.clear();

  ASSERT_EQ(kSuccess, sm_->GetPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  gp_res.Clear();
  ASSERT_TRUE(gp_res.ParseFromString(res[0]));
  ASSERT_EQ(new_gp.data(), gp_res.data());
  ASSERT_EQ(kSuccess, asymm::CheckSignature(new_gp.data(),
                                          gp_res.signature(),
                                          anmaid_public_key_));
}

TEST_F(LocalStoreManagerTest, BEH_UpdateSystemPacketNotOwner) {
  // Store one packet
  GenericPacket gp;
  std::string gp_name;
  GeneratePacket(false, &gp_name, &gp);

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.SerializeAsString(), functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  std::vector<std::string> res;
  ASSERT_EQ(kSuccess, sm_->GetPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  GenericPacket gp_res;
  ASSERT_TRUE(gp_res.ParseFromString(res[0]));
  ASSERT_EQ(gp.data(), gp_res.data());
  ASSERT_EQ(kSuccess, asymm::CheckSignature(gp.data(),
                                          gp_res.signature(),
                                          anmaid_public_key_));

  // Create different credentials
  CreateTestPacketsInSession();

  // Update the packet
  GenericPacket new_gp;
  std::string s;
  GeneratePacket(false, &s, &new_gp);
  cb_.Reset();
  sm_->UpdatePacket(gp_name,
                    gp.SerializeAsString(),
                    new_gp.SerializeAsString(),
                    functor_);
  ASSERT_NE(kSuccess, cb_.WaitForIntResult());

  res.clear();
  ASSERT_EQ(kSuccess, sm_->GetPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  gp_res.Clear();
  ASSERT_TRUE(gp_res.ParseFromString(res[0]));
  ASSERT_EQ(gp.data(), gp_res.data());
  ASSERT_EQ(kSuccess, asymm::CheckSignature(gp.data(),
                                          gp_res.signature(),
                                          anmaid_public_key_));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
