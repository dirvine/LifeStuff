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

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/store_components/local_store_manager.h"
#include "maidsafe/lifestuff/tests/test_callback.h"

namespace args = std::placeholders;
namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;

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
        anmid_public_key_(),
        encoded_anmaid_public_key_(),
        anmaid_name_(),
        anmid_name_() {}

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
    anmid_public_key_ =
        session_->passport_->SignaturePacketValue(passport::kAnmid, true);
    asymm::EncodePublicKey(anmaid_public_key_, &encoded_anmaid_public_key_);
    ASSERT_FALSE(encoded_anmaid_public_key_.empty());
    anmaid_name_ = session_->passport_->PacketName(passport::kAnmaid, true);
    anmid_name_ = session_->passport_->PacketName(passport::kAnmid, true);
  }

  void TearDown() {
    session_->ResetSession();
    cb_.Reset();
    sm_->Close(true);
  }

  void GeneratePacket(std::string *name, pca::SignedData *signed_data) {
    signed_data->set_data(encoded_anmaid_public_key_);
    signed_data->set_signature(
        session_->passport_->PacketSignature(passport::kAnmaid, true));
    *name = session_->passport_->PacketName(passport::kAnmaid, true) +
            std::string(1, pca::kSignaturePacket);
  }

  void GenerateModifiablePacket(std::string *name,
                                pca::SignedData *signed_data) {
    signed_data->set_data(RandomString(512));
    asymm::PrivateKey anmid_private_key(session_->passport_->PacketPrivateKey(
                                            passport::kAnmid, true));
    asymm::Signature mid_signature;
    ASSERT_EQ(kSuccess, asymm::Sign(signed_data->data(),
                                    anmid_private_key,
                                    &mid_signature));
    signed_data->set_signature(mid_signature);
    *name = *name + std::string(1, pca::kModifiableByOwner);
  }

  void CreateTestPacketsInSession() { session_->CreateTestPackets(); }

  std::shared_ptr<fs::path> test_root_dir_;
  std::shared_ptr<Session> session_;
  std::shared_ptr<LocalStoreManager> sm_;
  CallbackObject cb_;
  std::function<void(int)> functor_;  // NOLINT (Dan)
  std::function<void(const std::vector<std::string>&, int)> get_functor_;
  asymm::PublicKey anmaid_public_key_, anmid_public_key_;
  std::string encoded_anmaid_public_key_, anmaid_name_, anmid_name_;

 private:
  LocalStoreManagerTest(const LocalStoreManagerTest&);
  LocalStoreManagerTest &operator=(const LocalStoreManagerTest&);
};

TEST_F(LocalStoreManagerTest, BEH_KeyUnique) {
  pca::SignedData signed_data;
  std::string packet_name;
  GeneratePacket(&packet_name, &signed_data);

  ASSERT_TRUE(sm_->KeyUnique(packet_name, anmaid_name_));
  sm_->KeyUnique(packet_name, anmaid_name_, functor_);
  ASSERT_EQ(kKeyUnique, cb_.WaitForIntResult());

  cb_.Reset();
  sm_->StorePacket(packet_name,
                   signed_data.SerializeAsString(),
                   anmaid_name_,
                   functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  ASSERT_FALSE(sm_->KeyUnique(packet_name, anmaid_name_));
  sm_->KeyUnique(packet_name, anmaid_name_, functor_);
  ASSERT_EQ(kKeyNotUnique, cb_.WaitForIntResult());
}

TEST_F(LocalStoreManagerTest, BEH_GetPacket) {
  pca::SignedData signed_data;
  std::string packet_name;
  GeneratePacket(&packet_name, &signed_data);
  ASSERT_TRUE(sm_->KeyUnique(packet_name, anmaid_name_));

  cb_.Reset();
  sm_->StorePacket(packet_name,
                   signed_data.SerializeAsString(),
                   anmaid_name_,
                   functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
  ASSERT_FALSE(sm_->KeyUnique(packet_name, anmaid_name_));
  std::vector<std::string> res;

  // Test Blocking GetPacket Func
  ASSERT_EQ(kSuccess, sm_->GetPacket(packet_name, anmaid_name_, &res));
  ASSERT_EQ(size_t(1), res.size());
  pca::SignedData res_signed_data;
  ASSERT_TRUE(res_signed_data.ParseFromString(res[0]));
  ASSERT_EQ(signed_data.data(), res_signed_data.data());
  ASSERT_EQ(kSuccess, asymm::CheckSignature(signed_data.data(),
                                            res_signed_data.signature(),
                                            anmaid_public_key_));

  // Test Non-Blocking GetPacket Func
  sm_->GetPacket(packet_name, anmaid_name_, get_functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForGetPacketCallbackResult());
  std::vector<std::string> results(cb_.get_packet_results());
  ASSERT_EQ(size_t(1), results.size());
  pca::SignedData res_signed_data2;
  ASSERT_TRUE(res_signed_data2.ParseFromString(results[0]));
  ASSERT_EQ(signed_data.data(), res_signed_data2.data());
  ASSERT_EQ(kSuccess, asymm::CheckSignature(signed_data.data(),
                                            res_signed_data2.signature(),
                                            anmaid_public_key_));
}

TEST_F(LocalStoreManagerTest, BEH_StoreSystemPacket) {
  pca::SignedData signed_data;
  std::string packet_name;
  GeneratePacket(&packet_name, &signed_data);
  ASSERT_TRUE(sm_->KeyUnique(packet_name, anmaid_name_));

  cb_.Reset();
  sm_->StorePacket(packet_name,
                   signed_data.SerializeAsString(),
                   anmaid_name_,
                   functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
  ASSERT_FALSE(sm_->KeyUnique(packet_name, anmaid_name_));

  std::vector<std::string> res;
  ASSERT_EQ(kSuccess, sm_->GetPacket(packet_name, anmaid_name_, &res));
  ASSERT_EQ(size_t(1), res.size());
  pca::SignedData res_signed_data;
  ASSERT_TRUE(res_signed_data.ParseFromString(res[0]));
  ASSERT_EQ(signed_data.data(), res_signed_data.data());
  ASSERT_EQ(kSuccess, asymm::CheckSignature(signed_data.data(),
                                            res_signed_data.signature(),
                                            anmaid_public_key_));
}

TEST_F(LocalStoreManagerTest, BEH_DeleteSystemPacketOwner) {
  pca::SignedData signed_data;
  std::string packet_name;
  GeneratePacket(&packet_name, &signed_data);

  cb_.Reset();
  sm_->StorePacket(packet_name,
                   signed_data.SerializeAsString(),
                   anmaid_name_,
                   functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  ASSERT_FALSE(sm_->KeyUnique(packet_name, anmaid_name_));

  cb_.Reset();
  sm_->DeletePacket(packet_name, anmaid_name_, functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  ASSERT_FALSE(sm_->KeyUnique(packet_name, anmaid_name_));

  std::vector<std::string> res;
  ASSERT_EQ(kSuccess, sm_->GetPacket(packet_name, anmaid_name_, &res));
  ASSERT_EQ(size_t(1), res.size());
  ASSERT_EQ("0", res.at(0));
}

TEST_F(LocalStoreManagerTest, BEH_DeleteSystemPacketNotOwner) {
  pca::SignedData signed_data;
  std::string packet_name;
  GeneratePacket(&packet_name, &signed_data);

  cb_.Reset();
  sm_->StorePacket(packet_name,
                   signed_data.SerializeAsString(),
                   anmaid_name_,
                   functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
  ASSERT_FALSE(sm_->KeyUnique(packet_name, anmaid_name_));

  std::vector<std::string> values(1, signed_data.data());

  // Overwrite original signature packets
  CreateTestPacketsInSession();

  cb_.Reset();
  sm_->DeletePacket(packet_name, anmaid_name_, functor_);
  ASSERT_NE(kSuccess, cb_.WaitForIntResult());
  ASSERT_FALSE(sm_->KeyUnique(packet_name, anmaid_name_));
}

TEST_F(LocalStoreManagerTest, BEH_ModifySystemPacket) {
  // Store one packet
  pca::SignedData signed_data;
  std::string packet_name(RandomString(64));
  GenerateModifiablePacket(&packet_name, &signed_data);

  cb_.Reset();
  sm_->StorePacket(packet_name,
                   signed_data.SerializeAsString(),
                   anmid_name_,
                   functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  std::vector<std::string> res;
  ASSERT_EQ(kSuccess, sm_->GetPacket(packet_name, anmid_name_, &res));
  ASSERT_EQ(size_t(1), res.size());
  pca::SignedData res_signed_data;
  ASSERT_TRUE(res_signed_data.ParseFromString(res[0]));
  ASSERT_EQ(signed_data.data(), res_signed_data.data());
  ASSERT_EQ(kSuccess, asymm::CheckSignature(signed_data.data(),
                                            res_signed_data.signature(),
                                            anmid_public_key_));

  // Update the packet
  cb_.Reset();
  pca::SignedData new_signed_data;
  std::string s;
  GenerateModifiablePacket(&s, &new_signed_data);
  sm_->ModifyPacket(packet_name,
                    new_signed_data.SerializeAsString(),
                    anmid_name_,
                    functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
  res.clear();

  ASSERT_EQ(kSuccess, sm_->GetPacket(packet_name, anmid_name_, &res));
  ASSERT_EQ(size_t(1), res.size());
  res_signed_data.Clear();
  ASSERT_TRUE(res_signed_data.ParseFromString(res[0]));
  ASSERT_EQ(new_signed_data.data(), res_signed_data.data());
  ASSERT_EQ(kSuccess, asymm::CheckSignature(new_signed_data.data(),
                                            res_signed_data.signature(),
                                            anmid_public_key_));
}

TEST_F(LocalStoreManagerTest, BEH_ModifySystemPacketNotOwner) {
  // Store one packet
  pca::SignedData signed_data;
  std::string packet_name(RandomString(64));
  GenerateModifiablePacket(&packet_name, &signed_data);

  cb_.Reset();
  sm_->StorePacket(packet_name,
                   signed_data.SerializeAsString(),
                   anmid_name_,
                   functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());

  std::vector<std::string> res;
  ASSERT_EQ(kSuccess, sm_->GetPacket(packet_name, anmid_name_, &res));
  ASSERT_EQ(size_t(1), res.size());
  pca::SignedData res_signed_data;
  ASSERT_TRUE(res_signed_data.ParseFromString(res[0]));
  ASSERT_EQ(signed_data.data(), res_signed_data.data());
  ASSERT_EQ(kSuccess, asymm::CheckSignature(signed_data.data(),
                                            res_signed_data.signature(),
                                            anmid_public_key_));

  // Create different credentials
  CreateTestPacketsInSession();

  // Update the packet
  pca::SignedData new_signed_data;
  std::string s;
  GenerateModifiablePacket(&s, &new_signed_data);
  cb_.Reset();
  sm_->ModifyPacket(packet_name,
                    new_signed_data.SerializeAsString(),
                    anmid_name_,
                    functor_);
  ASSERT_NE(kSuccess, cb_.WaitForIntResult());

  res.clear();
  ASSERT_EQ(kSuccess, sm_->GetPacket(packet_name, anmid_name_, &res));
  ASSERT_EQ(size_t(1), res.size());
  res_signed_data.Clear();
  ASSERT_TRUE(res_signed_data.ParseFromString(res[0]));
  ASSERT_EQ(signed_data.data(), res_signed_data.data());
  ASSERT_EQ(kSuccess, asymm::CheckSignature(signed_data.data(),
                                            res_signed_data.signature(),
                                            anmid_public_key_));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
