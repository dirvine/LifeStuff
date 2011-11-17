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

#include "maidsafe/lifestuff/data_handler.h"
#include "maidsafe/lifestuff/local_store_manager.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/tests/test_callback.h"

namespace arg = std::placeholders;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

namespace test {

class LocalStoreManagerTest : public testing::Test {
 public:
  LocalStoreManagerTest()
      : test_root_dir_(maidsafe::test::CreateTestPath()),
        ss_(new Session),
        sm_(new LocalStoreManager(*test_root_dir_, ss_)),
        cb_(),
        functor_(),
        get_functor_(),
        anmaid_private_key_(),
        anmaid_public_key_(),
        mpid_public_key_() {}

  ~LocalStoreManagerTest() {}

  void OperationLine(const std::string& gp_value,
                     const std::string& new_gp_value,
                     std::shared_ptr<CallbackObject> cb,
                     std::shared_ptr<bool> thread_fail,
                     std::shared_ptr<std::string> res_msg) {
    std::function<void(int)> functor(std::bind(&CallbackObject::IntCallback,  // NOLINT (Viv)
                                               cb, arg::_1));
    GenericPacket gp;
    gp.set_data(gp_value);
    gp.set_signature(crypto::AsymSign(gp.data(), anmaid_private_key_));
    gp.set_hashable(false);
    gp.set_signing_id(ss_->Id(passport::kAnmaid, true));
    std::string gp_name(crypto::Hash<crypto::SHA512>(gp.data() +
                                                     gp.signature()));
    // Section 1 - Check For Unique Key
    if (!sm_->KeyUnique(gp_name)) {
      *res_msg = "1 - Not Unique Key";
      *thread_fail = true;
      return;
    }

    // Section 2 - Store Packet
    sm_->StorePacket(gp_name, gp.SerializeAsString(), functor);
    if ((kSuccess != cb->WaitForIntResult()) ||
        (sm_->KeyUnique(gp_name))) {
      *res_msg = "2 - Store Packet Unsuccessful";
      *thread_fail = true;
      return;
    }

    // Section 2 - Retrieve Packet and Check val
    std::vector<std::string> res;
    if ((kSuccess != sm_->GetPacket(gp_name, &res)) ||
        (size_t(1) != res.size())) {
      *res_msg = "2 - Retrieve Packet Unsuccessful";
      *thread_fail = true;
      return;
    }
    GenericPacket gp_res;
    if (!gp_res.ParseFromString(res[0]) ||
        gp.data() != gp_res.data() ||
        !crypto::AsymCheckSig(gp.data(),
                              gp_res.signature(),
                              anmaid_public_key_)) {
      *res_msg = "2 - Validation on Retrieved Packet Unsuccessful";
      *thread_fail = true;
      return;
    }

    // Section 3 - Update Packet as Owner and Check val
    GenericPacket new_gp;
    new_gp.set_data(new_gp_value);
    new_gp.set_signature(crypto::AsymSign(new_gp.data(), anmaid_private_key_));
    new_gp.set_hashable(false);
    new_gp.set_signing_id(ss_->Id(passport::kAnmaid, true));
    sm_->UpdatePacket(gp_name,
                      gp.SerializeAsString(),
                      new_gp.SerializeAsString(),
                      functor);
    res.clear();
    gp_res.Clear();
    if (kSuccess != cb->WaitForIntResult()) {
      *res_msg = "3 - Packet Update Failed as Owner";
      *thread_fail = true;
      return;
    }
    if ((kSuccess != sm_->GetPacket(gp_name, &res)) ||
        (size_t(1) != res.size()) ||
        (!gp_res.ParseFromString(res[0])) ||
        (new_gp.data() != gp_res.data()) ||
        (!crypto::AsymCheckSig(new_gp.data(),
                               gp_res.signature(),
                               anmaid_public_key_))) {
      *res_msg = "3 - Packet Update Validation Unsuccessful";
      *thread_fail = true;
      return;
    }

    // Secion 4 - Delete Packet as Owner and Check val
    sm_->DeletePacket(gp_name, gp.SerializeAsString(), functor);
    if  (kSuccess != cb->WaitForIntResult()) {
      *res_msg = "4 - Packet Delete Failed as Owner";
      *thread_fail = true;
      return;
    }
    if  (!sm_->KeyUnique(gp_name)) {
      *res_msg = "4 - Packet Exists after Delete as Owner";
      *thread_fail = true;
      return;
    }
  }

 protected:
  void SetUp() {
    ss_->ResetSession();

    sm_->Init(std::bind(&CallbackObject::IntCallback, &cb_, arg::_1));
    if (cb_.WaitForIntResult() != kSuccess) {
      FAIL();
      return;
    }

    ss_->ResetSession();
    ASSERT_TRUE(ss_->CreateTestPackets("Me"));
    cb_.Reset();
    functor_ = std::bind(&CallbackObject::IntCallback, &cb_, arg::_1);
    get_functor_ = std::bind(&CallbackObject::GetPacketCallback,
                             &cb_,
                             arg::_1,
                             arg::_2);
    anmaid_private_key_ = ss_->PrivateKey(passport::kAnmaid, true);
    anmaid_public_key_ = ss_->PublicKey(passport::kAnmaid, true);
    mpid_public_key_ = ss_->PublicKey(passport::MPID, true);
  }

  void TearDown() {
    ss_->ResetSession();
    cb_.Reset();
    sm_->Close(true);
    ss_->passport_->StopCreatingKeyPairs();
  }

  void GeneratePacket(bool hashable, std::string *name, GenericPacket *gp) {
    gp->set_data(anmaid_public_key_);
    gp->set_signature(ss_->PublicKeySignature(passport::kAnmaid, true));
    gp->set_hashable(hashable);
    *name = crypto::Hash<crypto::SHA512>(gp->data() + gp->signature());
    gp->set_signing_id(ss_->Id(passport::kAnmaid, true));
  }

  std::shared_ptr<fs::path> test_root_dir_;
  std::shared_ptr<Session> ss_;
  std::shared_ptr<LocalStoreManager> sm_;
  CallbackObject cb_;
  std::function<void(int)> functor_;  // NOLINT (Dan)
  std::function<void(const std::vector<std::string>&, int)> get_functor_;
  std::string anmaid_private_key_, anmaid_public_key_, mpid_public_key_;

 private:
  LocalStoreManagerTest(const LocalStoreManagerTest&);
  LocalStoreManagerTest &operator=(const LocalStoreManagerTest&);
};

TEST_F(LocalStoreManagerTest, BEH_KeyUnique) {
  GenericPacket gp;
  std::string gp_name;
  GeneratePacket(true, &gp_name, &gp);

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
  GeneratePacket(true, &gp_name, &gp);
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
  ASSERT_TRUE(crypto::AsymCheckSig(gp.data(),
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
  ASSERT_TRUE(crypto::AsymCheckSig(gp.data(),
                                   gp_res2.signature(),
                                   anmaid_public_key_));
}

TEST_F(LocalStoreManagerTest, BEH_StoreSystemPacket) {
  GenericPacket gp;
  std::string gp_name;
  GeneratePacket(true, &gp_name, &gp);
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
  ASSERT_TRUE(crypto::AsymCheckSig(gp.data(),
                                   gp_res.signature(),
                                   anmaid_public_key_));
}

TEST_F(LocalStoreManagerTest, BEH_DeleteSystemPacketOwner) {
  GenericPacket gp;
  std::string gp_name;
  GeneratePacket(true, &gp_name, &gp);

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
  GeneratePacket(true, &gp_name, &gp);

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.SerializeAsString(), functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForIntResult());
  ASSERT_FALSE(sm_->KeyUnique(gp_name));

  std::vector<std::string> values(1, gp.data());

  // Overwrite original signature packets
  ss_->CreateTestPackets("");

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
  ASSERT_TRUE(crypto::AsymCheckSig(gp.data(),
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
  ASSERT_TRUE(crypto::AsymCheckSig(new_gp.data(),
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
  ASSERT_TRUE(crypto::AsymCheckSig(gp.data(),
                                   gp_res.signature(),
                                   anmaid_public_key_));

  // Create different credentials
  ss_->CreateTestPackets("");

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
  ASSERT_TRUE(crypto::AsymCheckSig(gp.data(),
                                   gp_res.signature(),
                                   anmaid_public_key_));
}

TEST_F(LocalStoreManagerTest, FUNC_ThreadedLocalStoreManager) {
  const size_t kNumThreads(7);
  std::set<std::string> gp_values;
  while (gp_values.size() < kNumThreads * 2)
    gp_values.insert(maidsafe::RandomAlphaNumericString(kNumThreads));

  std::set<std::string>::iterator gp_values_terminal(gp_values.begin());
  std::advance(gp_values_terminal, kNumThreads);
  std::vector<std::shared_ptr<CallbackObject>> cbo;
  std::vector<std::shared_ptr<bool>> threads_fail_state;
  threads_fail_state.reserve(kNumThreads);
  std::vector<std::shared_ptr<std::string>> threads_result;
  threads_result.reserve(kNumThreads);

  for (size_t i = 0; i < kNumThreads; ++i) {
    cbo.push_back(std::shared_ptr<CallbackObject>(new CallbackObject()));
    threads_fail_state.push_back(std::shared_ptr<bool>(new bool(false)));
    threads_result.push_back(std::shared_ptr<std::string>(new std::string()));
  }

  boost::thread_group worker_group;
  size_t thread_num(0);
  for (auto it(gp_values.begin());
       it != gp_values_terminal;
       ++it, ++thread_num) {
    std::set<std::string>::iterator itr = it;
    std::advance(itr, kNumThreads);
    worker_group.create_thread(std::bind(&LocalStoreManagerTest::OperationLine,
                                         this,
                                         *it,
                                         *itr,
                                         cbo[thread_num],
                                         threads_fail_state[thread_num],
                                         threads_result[thread_num]));
  }
  worker_group.join_all();
  for (size_t i = 0; i < kNumThreads; ++i) {
    DLOG(INFO) << "Checking Exit Status of Thread: " << i + 1;
    ASSERT_FALSE(*threads_fail_state[i]) << "Error in Section "
                                         << threads_result[i];
  }
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
