/*
 * ============================================================================
 *
 * Copyright [2010] maidsafe.net limited
 *
 * Description:  Test MaidsafeValidator Class
 * Version:      1.0
 * Created:      2010-01-06
 * Revision:     none
 * Compiler:     gcc
 * Author:       Jose Cisnertos
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

#include <gtest/gtest.h>

#include "maidsafe-dht/common/crypto.h"
#include "maidsafe-dht/common/utils.h"

#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/returncodes.h"
#include "maidsafe/pki/maidsafevalidator.h"
#include "maidsafe/pki/packet.h"

namespace maidsafe {

namespace pki {

namespace test {

class MSValidatorTest : public testing::Test {
 public:
  MSValidatorTest() : signed_public_key_(), validator_(), keys_() {}
 protected:
  void SetUp() {
    crypto::RsaKeyPair rsakp;
    keys_.push_back(rsakp);
    keys_.at(0).GenerateKeys(4096);
    keys_.push_back(rsakp);
    keys_.at(1).GenerateKeys(4096);
    signed_public_key_ = crypto::AsymSign(keys_.at(0).public_key(),
                                          keys_.at(0).private_key());
  }
  std::string signed_public_key_;
  MaidsafeValidator validator_;
  std::vector<crypto::RsaKeyPair> keys_;
};

TEST_F(MSValidatorTest, BEH_PKI_TestValidateSignerID) {
  std::string id(crypto::Hash<crypto::SHA512>(keys_.at(0).public_key() +
                                              signed_public_key_));
  ASSERT_TRUE(validator_.ValidateSignerId(id, keys_.at(0).public_key(),
                                          signed_public_key_));
  ASSERT_FALSE(validator_.ValidateSignerId(id, keys_.at(1).public_key(),
                                           signed_public_key_));
  ASSERT_FALSE(validator_.ValidateSignerId("invalid id",
      keys_.at(0).public_key(), signed_public_key_));
}

TEST_F(MSValidatorTest, BEH_PKI_TestValidateSignedRequest) {
  std::string rec_id(crypto::Hash<crypto::SHA512>(RandomString(10)));
//  validator_.set_id(rec_id);
  std::string key(crypto::Hash<crypto::SHA512>(RandomString(10)));
  std::string signed_request(crypto::AsymSign(
      crypto::Hash<crypto::SHA512>(keys_.at(0).public_key() + signed_public_key_
                                   + key),
      keys_.at(0).private_key()));
  ASSERT_TRUE(validator_.ValidateRequest(signed_request,
                                         keys_.at(0).public_key(),
                                         signed_public_key_, key));
  ASSERT_FALSE(validator_.ValidateRequest(signed_request,
                                          keys_.at(1).public_key(),
                                          signed_public_key_, key));
  ASSERT_FALSE(validator_.ValidateRequest("invalid signed request",
                                          keys_.at(1).public_key(),
                                          signed_public_key_, key));
  ASSERT_FALSE(validator_.ValidateRequest(signed_request,
                                          keys_.at(0).public_key(),
                                          signed_public_key_, "key"));
}

TEST_F(MSValidatorTest, BEH_PKI_TestCreateRequestSignature) {
  std::list<std::string> params;
  std::string signature;
  ASSERT_EQ(kValidatorNoPrivateKey,
            validator_.CreateRequestSignature("", params, &signature));
  ASSERT_EQ(kValidatorNoParameters,
            validator_.CreateRequestSignature(keys_.at(0).private_key(), params,
                                              &signature));
  params.push_back(keys_.at(0).public_key());
  params.push_back(signed_public_key_);
  params.push_back("a");
  params.push_back("b");
  params.push_back("c");
  ASSERT_EQ(0, validator_.CreateRequestSignature(keys_.at(0).private_key(),
                                                 params, &signature));
//  validator_.set_id(a);
  ASSERT_TRUE(validator_.ValidateRequest(signature, keys_.at(0).public_key(),
                                         signed_public_key_, "abc"));
/*  ASSERT_EQ(0, validator_.CreateRequestSignature(keys_.at(0).private_key(),
                                                 params, &signature));
//  validator_.set_id("c");
  ASSERT_TRUE(validator_.ValidateRequest(signature, keys_.at(0).public_key(),
                                         "", "abc"));*/
}

}  // namespace test

}  // namespace pki

}  // namespace maidsafe
