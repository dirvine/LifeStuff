/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
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

#include "maidsafe/lifestuff/utils.h"

#include <vector>

#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/store_components/packet_manager.h"

namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

int GetValidatedMpidPublicKey(const std::string &public_username,
                              const std::string &own_mpid_name,
                              std::shared_ptr<PacketManager> packet_manager,
                              asymm::PublicKey *public_key) {
  // Get public key packet from network
  std::string packet_name(crypto::Hash<crypto::SHA512>(public_username) +
                          std::string(1, pca::kAppendableByAll));
  std::vector<std::string> packet_values;
  int result(packet_manager->GetPacket(packet_name,
                                       own_mpid_name,
                                       &packet_values));
  if (result != kSuccess || packet_values.size() != 1U) {
    DLOG(ERROR) << "Failed to get public key for " << public_username;
    *public_key = asymm::PublicKey();
    return kGetPublicKeyFailure;
  }

  pca::SignedData packet;
  if (!packet.ParseFromString(packet_values.at(0))) {
    DLOG(ERROR) << "Failed to parse public key packet for " << public_username;
    *public_key = asymm::PublicKey();
    return kGetPublicKeyFailure;
  }
  BOOST_ASSERT(!packet.data().empty());
  BOOST_ASSERT(!packet.signature().empty());

  // Decode and validate public key
  std::string serialised_public_key(packet.data());
  std::string public_key_signature(packet.signature());
  asymm::DecodePublicKey(serialised_public_key, public_key);
  if (!asymm::ValidateKey(*public_key)) {
    DLOG(ERROR) << "Failed to validate public key for " << public_username;
    *public_key = asymm::PublicKey();
    return kGetPublicKeyFailure;
  }

  // Get corresponding MPID packet from network
  std::string mpid_value(serialised_public_key + public_key_signature);
  std::string mpid_name(crypto::Hash<crypto::SHA512>(mpid_value) +
                        std::string(1, pca::kSignaturePacket));
  packet_values.clear();
  result = packet_manager->GetPacket(mpid_name, own_mpid_name, &packet_values);
  if (result != kSuccess || packet_values.size() != 1U) {
    DLOG(ERROR) << "Failed to get MPID for " << public_username;
    *public_key = asymm::PublicKey();
    return kGetMpidFailure;
  }

  packet.Clear();
  if (!packet.ParseFromString(packet_values.at(0))) {
    DLOG(ERROR) << "Failed to parse MPID packet for " << public_username;
    *public_key = asymm::PublicKey();
    return kGetMpidFailure;
  }
  BOOST_ASSERT(!packet.data().empty());
  BOOST_ASSERT(!packet.signature().empty());

  // Check that public key packet matches MPID packet, and validate the
  // signature
  if (serialised_public_key != packet.data() ||
      public_key_signature != packet.signature()) {
    DLOG(ERROR) << "Public key doesn't match MPID for " << public_username;
    *public_key = asymm::PublicKey();
    return kInvalidPublicKey;
  }

  return kSuccess;
}

int GetValidatedMmidPublicKey(const std::string &mmid_name,
                              const std::string &own_mmid_name,
                              std::shared_ptr<PacketManager> packet_manager,
                              asymm::PublicKey *public_key) {
  std::vector<std::string> packet_values;
  int result(packet_manager->GetPacket(
                  mmid_name + std::string(1, pca::kAppendableByAll),
                  own_mmid_name,
                  &packet_values));
  if (result != kSuccess || packet_values.size() != 1U) {
    DLOG(ERROR) << "Failed to get public key for " << Base32Substr(mmid_name);
    *public_key = asymm::PublicKey();
    return kGetPublicKeyFailure;
  }

  pca::SignedData packet;
  if (!packet.ParseFromString(packet_values.at(0))) {
    DLOG(ERROR) << "Failed to parse public key packet for "
                << Base32Substr(mmid_name);
    *public_key = asymm::PublicKey();
    return kGetPublicKeyFailure;
  }
  BOOST_ASSERT(!packet.data().empty());
  BOOST_ASSERT(!packet.signature().empty());

  // Validate self-signing
  if (crypto::Hash<crypto::SHA512>(packet.data() + packet.signature()) !=
      mmid_name) {
    DLOG(ERROR) << "Failed to validate MMID " << Base32Substr(mmid_name);
    *public_key = asymm::PublicKey();
    return kGetPublicKeyFailure;
  }

  // Decode and validate public key
  std::string serialised_public_key(packet.data());
  std::string public_key_signature(packet.signature());
  asymm::DecodePublicKey(serialised_public_key, public_key);
  if (!asymm::ValidateKey(*public_key)) {
    DLOG(ERROR) << "Failed to validate public key for "
                << Base32Substr(mmid_name);
    *public_key = asymm::PublicKey();
    return kGetPublicKeyFailure;
  }

  return kSuccess;
}

}  // namespace lifestuff

}  // namespace maidsafe
