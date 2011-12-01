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

#include "maidsafe/lifestuff/lifestuff_messages_pb.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/store_components/packet_manager.h"

namespace maidsafe {

namespace lifestuff {

int GetValidatedPublicKey(const std::string &public_username,
                          std::shared_ptr<PacketManager> packet_manager,
                          asymm::PublicKey *public_key) {
  // Get public key packet from network
  std::string packet_name(crypto::Hash<crypto::SHA512>(public_username));
  std::vector<std::string> packet_values;
  int result(packet_manager->GetPacket(packet_name, &packet_values));
  if (result != kSuccess || packet_values.size() != 1U) {
    DLOG(ERROR) << "Failed to get public key for " << public_username;
    *public_key = asymm::PublicKey();
    return kGetPublicKeyFailure;
  }

  GenericPacket packet;
                                            // TODO(Fraser#5#): 2011-12-01 - Check if this could throw
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
  std::string mpid_name(crypto::Hash<crypto::SHA512>(mpid_value));
  packet_values.clear();
  result = packet_manager->GetPacket(mpid_name, &packet_values);
  if (result != kSuccess || packet_values.size() != 1U) {
    DLOG(ERROR) << "Failed to get MPID for " << public_username;
    *public_key = asymm::PublicKey();
    return kGetMpidFailure;
  }

  packet.Clear();
                                            // TODO(Fraser#5#): 2011-12-01 - Check if this could throw
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

  if (asymm::CheckSignature(serialised_public_key,
                            public_key_signature,
                            *public_key) != kSuccess) {
    DLOG(ERROR) << "Invalid public key signature for " << public_username;
    *public_key = asymm::PublicKey();
    return kInvalidPublicKey;
  }

  return kSuccess;
}

}  // namespace lifestuff

}  // namespace maidsafe
