/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Utility Functions
* Version:      1.0
* Created:      2010-04-29-13.26.25
* Revision:     none
* Compiler:     gcc
* Author:       Team, dev@maidsafe.net
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

#include "maidsafe/shared/commonutils.h"
#include "boost/function.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe-dht/kademlia/contact.h"
#include "maidsafe-dht/kademlia/node_id.h"

namespace maidsafe {

bool ContactHasId(const std::string &id, const kademlia::Contact &contact) {
  return contact.node_id().String() == id;
}

std::string SHA512File(const boost::filesystem::path &file_path) {
  return crypto::HashFile<crypto::SHA512>(file_path.string());
}

std::string SHA512String(const std::string &input) {
  return crypto::Hash<crypto::SHA512>(input);
}

std::string SHA1File(const boost::filesystem::path &file_path) {
  return crypto::Hash<crypto::SHA512>(file_path.string());
}

std::string SHA1String(const std::string &input) {
  return crypto::Hash<crypto::SHA512>(input);
}

std::string RSASign(const std::string &input, const std::string &private_key) {
  return crypto::AsymSign(input, private_key);
}

bool RSACheckSignedData(const std::string &input,
                        const std::string &signature,
                        const std::string &public_key) {
  return crypto::AsymCheckSig(input, signature, public_key);
}

std::string RSAEncrypt(const std::string &input,
                       const std::string &public_key) {
  return crypto::AsymEncrypt(input, public_key);
}

std::string RSADecrypt(const std::string &input,
                       const std::string &private_key) {
  return crypto::AsymDecrypt(input, private_key);
}

std::string AESEncrypt(const std::string &input,
                       const std::string &key) {
  if (key.size() != size_t(crypto::AES256_KeySize + crypto::AES256_IVSize))
    return "";
  return crypto::SymmEncrypt(input,
                             key.substr(0, crypto::AES256_KeySize),
                             key.substr(crypto::AES256_KeySize,
                                        crypto::AES256_IVSize));
}

std::string AESDecrypt(const std::string &input,
                       const std::string &key) {

  return crypto::SymmDecrypt(input, key, "");
}

std::string SecurePassword(const std::string &password,
                           const std::string &salt,
                           const boost::uint32_t &pin) {
  return crypto::SecurePassword(password, salt, pin);
}

std::string XORObfuscate(const std::string &first,
                         const std::string &second) {
  return crypto::XOR(first, second);
}

}  // namespace maidsafe
