/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of maidsafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the license file LICENSE.TXT found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of maidsafe.net.                                          *
 **************************************************************************************************/
/**
 * @file  account_locking.cc
 * @brief Functionality to handle account packet.
 * @date  2012-09-04
 */
#include "maidsafe/lifestuff/detail/account_locking.h"

#include <string>
#include <vector>

#include "boost/lexical_cast.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_pb.h"

#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace maidsafe {

namespace lifestuff {

namespace account_locking {

const std::string kLidAppendix("lidl");

std::string LidName(const std::string& keyword, const std::string& pin) {
  return crypto::Hash<crypto::SHA512>(crypto::Hash<crypto::SHA512>(keyword) +
                                      crypto::Hash<crypto::SHA512>(pin) +
                                      kLidAppendix);
}

std::string EncryptAccountStatus(const std::string& keyword,
                                 const std::string& pin,
                                 const std::string& password,
                                 const std::string& account_status) {
  if (account_status.empty()) {
    LOG(kError) << "Empty account status.";
    return "";
  }

  if (keyword.empty() || pin.empty() || password.empty()) {
    LOG(kError) << "One or more user credentials is empty.";
    return "";
  }

  std::string salt(crypto::Hash<crypto::SHA512>(pin + keyword));
  uint32_t pin_num;
  try {
    pin_num = boost::lexical_cast<uint32_t>(pin);
  }
  catch(boost::bad_lexical_cast& e) {
    LOG(kError) << "Bad pin:" << e.what();
    return "";
  }

  std::string secure_password;
  int result = crypto::SecurePassword(password, salt, pin_num, &secure_password);
  if (result != kSuccess) {
    LOG(kError) << "Failed to create secure password.  Result: " << result;
    return "";
  }

  std::string secure_key(secure_password.substr(0, crypto::AES256_KeySize));
  std::string secure_iv(secure_password.substr(crypto::AES256_KeySize, crypto::AES256_IVSize));

  std::string encrypted_account_status(crypto::SymmEncrypt(account_status, secure_key, secure_iv));
  if (encrypted_account_status.empty()) {
    LOG(kError) << "Failed to encrypt given account status.";
    return "";
  }
  return encrypted_account_status;
}

std::string DecryptAccountStatus(const std::string& keyword,
                                 const std::string& pin,
                                 const std::string& password,
                                 const std::string& encrypted_account_status) {
  if (encrypted_account_status.empty()) {
    LOG(kError) << "Empty encrypted account status.";
    return "";
  }

  if (keyword.empty() || pin.empty() || password.empty()) {
    LOG(kError) << "One or more user credentials is empty.";
    return "";
  }

  std::string salt(crypto::Hash<crypto::SHA512>(pin + keyword));
  uint32_t pin_num;
  try {
    pin_num = boost::lexical_cast<uint32_t>(pin);
  }
  catch(boost::bad_lexical_cast& e) {
    LOG(kError) << "Bad pin:" << e.what();
    return "";
  }

  std::string secure_password;
  int result = crypto::SecurePassword(password, salt, pin_num, &secure_password);
  if (result != kSuccess) {
    LOG(kError) << "Failed to create secure password.  Result: " << result;
    return "";
  }

  std::string secure_key(secure_password.substr(0, crypto::AES256_KeySize));
  std::string secure_iv(secure_password.substr(crypto::AES256_KeySize, crypto::AES256_IVSize));

  std::string account_status_(crypto::SymmDecrypt(encrypted_account_status, secure_key, secure_iv));
  if (account_status_.empty()) {
    LOG(kError) << "DecryptAccountStatus: Failed decryption.";
    return "";
  }

  return account_status_;
}

LockingPacket CreateLockingPacket(const std::string& identifier) {
  LockingPacket locking_packet;
  locking_packet.set_space_filler(RandomString(64));
  LockingItem* locking_item = locking_packet.add_locking_item();
  locking_item->set_identifier(identifier);
  locking_item->set_timestamp(IsoTimeWithMicroSeconds());
  locking_item->set_full_access(true);
  locking_item->set_active(0);
  return locking_packet;
}

int CheckLockingPacketForIdentifier(LockingPacket& locking_packet, const std::string& identifier) {
  for (int i = 0; i < locking_packet.locking_item_size(); ++i) {
    if (locking_packet.locking_item(i).identifier() == identifier) {
      LOG(kError) << "Item with identifier already exists! Identifier: " << identifier;
      return kLidIdentifierAlreadyInUse;
    }
  }
  return kSuccess;
}

int AddItemToLockingPacket(LockingPacket& locking_packet,
                           const std::string& identifier,
                           bool full_access) {
  LOG(kInfo) << "AddItemToLockingPacket - locking_packet.locking_item_size() BEFORE: " <<
                locking_packet.locking_item_size();
  for (int i = 0; i < locking_packet.locking_item_size(); ++i) {
    if (locking_packet.locking_item(i).identifier() == identifier) {
      LOG(kError) << "Item with identifier already exists! Identifier: " << identifier;
      LOG(kInfo) << "AddItemToLockingPacket - locking_packet.locking_item_size() AFTER: " <<
                    locking_packet.locking_item_size();
      return kLidIdentifierAlreadyInUse;
    }
  }

  bool need_to_wait(false);
  if (full_access) {
    for (int i = 0; i < locking_packet.locking_item_size(); ++i) {
      if (locking_packet.locking_item(i).full_access()) {
        LOG(kError) << "Item with full access already exists!";
        need_to_wait = true;
      }
    }
  }
  LockingItem* locking_item = locking_packet.add_locking_item();
  locking_item->set_identifier(identifier);
  locking_item->set_timestamp(IsoTimeWithMicroSeconds());
  locking_item->set_full_access(full_access);
  locking_item->set_active(0);
  LOG(kInfo) << "AddItemToLockingPacket - locking_packet.locking_item_size() AFTER: " <<
                locking_packet.locking_item_size();

  if (need_to_wait)
    return kLidFullAccessUnavailable;
  else
    return kSuccess;
}

int RemoveItemFromLockingPacket(LockingPacket& locking_packet, const std::string& identifier) {
  LOG(kInfo) << "RemoveItemFromLockingPacket - locking_packet.locking_item_size() BEFORE: " <<
                locking_packet.locking_item_size();
  LockingPacket new_locking_packet;
  new_locking_packet.set_space_filler(locking_packet.space_filler());
  for (int i = 0; i < locking_packet.locking_item_size(); ++i) {
    if (locking_packet.locking_item(i).identifier() != identifier) {
      LockingItem* new_locking_item = new_locking_packet.add_locking_item();
      *new_locking_item = locking_packet.locking_item(i);
    }
  }

  if (new_locking_packet.locking_item_size() == locking_packet.locking_item_size()) {
    LOG(kError) << "Item not found! " << locking_packet.locking_item_size();
    return kLidIdentifierNotFound;
  }

  locking_packet = new_locking_packet;
  LOG(kInfo) << "RemoveItemFromLockingPacket - locking_packet.locking_item_size() AFTER: " <<
                locking_packet.locking_item_size();
  return kSuccess;
}

int RemoveItemsFromLockingPacket(LockingPacket& locking_packet,
                                 std::vector<std::string>& identifiers) {
  if (identifiers.empty()) {
    LOG(kInfo) << "RemoveItemsFromLockingPacket - none to remove";
    return kSuccess;
  }
  LOG(kInfo) << "RemoveItemsFromLockingPacket - locking_packet.locking_item_size() BEFORE: " <<
                locking_packet.locking_item_size();

  LockingPacket new_locking_packet;
  new_locking_packet.set_space_filler(locking_packet.space_filler());

  std::string current_identifier;
  for (int i = 0; i < locking_packet.locking_item_size(); ++i) {
    auto it(std::find_if(identifiers.begin(),
                         identifiers.end(),
                         [&] (const std::string& element)->bool {
                           return locking_packet.locking_item(i).identifier() == element;
                         }));
    if (it == identifiers.end()) {
      LockingItem* new_locking_item = new_locking_packet.add_locking_item();
      *new_locking_item = locking_packet.locking_item(i);
    } else {
      identifiers.erase(it);
    }
  }

  if (!identifiers.empty()) {
    LOG(kError) << "Item(s) not found! " << identifiers.size();
    return kLidIdentifierNotFound;
  }

  locking_packet = new_locking_packet;
  LOG(kInfo) << "RemoveItemsFromLockingPacket - locking_packet.locking_item_size() AFTER: " <<
                locking_packet.locking_item_size();
  return kSuccess;
}

void OverthrowInstancesUsingLockingPacket(LockingPacket& locking_packet,
                                          const std::string& identifier) {
  LockingItem* locking_item;
  for (int i = 0; i < locking_packet.locking_item_size(); ++i) {
    if (locking_packet.locking_item(i).full_access() &&
        locking_packet.locking_item(i).identifier() != identifier) {
      locking_item = locking_packet.mutable_locking_item(i);
      locking_item->set_full_access(false);
    }
  }
}

int UpdateTimestampInLockingPacket(LockingPacket& locking_packet,
                                   const std::string& identifier) {
  LOG(kInfo) << "UpdateTimestampInLockingPacket - locking_packet.locking_item_size() BEFORE: " <<
                locking_packet.locking_item_size();
  int index(0);
  while (index < locking_packet.locking_item_size()) {
    if (locking_packet.locking_item(index).identifier() == identifier) {
      LockingItem* locking_item = locking_packet.mutable_locking_item(index);
      locking_item->set_timestamp(IsoTimeWithMicroSeconds());
      LOG(kInfo) << "UpdateTimestampInLockingPacket - locking_packet.locking_item_size() AFTER: " <<
                    locking_packet.locking_item_size();
      return kSuccess;
    } else {
      ++index;
    }
  }
  LOG(kError) << "Item not found!";
  return kLidIdentifierNotFound;
}

int CheckLockingPacketForFullAccess(const LockingPacket& locking_packet) {
  for (int i = 0; i < locking_packet.locking_item_size(); ++i) {
    if (locking_packet.locking_item(i).full_access()) {
      LOG(kInfo) << "Item with full access already exists!";
      return kReadOnlyRestrictedSuccess;
    }
  }
  return kSuccess;
}

int CheckLockingPacketForOthersLoggedIn(const LockingPacket& locking_packet,
                                        const std::string& identifier) {
  if (locking_packet.locking_item_size() > 1) {
    LOG(kError) << "More than one instance logged in";
    return kAccountAlreadyLoggedIn;
  }
  if (locking_packet.locking_item(0).identifier() != identifier) {
    LOG(kError) << "LockingPacket says this instance isn't logged in!";
    return kGeneralError;
  }
  return kSuccess;
}

int ProcessAccountStatus(const std::string& keyword,
                         const std::string& pin,
                         const std::string& password,
                         const std::string& lid_packet,
                         LockingPacket& locking_packet) {
  if (lid_packet.empty()) {
    LOG(kInfo) << "LID not found.";
    return kUserDoesntExist;
  }

  priv::chunk_actions::SignedData packet;
  if (!packet.ParseFromString(lid_packet) || packet.data().empty()) {
    LOG(kError) << "LID packet corrupted: Failed parse.";
    return kCorruptedLidPacket;
  }

  std::string decrypted_account_status(DecryptAccountStatus(keyword, pin, password, packet.data()));
  if (decrypted_account_status.empty()) {
    LOG(kError) << "LID packet corrupted: Failed decryption.";
    return kCorruptedLidPacket;
  }

  if (!locking_packet.ParseFromString(decrypted_account_status)) {
    LOG(kError) << "Failed to parse string into LockingPacket.";
    return kCorruptedLidPacket;
  }

  return kSuccess;
}

}  // namespace account_locking

}  // namespace lifestuff

}  // namespace maidsafe
