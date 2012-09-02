/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Creates, stores and accesses user details
* Version:      1.0
* Created:      2009-01-28-22.18.47
* Revision:     none
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

#include "maidsafe/lifestuff/detail/user_credentials_impl.h"

#include <memory>
#include <vector>

#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/thread/thread.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"
#include "maidsafe/private/utils/utilities.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace args = std::placeholders;
namespace pca = maidsafe::priv::chunk_actions;
namespace bptime = boost::posix_time;
namespace lid = maidsafe::lifestuff::account_locking;
namespace utils = maidsafe::priv::utilities;

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

int AddItemToLockingPacket(LockingPacket& locking_packet,
                           const std::string& identifier,
                           bool full_access) {
  LOG(kInfo) << "AddItemToLockingPacket - locking_packet.locking_item_size() BEFORE: " <<
                locking_packet.locking_item_size();
  for (int i = 0; i < locking_packet.locking_item_size(); ++i) {
    if (locking_packet.locking_item(i).identifier() == identifier) {
      LOG(kError) << "Item with identifier already exists! Identifier: " << identifier;
      return kLidIdentifierAlreadyInUse;
    }
  }

  if (full_access) {
    for (int i = 0; i < locking_packet.locking_item_size(); ++i) {
      if (locking_packet.locking_item(i).full_access()) {
        LOG(kError) << "Item with full access already exists!";
        return kLidFullAccessUnavailable;
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
  return kSuccess;
}

int RemoveItemFromLockingPacket(LockingPacket& locking_packet,
                                const std::string& identifier) {
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

int UpdateTimestampInLockingPacket(LockingPacket& locking_packet,
                                   const std::string& identifier) {
  LOG(kInfo) << "UpdateTimestampInLockingPacket - locking_packet.locking_item_size() BEFORE: " <<
                locking_packet.locking_item_size();
  int index(0);
  while (index < locking_packet.locking_item_size()) {
    if (locking_packet.locking_item(index).identifier() == identifier) {
      LockingItem locking_item = locking_packet.locking_item(index);
      locking_item.set_timestamp(IsoTimeWithMicroSeconds());
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

int CheckLockingPacketForFullAccess(LockingPacket& locking_packet) {
  // TODO(Alison) - check that identifier doesn't exist already?
  for (int i = 0; i < locking_packet.locking_item_size(); ++i) {
    if (locking_packet.locking_item(i).full_access()) {
      // TODO(Alison) - check if it's the current user who has full access!
      LOG(kInfo) << "Item with full access already exists!";
      return kReadOnlyRestrictedSuccess;
    }
  }
  return kSuccess;
}

int ProcessAccountStatus(const std::string& keyword,
                         const std::string& pin,
                         const std::string& password,
                         const std::string& lid_packet,
                         LockingPacket& locking_packet) {
  // TODO(Alison) - fix LID if corrupted
  if (lid_packet.empty()) {
    LOG(kInfo) << "LID not found.";
    return kUserDoesntExist;
  }

  pca::SignedData packet;
  if (!packet.ParseFromString(lid_packet) || packet.data().empty()) {
    LOG(kError) << "LID packet corrupted: Failed parse.";
    return kCorruptedLidPacket;
  }

  std::string decrypted_account_status(DecryptAccountStatus(keyword, pin, password, packet.data()));
  if (decrypted_account_status.empty()) {
    LOG(kError) << "LID packet corrupted: Failed decryption.";
    return kCorruptedLidPacket;
  }

  if (locking_packet.ParseFromString(decrypted_account_status)) {
    return kSuccess;
  } else {
    LOG(kError) << "Failed to parse string into LockingPacket.";
    return kCorruptedLidPacket;
  }
  return kGeneralError;
}

}  // namespace account_locking

namespace {

int CreateSignaturePacketInfo(std::shared_ptr<asymm::Keys> packet,
                              std::string* packet_name,
                              std::string* packet_content) {
  BOOST_ASSERT(packet && packet_name && packet_content);
  *packet_name = pca::ApplyTypeToName(packet->identity, pca::kSignaturePacket);

  pca::SignedData signed_data;
  std::string public_key;
  asymm::EncodePublicKey(packet->public_key, &public_key);
  if (public_key.empty()) {
    LOG(kError) << "Public key not properly encoded.";
    return kCreateSignaturePacketInfoFailure;
  }

  signed_data.set_data(public_key);
  signed_data.set_signature(packet->validation_token);
  if (!signed_data.SerializeToString(packet_content) || packet_content->empty()) {
    LOG(kError) << "SignedData not properly serialised.";
    return kCreateSignaturePacketInfoFailure;
  }

  return kSuccess;
}

}  // namespace

UserCredentialsImpl::UserCredentialsImpl(pcs::RemoteChunkStore& remote_chunk_store,
                                         Session& session,
                                         boost::asio::io_service& service)
    : remote_chunk_store_(remote_chunk_store),
      session_(session),
      passport_(session_.passport()),
      single_threaded_class_mutex_(),
      asio_service_(service),
      session_saver_timer_(asio_service_),
      session_saver_timer_active_(false),
      session_saved_once_(false),
      session_saver_interval_(kSecondsInterval * 12) {}

UserCredentialsImpl::~UserCredentialsImpl() {}

int UserCredentialsImpl::GetUserInfo(const std::string& keyword,
                                     const std::string& pin,
                                     const std::string& password) {
  LOG(kInfo) << "UserCredentialsImpl::GetUserInfo";
  boost::mutex::scoped_lock loch_a_phuill(single_threaded_class_mutex_);

  // TODO(Alison) - overwrite unintelligible LID
  std::string lid_packet(remote_chunk_store_.Get(pca::ApplyTypeToName(lid::LidName(keyword, pin),
                                                                      pca::kModifiableByOwner)));
  LockingPacket locking_packet;
  int lid_result(lid::ProcessAccountStatus(keyword, pin, password, lid_packet, locking_packet));
  if (lid_result != kSuccess) {
    LOG(kError) << "Account can't be logged in: " << lid_result;
    return lid_result;
  }

  // Obtain MID, TMID
  int mid_tmid_result(kSuccess);
  std::string tmid_packet;
  boost::thread mid_tmid_thread([&] {
                                  GetIdAndTemporaryId(keyword, pin, password, false,
                                                      &mid_tmid_result, &tmid_packet);
                                });
  // Obtain SMID, STMID
  int smid_stmid_result(kSuccess);
  std::string stmid_packet;
  boost::thread smid_stmid_thread([&] {
                                    GetIdAndTemporaryId(keyword, pin, password, true,
                                                        &smid_stmid_result, &stmid_packet);
                                  });

  // Wait for them to finish
  mid_tmid_thread.join();
  smid_stmid_thread.join();

  // Evaluate MID & TMID
  if (mid_tmid_result == kIdPacketNotFound && smid_stmid_result == kIdPacketNotFound) {
    LOG(kInfo) << "User doesn't exist: " << keyword << ", " << pin;
    return kUserDoesntExist;
  }

  if (mid_tmid_result == kCorruptedPacket && smid_stmid_result == kCorruptedPacket) {
    LOG(kError) << "Account corrupted. Should never happen: "
                << keyword << ", " << pin;
    return kAccountCorrupted;
  }

  int result(HandleSerialisedDataMaps(keyword, pin, password, tmid_packet, stmid_packet));
  if (result != kSuccess) {
    if (result != kUsingNextToLastSession) {
      LOG(kError) << "Failed to initialise session: " << result;
      result = kAccountCorrupted;
    }
    return result;
  }

  result = GetAndLockLid(keyword, pin, password, lid_packet, locking_packet);
  if (result != kSuccess) {
    LOG(kError) << "Failed to lock LID.";
    return result;
  }

  // Check level of access allowed
  int anticipated_access(lid::CheckLockingPacketForFullAccess(locking_packet));
  session_.set_keyword(keyword);
  session_.set_pin(pin);
  session_.set_password(password);
  if (!session_.set_session_name()) {
    LOG(kError) << "Failed to set session.";
    return kSessionFailure;
  }

  if (anticipated_access == kSuccess)
    result = lid::AddItemToLockingPacket(locking_packet, session_.session_name(), true);
  else if (anticipated_access == kReadOnlyRestrictedSuccess)
    result = lid::AddItemToLockingPacket(locking_packet, session_.session_name(), false);
  else
    LOG(kError) << "Wrong anticipated_access value: " << anticipated_access;

  if (result != kSuccess) {
    LOG(kError) << "Failed to change contents of Locking Packet.";
    return result;
  }

  result = ModifyLid(keyword, pin, password, locking_packet);
  if (result != kSuccess) {
    LOG(kError) << "Failed to modify LID.";
    return result;
  }

  if (anticipated_access == kSuccess) {
    session_saved_once_ = false;
  }
  StartSessionSaver();

  if (anticipated_access == kSuccess)
  return kSuccess;
  else
  return kReadOnlyRestrictedSuccess;
}

int UserCredentialsImpl::GetAndLockLid(const std::string& keyword,
                                       const std::string& pin,
                                       const std::string& password,
                                       std::string& lid_packet,
                                       LockingPacket& locking_packet) {
  LOF(kInfo) << "UserCredentialsImpl::GetAndLockLid";
  std::string lid_name(pca::ApplyTypeToName(lid::LidName(keyword, pin), pca::kModifiableByOwner));

  std::shared_ptr<asymm::Keys> keys(
      new asymm::Keys(passport_.SignaturePacketDetails(passport::kAnmid, true)));
  int get_lock_result(remote_chunk_store_.GetAndLock(lid_name, "", keys, &lid_packet));
  if (get_lock_result != kSuccess) {
    LOG(kError) << "Failed to GetAndLock LID: " << get_lock_result;
    return get_lock_result;
  };
  return lid::ProcessAccountStatus(keyword, pin, password, lid_packet, locking_packet);
  // TODO(Alison) - need to give contents of LID back out to be read - return
}

void UserCredentialsImpl::StartSessionSaver() {
  session_saver_timer_active_ = true;
  session_saver_timer_.expires_from_now(bptime::seconds(session_saver_interval_));
  session_saver_timer_.async_wait([=] (const boost::system::error_code &error_code) {
                                    this->SessionSaver(bptime::seconds(session_saver_interval_),
                                                       error_code);
                                  });
}

void UserCredentialsImpl::GetIdAndTemporaryId(const std::string& keyword,
                                              const std::string& pin,
                                              const std::string& password,
                                              bool surrogate,
                                              int* result,
                                              std::string* temporary_packet) {
  std::string id_name(pca::ApplyTypeToName(passport::MidName(keyword, pin, surrogate),
                                           pca::kModifiableByOwner));
  std::string id_packet(remote_chunk_store_.Get(id_name));
  if (id_packet.empty()) {
    LOG(kError) << "No " << (surrogate ? "SMID" : "MID") << " found.";
    *result = kIdPacketNotFound;
    return;
  }

  pca::SignedData packet;
  if (!packet.ParseFromString(id_packet) || packet.data().empty()) {
    LOG(kError) << (surrogate ? "SMID" : "MID") << " packet corrupted: Failed parse.";
    *result = kCorruptedPacket;
    return;
  }

  std::string decrypted_rid(passport::DecryptRid(keyword, pin, packet.data()));
  if (decrypted_rid.empty()) {
    LOG(kError) << (surrogate ? "SMID" : "MID") << " packet corrupted: Failed decryption.";
    *result = kCorruptedPacket;
    return;
  }
  decrypted_rid = pca::ApplyTypeToName(decrypted_rid, pca::kModifiableByOwner);

  std::string temporary_id_packet(remote_chunk_store_.Get(decrypted_rid));
  if (temporary_id_packet.empty()) {
    LOG(kError) << "No " << (surrogate ? "STMID" : "TMID") << " found.";
    *result = kTemporaryIdPacketNotFound;
    return;
  }

  packet.Clear();
  if (!packet.ParseFromString(temporary_id_packet) || packet.data().empty()) {
    LOG(kError) << (surrogate ? "STMID" : "TMID") << " packet corrupted: "
                << "Failed parse.";
    *result = kCorruptedPacket;
    return;
  }

  *temporary_packet = passport::DecryptMasterData(keyword, pin, password, packet.data());
  if (temporary_packet->empty()) {
    LOG(kError) << (surrogate ? "STMID" : "TMID") << " packet corrupted: "
                << "Failed decryption.";
    *result = kCorruptedPacket;
    return;
  }
}

int UserCredentialsImpl::HandleSerialisedDataMaps(const std::string& keyword,
                                                  const std::string& pin,
                                                  const std::string& password,
                                                  const std::string& tmid_serialised_data_atlas,
                                                  const std::string& stmid_serialised_data_atlas) {
  int result(kSuccess);
  std::string tmid_da, stmid_da;
  if (!tmid_serialised_data_atlas.empty()) {
    result = session_.ParseDataAtlas(tmid_serialised_data_atlas);
    if (result == kSuccess) {
      session_.set_serialised_data_atlas(tmid_serialised_data_atlas);
      tmid_da = tmid_serialised_data_atlas;
    }
  } else if (!stmid_serialised_data_atlas.empty()) {
    tmid_da = stmid_serialised_data_atlas;
    stmid_da = stmid_serialised_data_atlas;
    result = session_.ParseDataAtlas(stmid_serialised_data_atlas);
    if (result == kSuccess) {
      session_.set_serialised_data_atlas(stmid_serialised_data_atlas);
      result = kUsingNextToLastSession;
    }
  }

  if (stmid_da.empty()) {
    if (tmid_da.empty()) {
      LOG(kError) << "No valid DA.";
      return kSetIdentityPacketsFailure;
    } else if (!stmid_serialised_data_atlas.empty()) {
      stmid_da = stmid_serialised_data_atlas;
    }
  }

  result = passport_.SetIdentityPackets(keyword, pin, password, tmid_da, stmid_da);
  result += passport_.ConfirmIdentityPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failure to set and confirm identity packets.";
    return kSetIdentityPacketsFailure;
  }

  return result;
}

int UserCredentialsImpl::CreateUser(const std::string& keyword,
                                    const std::string& pin,
                                    const std::string& password) {
  boost::mutex::scoped_lock loch_a_phuill(single_threaded_class_mutex_);

  int result(ProcessSigningPackets());
  if (result != kSuccess) {
    LOG(kError) << "Failed processing signature packets: " << result;
    return kSessionFailure;
  }

  result = ProcessIdentityPackets(keyword, pin, password);
  if (result != kSuccess) {
    LOG(kError) << "Failed processing identity packets: " << result;
    return kSessionFailure;
  }

  session_.set_keyword(keyword);
  session_.set_pin(pin);
  session_.set_password(password);
  if (!session_.set_session_name()) {
    LOG(kError) << "Failed to set session.";
    return kSessionFailure;
  }

  LockingPacket locking_packet(lid::CreateLockingPacket(session_.session_name()));
  result = StoreLid(keyword, pin, password, locking_packet);
  if (result != kSuccess) {
    LOG(kError) << "Failed to create LID.";
    return result;
  }

  StartSessionSaver();

  return kSuccess;
}

int UserCredentialsImpl::ProcessSigningPackets() {
  int result(passport_.CreateSigningPackets());
  if (result != kSuccess) {
    LOG(kError) << "Failed creating signature packets: " << result;
    return kSessionFailure;
  }

  result = StoreAnonymousPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failure to Store Anonymous packets: " << result;
    return result;
  }

  result = passport_.ConfirmSigningPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed confirming signature packets: " << result;
    return kSessionFailure;
  }

  return kSuccess;
}

int UserCredentialsImpl::StoreAnonymousPackets() {
  std::vector<int> individual_results(4, kPendingResult);
  boost::condition_variable condition_variable;
  boost::mutex mutex;
  OperationResults results(mutex, condition_variable, individual_results);

  // ANMID path
  StoreAnmid(results);
  // ANSMID path
  StoreAnsmid(results);
  // ANTMID path
  StoreAntmid(results);
  // PMID path: ANMAID, MAID, PMID
  StoreAnmaid(results);

  int result(utils::WaitForResults(mutex, condition_variable, individual_results));
  if (result != kSuccess) {
    LOG(kError) << "Wait for results timed out: " << result;
    LOG(kError) << "ANMID: " << individual_results.at(0)
              << ", ANSMID: " << individual_results.at(1)
              << ", ANTMID: " << individual_results.at(2)
              << ", PMID path: " << individual_results.at(3);
    return result;
  }
  LOG(kInfo) << "ANMID: " << individual_results.at(0)
             << ", ANSMID: " << individual_results.at(1)
             << ", ANTMID: " << individual_results.at(2)
             << ", PMID path: " << individual_results.at(3);

  result = AssessJointResult(individual_results);
  if (result != kSuccess) {
    LOG(kError) << "One of the operations for Anonymous Packets failed. "
                << "Turn on INFO for feedback on which one. ";
    return kCreateSignaturePacketsFailure;
  }

  return kSuccess;
}

void UserCredentialsImpl::StoreAnmid(OperationResults& results) {
  std::shared_ptr<asymm::Keys> anmid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kAnmid, false)));
  StoreSignaturePacket(anmid, results, 0);
}

void UserCredentialsImpl::StoreAnsmid(OperationResults& results) {
  std::shared_ptr<asymm::Keys> ansmid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kAnsmid, false)));
  StoreSignaturePacket(ansmid, results, 1);
}

void UserCredentialsImpl::StoreAntmid(OperationResults& results) {
  std::shared_ptr<asymm::Keys> antmid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kAntmid, false)));
  StoreSignaturePacket(antmid, results, 2);
}

void UserCredentialsImpl::StoreSignaturePacket(std::shared_ptr<asymm::Keys> packet,
                                               OperationResults& results,
                                               int index) {
  std::string packet_name, packet_content;

  CreateSignaturePacketInfo(packet, &packet_name, &packet_content);
  if (!remote_chunk_store_.Store(packet_name,
                                 packet_content,
                                 [&] (bool result) {
                                   OperationCallback(result, results, index);
                                 },
                                 packet)) {
    LOG(kError) << "Failed to store: " << index;
    OperationCallback(false, results, index);
  }
}

void UserCredentialsImpl::StoreAnmaid(OperationResults& results) {
  std::shared_ptr<asymm::Keys> anmaid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kAnmaid, false)));
  std::string packet_name, packet_content;

  CreateSignaturePacketInfo(anmaid, &packet_name, &packet_content);
  if (!remote_chunk_store_.Store(packet_name,
                                 packet_content,
                                 [&] (bool result) { StoreMaid(result, results); },
                                 anmaid)) {
    LOG(kError) << "Failed to store ANMAID.";
    StoreMaid(false, results);
  }
}

void UserCredentialsImpl::StoreMaid(bool result, OperationResults& results) {
  if (!result) {
    LOG(kError) << "Anmaid failed to store.";
    OperationCallback(false, results, 3);
    return;
  }

  std::shared_ptr<asymm::Keys> maid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kMaid, false)));
  std::shared_ptr<asymm::Keys> anmaid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kAnmaid, false)));

  std::string maid_name(pca::ApplyTypeToName(maid->identity, pca::kSignaturePacket));
  pca::SignedData signed_maid;
  signed_maid.set_signature(maid->validation_token);
  std::string maid_string_public_key;
  asymm::EncodePublicKey(maid->public_key, &maid_string_public_key);
  if (maid_string_public_key.empty()) {
    LOG(kError) << "Failed to procure sign MAID's public key.";
    StorePmid(false, results);
    return;
  }
  signed_maid.set_data(maid_string_public_key);
  if (!remote_chunk_store_.Store(maid_name,
                                 signed_maid.SerializeAsString(),
                                 [&] (bool result) { StorePmid(result, results); },
                                 anmaid)) {
    LOG(kError) << "Failed to store MAID.";
    StorePmid(false, results);
  }
}

void UserCredentialsImpl::StorePmid(bool result, OperationResults& results) {
  if (!result) {
    LOG(kError) << "Maid failed to store.";
    OperationCallback(false, results, 3);
    return;
  }

  std::shared_ptr<asymm::Keys> pmid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kPmid, false)));
  std::shared_ptr<asymm::Keys> maid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kMaid, false)));

  std::string pmid_name(pca::ApplyTypeToName(pmid->identity, pca::kSignaturePacket));
  pca::SignedData signed_pmid;
  signed_pmid.set_signature(pmid->validation_token);
  std::string pmid_string_public_key;
  asymm::EncodePublicKey(pmid->public_key, &pmid_string_public_key);
  if (pmid_string_public_key.empty()) {
    LOG(kError) << "Failed to procure sign PMID's public key.";
    StorePmid(false, results);
    return;
  }
  signed_pmid.set_data(pmid_string_public_key);

  if (!remote_chunk_store_.Store(pmid_name,
                                 signed_pmid.SerializeAsString(),
                                 [&] (bool result) {
                                   OperationCallback(result, results, 3);
                                 },
                                 maid)) {
    LOG(kError) << "Failed to store PMID.";
    OperationCallback(false, results, 3);
  }
}

int UserCredentialsImpl::ProcessIdentityPackets(const std::string& keyword,
                                                const std::string& pin,
                                                const std::string& password) {
  std::string serialised_data_atlas, surrogate_serialised_data_atlas;
  int result(session_.SerialiseDataAtlas(&serialised_data_atlas));
  Sleep(bptime::milliseconds(1));  // Need different timestamps
  result += session_.SerialiseDataAtlas(&surrogate_serialised_data_atlas);
  if (result != kSuccess ||
      serialised_data_atlas.empty() ||
      surrogate_serialised_data_atlas.empty()) {
    LOG(kError) << "Don't have the appropriate elements to save on ID packets.";
    return kSessionSerialisationFailure;
  }

  result = passport_.SetIdentityPackets(keyword,
                                        pin,
                                        password,
                                        serialised_data_atlas,
                                        surrogate_serialised_data_atlas);
  if (result!= kSuccess) {
    LOG(kError) << "Creation of ID packets failed.";
    return kSessionSerialisationFailure;
  }

  result = StoreIdentityPackets();
  if (result!= kSuccess) {
    LOG(kError) << "Storing of ID packets failed.";
    return result;
  }

  result = passport_.ConfirmIdentityPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed confirming identity packets: " << result;
    return kSessionFailure;
  }

  session_.set_serialised_data_atlas(serialised_data_atlas);

  return kSuccess;
}

int UserCredentialsImpl::StoreIdentityPackets() {
  std::vector<int> individual_results(4, kPendingResult);
  boost::condition_variable condition_variable;
  boost::mutex mutex;
  OperationResults results(mutex, condition_variable, individual_results);

  // MID path
  StoreMid(results);
  // SMID path
  StoreSmid(results);
  // TMID path
  StoreTmid(results);
  // STMID
  StoreStmid(results);

  int result(utils::WaitForResults(mutex, condition_variable, individual_results));
  if (result != kSuccess) {
    LOG(kError) << "Wait for results timed out.";
    return result;
  }
  LOG(kInfo) << "MID: " << individual_results.at(0)
             << ", SMID: " << individual_results.at(1)
             << ", TMID: " << individual_results.at(2)
             << ", STMID: " << individual_results.at(3);

  result = AssessJointResult(individual_results);
  if (result != kSuccess) {
    LOG(kError) << "One of the operations for Identity Packets failed. "
                << "Turn on INFO for feedback on which one. ";
    return kStoreIdentityPacketsFailure;
  }

  return kSuccess;
}

void UserCredentialsImpl::StoreMid(OperationResults& results) {
  StoreIdentity(results, passport::kMid, passport::kAnmid, 0);
}

void UserCredentialsImpl::StoreSmid(OperationResults& results) {
  StoreIdentity(results, passport::kSmid, passport::kAnsmid, 1);
}

void UserCredentialsImpl::StoreTmid(OperationResults& results) {
  StoreIdentity(results, passport::kTmid, passport::kAntmid, 2);
}

void UserCredentialsImpl::StoreStmid(OperationResults& results) {
  StoreIdentity(results, passport::kStmid, passport::kAntmid, 3);
}

void UserCredentialsImpl::StoreIdentity(OperationResults& results,
                                        int identity_type,
                                        int signer_type,
                                        int index) {
  passport::PacketType id_pt(static_cast<passport::PacketType>(identity_type));
  passport::PacketType sign_pt(static_cast<passport::PacketType>(signer_type));
  std::string packet_name(passport_.IdentityPacketName(id_pt, false)),
              packet_content(passport_.IdentityPacketValue(id_pt, false));
  packet_name = pca::ApplyTypeToName(packet_name, pca::kModifiableByOwner);
  std::shared_ptr<asymm::Keys> signer(new asymm::Keys(
      passport_.SignaturePacketDetails(sign_pt, true)));

  asymm::Signature signature;
  int result(asymm::Sign(packet_content, signer->private_key, &signature));
  if (result != kSuccess) {
    LOG(kError) << "Failed to sign content: " << result;
    OperationCallback(false, results, index);
    return;
  }

  pca::SignedData signed_data;
  signed_data.set_data(packet_content);
  signed_data.set_signature(signature);
  if (!remote_chunk_store_.Store(packet_name,
                                 signed_data.SerializeAsString(),
                                 [&] (bool result) {
                                   OperationCallback(result, results, index);
                                 },
                                 signer)) {
    LOG(kError) << "Failed to store: " << index;
    OperationCallback(false, results, index);
  }
}

int UserCredentialsImpl::StoreLid(const std::string keyword,
                                  const std::string pin,
                                  const std::string password,
                                  const LockingPacket& locking_packet) {
  LOG(kInfo) << "UserCredentialsImpl::StoreLid";
  std::string packet_name(pca::ApplyTypeToName(lid::LidName(keyword, pin),
                                               pca::kModifiableByOwner));
  std::string account_status(locking_packet.SerializeAsString());
  std::string encrypted_account_status(lid::EncryptAccountStatus(keyword, pin, password,
                                                                 account_status));

  std::shared_ptr<asymm::Keys> signer(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kAnmid, true)));
  asymm::Signature signature;
  int result(asymm::Sign(encrypted_account_status, signer->private_key, &signature));
  if (result != kSuccess) {
    LOG(kError) << "Failed to sign content: " << result;
    return result;
  }

  pca::SignedData signed_data;
  signed_data.set_data(encrypted_account_status);
  signed_data.set_signature(signature);

  std::vector<int> individual_result(1, kPendingResult);
  boost::condition_variable condition_variable;
  boost::mutex mutex;
  OperationResults operation_result(mutex, condition_variable, individual_result);
  if (!remote_chunk_store_.Store(packet_name,
                                 signed_data.SerializeAsString(),
                                 [&] (bool result) {
                                   OperationCallback(result, operation_result, 0);
                                 },
                                 signer)) {
    LOG(kError) << "Failed to store LID.";
    OperationCallback(false, operation_result, 0);
  }
  result = utils::WaitForResults(mutex, condition_variable, individual_result);
  if (result != kSuccess) {
    LOG(kError) << "Failed to store LID:" << result;
    return result;
  }
  return individual_result.at(0);
}

int UserCredentialsImpl::SaveSession(bool log_out) {
  boost::mutex::scoped_lock loch_a_phuill(single_threaded_class_mutex_);

  if (log_out) {
    session_saver_timer_active_ = false;
    session_saver_timer_.cancel();

    if (!session_.changed() && session_saved_once_) {
      LOG(kError) << "Session has not changed.";
      return kSuccess;
    }
  } else if (!session_.changed()) {
    LOG(kError) << "Session has not changed.";
    return kSuccess;
  }

  std::string serialised_data_atlas;
  int result(SerialiseAndSetIdentity("", "", "", &serialised_data_atlas));
  if (result != kSuccess) {
    LOG(kError) << "Failure setting details of new session: " << result;
    return result;
  }

  std::vector<int> individual_results(4, kPendingResult);
  boost::condition_variable condition_variable;
  boost::mutex mutex;
  OperationResults results(mutex, condition_variable, individual_results);

  ModifyMid(results);
  ModifySmid(results);
  StoreTmid(results);
  DeleteStmid(results);

  result = utils::WaitForResults(mutex, condition_variable, individual_results);
  if (result != kSuccess) {
    LOG(kError) << "Failed to store new identity packets: Time out.";
    return kSaveSessionFailure;
  }

  LOG(kError) << "MID: " << individual_results.at(0)
             << ", SMID: " << individual_results.at(1)
             << ", TMID: " << individual_results.at(2)
             << ", STMID: " << individual_results.at(3);

  result = AssessJointResult(individual_results);
  if (result != kSuccess) {
    LOG(kError) << "One of the operations for Identity Packets failed. "
                << "Turn on INFO for feedback on which one. ";
    return kSaveSessionFailure;
  }

  session_.set_serialised_data_atlas(serialised_data_atlas);
  session_.set_changed(false);
  session_saved_once_ = true;

  return kSuccess;
}

int UserCredentialsImpl::UpdateLid(bool log_out) {
  LOG(kInfo) << "UserCredentialsImpl::UpdateLid";
  std::string lid_packet;
  LockingPacket locking_packet;
  int result(GetAndLockLid(session_.keyword(),
                           session_.pin(),
                           session_.password(),
                           lid_packet,
                           locking_packet));
  if (result != kSuccess) {
    LOG(kError) << "Failed to get and lock LID.";
    return result;
  }

  if (log_out) {
    LOG(kInfo) << "UserCredentialsImpl::UpdateLid - Removing item :(";
    result = lid::RemoveItemFromLockingPacket(locking_packet, session_.session_name());
    if (result != kSuccess) {
      LOG(kError) << "Failed to remove item from locking packet.";
      return result;
    }
  } else {
    LOG(kInfo) << "UserCredentialsImpl::UpdateLid - Updating timestamp :)";
    result = lid::UpdateTimestampInLockingPacket(locking_packet, session_.session_name());
    if (result != kSuccess) {
      LOG(kError) << "Failed to update timestamp locking packet.";
      return result;
    }
  }

  result = ModifyLid(session_.keyword(), session_.pin(), session_.password(), locking_packet);
  if (result != kSuccess) {
    LOG(kError) << "Failed to modify LID.";
    return result;
  }
  return kSuccess;
}

void UserCredentialsImpl::ModifyMid(OperationResults& results) {
  ModifyIdentity(results, passport::kMid, passport::kAnmid, 0);
}

void UserCredentialsImpl::ModifySmid(OperationResults& results) {
  ModifyIdentity(results, passport::kSmid, passport::kAnsmid, 1);
}

void UserCredentialsImpl::ModifyIdentity(OperationResults& results,
                                         int identity_type,
                                         int signer_type,
                                         int index) {
  passport::PacketType id_pt(static_cast<passport::PacketType>(identity_type));
  passport::PacketType sign_pt(static_cast<passport::PacketType>(signer_type));
  std::string name(passport_.IdentityPacketName(id_pt, false)),
              content(passport_.IdentityPacketValue(id_pt, false));
  name = pca::ApplyTypeToName(name, pca::kModifiableByOwner);
  std::shared_ptr<asymm::Keys> signer(new asymm::Keys(passport_.SignaturePacketDetails(sign_pt,
                                                                                       true)));

  asymm::Signature signature;
  int result(asymm::Sign(content, signer->private_key, &signature));
  if (result != kSuccess) {
    LOG(kError) << "Failed to sign content: " << result;
    OperationCallback(false, results, index);
    return;
  }

  pca::SignedData signed_data;
  signed_data.set_data(content);
  signed_data.set_signature(signature);
  if (!remote_chunk_store_.Modify(name,
                                  signed_data.SerializeAsString(),
                                  [&] (bool result) {
                                    OperationCallback(result, results, index);
                                  },
                                  signer)) {
    LOG(kError) << "Failed to modify: " << index;
    OperationCallback(false, results, index);
  }
}

int UserCredentialsImpl::ModifyLid(const std::string keyword,
                                   const std::string pin,
                                   const std::string password,
                                   const LockingPacket& locking_packet) {
  LOG(kInfo) << "UserCredentialsImpl::ModifyLid";
  std::string packet_name(lid::LidName(keyword, pin));
  packet_name = pca::ApplyTypeToName(packet_name, pca::kModifiableByOwner);

  std::string account_status(locking_packet.SerializeAsString());
  std::string encrypted_account_status(lid::EncryptAccountStatus(keyword, pin, password,
                                                                 account_status));

  std::shared_ptr<asymm::Keys> signer(
      new asymm::Keys(passport_.SignaturePacketDetails(passport::kAnmid, true)));
  asymm::Signature signature;
  int result(asymm::Sign(encrypted_account_status, signer->private_key, &signature));
  if (result != kSuccess) {
    LOG(kError) << "Failed to sign content: " << result;
    return result;
  }

  pca::SignedData signed_data;
  signed_data.set_data(encrypted_account_status);
  signed_data.set_signature(signature);

  std::vector<int> individual_result(1, kPendingResult);
  boost::condition_variable condition_variable;
  boost::mutex mutex;
  OperationResults operation_result(mutex, condition_variable, individual_result);
  if (!remote_chunk_store_.Modify(packet_name,
                                  signed_data.SerializeAsString(),
                                  [&] (bool result) {
                                    OperationCallback(result, operation_result, 0);
                                  },
                                  signer)) {
    LOG(kError) << "Failed to modify LID.";
    OperationCallback(false, operation_result, 0);
  }
  result = utils::WaitForResults(mutex, condition_variable, individual_result);
  if (result != kSuccess) {
    LOG(kError) << "Failed to modify LID:" << result;
    return result;
  }
  return individual_result.at(0);
}

int UserCredentialsImpl::ChangePin(const std::string& new_pin) {
  boost::mutex::scoped_lock loch_a_phuill(single_threaded_class_mutex_);
  std::string keyword(session_.keyword());
  return ChangeUsernamePin(keyword, new_pin);
}

int UserCredentialsImpl::ChangeKeyword(const std::string new_keyword) {
  boost::mutex::scoped_lock loch_a_phuill(single_threaded_class_mutex_);
  std::string pin(session_.pin());
  return ChangeUsernamePin(new_keyword, pin);
}

int UserCredentialsImpl::ChangeUsernamePin(const std::string& new_keyword,
                                           const std::string& new_pin) {
  BOOST_ASSERT(!new_keyword.empty());
  BOOST_ASSERT(!new_pin.empty());

  std::string serialised_data_atlas;
  int result(SerialiseAndSetIdentity(new_keyword, new_pin, "", &serialised_data_atlas));
  if (result != kSuccess) {
    LOG(kError) << "Failure setting details of new session: " << result;
    return result;
  }

  result = StoreIdentityPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed to store new identity packets: " << result;
    return result;
  }

  // TODO(Alison) - should prohibit starting ChangeUsernamePin if any other instances logged in!
  result = StoreLid(new_keyword,
                    new_pin,
                    session_.password(),
                    lid::CreateLockingPacket(session_.session_name()));
  if (result != kSuccess) {
    LOG(kError) << "Failed to store new LID.";
    return result;
  }

  result = DeleteOldIdentityPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed to delete old identity packets: " << result;
    return result;
  }

  result = DeleteLid(session_.keyword(), session_.pin());
  if (result != kSuccess) {
    LOG(kError) << "Failed to delete old LID.";
    return result;
  }

  result = passport_.ConfirmIdentityPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed to set new identity packets: " << result;
    return kSetIdentityPacketsFailure;
  }

  session_.set_keyword(new_keyword);
  session_.set_pin(new_pin);
  session_.set_serialised_data_atlas(serialised_data_atlas);
  session_.set_changed(false);

  return kSuccess;
}

int UserCredentialsImpl::DeleteOldIdentityPackets() {
  std::vector<int> individual_results(4, kPendingResult);
  boost::condition_variable condition_variable;
  boost::mutex mutex;
  OperationResults results(mutex, condition_variable, individual_results);

  DeleteMid(results);
  DeleteSmid(results);
  DeleteTmid(results);
  DeleteStmid(results);

  int result(utils::WaitForResults(mutex, condition_variable, individual_results));
  if (result != kSuccess) {
    LOG(kError) << "Wait for results timed out.";
    return result;
  }
  LOG(kInfo) << "MID: " << individual_results.at(0)
             << ", SMID: " << individual_results.at(1)
             << ", TMID: " << individual_results.at(2)
             << ", STMID: " << individual_results.at(3);

  result = AssessJointResult(individual_results);
  if (result != kSuccess) {
    LOG(kError) << "One of the operations for Identity Packets failed. "
                << "Turn on INFO for feedback on which one. ";
    return kDeleteIdentityPacketsFailure;
  }

  return kSuccess;
}

void UserCredentialsImpl::DeleteMid(OperationResults& results) {
  DeleteIdentity(results, passport::kMid, passport::kAnmid, 0);
}

void UserCredentialsImpl::DeleteSmid(OperationResults& results) {
  DeleteIdentity(results, passport::kSmid, passport::kAnsmid, 1);
}

void UserCredentialsImpl::DeleteTmid(OperationResults& results) {
  DeleteIdentity(results, passport::kTmid, passport::kAntmid, 2);
}

void UserCredentialsImpl::DeleteStmid(OperationResults& results) {
  DeleteIdentity(results, passport::kStmid, passport::kAntmid, 3);
}

void UserCredentialsImpl::DeleteIdentity(OperationResults& results,
                                         int packet_type,
                                         int signer_type,
                                         int index) {
  passport::PacketType id_type(static_cast<passport::PacketType>(packet_type));
  passport::PacketType sig_type(static_cast<passport::PacketType>(signer_type));
  std::string name(passport_.IdentityPacketName(id_type, true));
  if (name.empty()) {
    LOG(kError) << "Failed to get packet name: " << index;
    OperationCallback(false, results, index);
    return;
  }
  name = pca::ApplyTypeToName(name, pca::kModifiableByOwner);

  std::shared_ptr<asymm::Keys> signer(new asymm::Keys(passport_.SignaturePacketDetails(sig_type,
                                                                                       true)));
  if (!remote_chunk_store_.Delete(name,
                                  [&] (bool result) {
                                    OperationCallback(result, results, index);
                                  },
                                  signer)) {
    LOG(kError) << "Failed to delete: " << index;
    OperationCallback(false, results, index);
  }
}

int UserCredentialsImpl::DeleteLid(const std::string& keyword,
                                   const std::string& pin) {
  std::string packet_name(pca::ApplyTypeToName(lid::LidName(keyword, pin),
                                               pca::kModifiableByOwner));
  // TODO(Alison) - should only be allowed to delete LID if self is only user of LID
  //                and have read-write access
  std::shared_ptr<asymm::Keys> signer(new asymm::Keys(
                                          passport_.SignaturePacketDetails(passport::kAnmid,
                                                                           true)));
  std::vector<int> individual_result(1, kPendingResult);
  boost::condition_variable condition_variable;
  boost::mutex mutex;
  OperationResults operation_result(mutex, condition_variable, individual_result);
  if (!remote_chunk_store_.Delete(packet_name,
                                  [&] (bool result) {
                                    OperationCallback(result, operation_result, 0);
                                  },
                                  signer)) {
    LOG(kError) << "Failed to delete LID.";
    OperationCallback(false, operation_result, 0);
  }
  int result = utils::WaitForResults(mutex, condition_variable, individual_result);
  if (result != kSuccess) {
    LOG(kError) << "Storing new LID timed out.";
    return result;
  }
  return individual_result.at(0);
}

int UserCredentialsImpl::ChangePassword(const std::string& new_password) {
  boost::mutex::scoped_lock loch_a_phuill(single_threaded_class_mutex_);

  std::string serialised_data_atlas;
  int result(SerialiseAndSetIdentity("", "", new_password, &serialised_data_atlas));
  if (result != kSuccess) {
    LOG(kError) << "Failure setting details of new session: " << result;
    return result;
  }

  result = DoChangePasswordAdditions();
  if (result != kSuccess) {
    LOG(kError) << "Failed to perform additions.";
    return result;
  }

  result = DoChangePasswordRemovals();
  if (result != kSuccess) {
    LOG(kError) << "Failed to perform removals.";
    return result;
  }

  result = passport_.ConfirmIdentityPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed to set new identity packets: " << result;
    return kSetIdentityPacketsFailure;
  }

  // TODO(Alison) - prevent changing password if other instances logged in.
  std::string lid_packet;
  LockingPacket locking_packet;
  result = GetAndLockLid(session_.keyword(),
                         session_.pin(),
                         session_.password(),
                         lid_packet,
                         locking_packet);
  if (result != kSuccess) {
    LOG(kError) << "Failed to lock LID.";
    return result;
  }
  result = ModifyLid(session_.keyword(), session_.pin(), new_password, locking_packet);
  if (result != kSuccess) {
    LOG(kError) << "Failed to modify LID.";
    return result;
  }

  session_.set_password(new_password);
  session_.set_serialised_data_atlas(serialised_data_atlas);
  session_.set_changed(false);

  return kSuccess;
}

int UserCredentialsImpl::DoChangePasswordAdditions() {
  std::vector<int> individual_results(4, kPendingResult);
  boost::condition_variable condition_variable;
  boost::mutex mutex;
  OperationResults new_results(mutex, condition_variable, individual_results);

  ModifyMid(new_results);
  ModifySmid(new_results);
  StoreTmid(new_results);
  StoreStmid(new_results);

  int result(utils::WaitForResults(mutex, condition_variable, individual_results));
  if (result != kSuccess) {
    LOG(kError) << "Failed to store new identity packets: Time out.";
    return kChangePasswordFailure;
  }

  LOG(kInfo) << "MID: " << individual_results.at(0)
             << ", SMID: " << individual_results.at(1)
             << ", TMID: " << individual_results.at(2)
             << ", STMID: " << individual_results.at(3);

  result = AssessJointResult(individual_results);
  if (result != kSuccess) {
    LOG(kError) << "One of the operations for Identity Packets failed. "
                << "Turn on INFO for feedback on which one. ";
    return kChangePasswordFailure;
  }

  return kSuccess;
}

int UserCredentialsImpl::DoChangePasswordRemovals() {
  // Delete old TMID, STMID
  std::vector<int> individual_results(4, kSuccess);
  boost::condition_variable condition_variable;
  boost::mutex mutex;
  individual_results[2] = kPendingResult;
  individual_results[3] = kPendingResult;
  OperationResults del_results(mutex, condition_variable, individual_results);
  DeleteTmid(del_results);
  DeleteStmid(del_results);

  int result(utils::WaitForResults(mutex, condition_variable, individual_results));
  if (result != kSuccess) {
    LOG(kError) << "Failed to store new identity packets: Time out.";
    return kChangePasswordFailure;
  }

  LOG(kInfo) << "TMID: " << individual_results.at(2)
             << ", STMID: " << individual_results.at(3);

  result = AssessJointResult(individual_results);
  if (result != kSuccess) {
    LOG(kError) << "One of the operations for Identity Packets failed. "
                << "Turn on INFO for feedback on which one. ";
    return kChangePasswordFailure;
  }

  return kSuccess;
}

int UserCredentialsImpl::SerialiseAndSetIdentity(const std::string& keyword,
                                                 const std::string& pin,
                                                 const std::string& password,
                                                 std::string* serialised_data_atlas) {
  BOOST_ASSERT(serialised_data_atlas);
  int result(session_.SerialiseDataAtlas(serialised_data_atlas));
  if (result != kSuccess || serialised_data_atlas->empty()) {
    LOG(kError) << "Failed to serialise session: " << result;
    return kSessionSerialisationFailure;
  }

  result = passport_.SetIdentityPackets(keyword.empty()? session_.keyword() : keyword,
                                        pin. empty() ? session_.pin() : pin,
                                        password.empty() ? session_.password() : password,
                                        *serialised_data_atlas,
                                        session_.serialised_data_atlas());

  if (result != kSuccess) {
    LOG(kError) << "Failed to set new identity packets: " << result;
    return kSetIdentityPacketsFailure;
  }

  return kSuccess;
}

int UserCredentialsImpl::DeleteUserCredentials() {
  int result(DeleteOldIdentityPackets());
  if (result != kSuccess) {
    LOG(kError) << "Failed to delete identity packets.";
    return result;
  }

  result = DeleteLid(session_.keyword(), session_.pin());
  if (result != kSuccess) {
    LOG(kError) << "Failed to delete LID.";
    return result;
  }

  result = DeleteSignaturePackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed to delete signature packets.";
    return result;
  }

  return kSuccess;
}

int UserCredentialsImpl::DeleteSignaturePackets() {
  std::vector<int> individual_results(4, kPendingResult);
  boost::condition_variable condition_variable;
  boost::mutex mutex;
  OperationResults results(mutex, condition_variable, individual_results);

  // ANMID path
  DeleteAnmid(results);
  // ANSMID path
  DeleteAnsmid(results);
  // ANTMID path
  DeleteAntmid(results);
  // PMID path: PMID, MAID, ANMAID
  DeletePmid(results);

  int result(utils::WaitForResults(mutex, condition_variable, individual_results));
  if (result != kSuccess) {
    LOG(kError) << "Wait for results timed out: " << result;
    LOG(kError) << "ANMID: " << individual_results.at(0)
              << ", ANSMID: " << individual_results.at(1)
              << ", ANTMID: " << individual_results.at(2)
              << ", PMID path: " << individual_results.at(3);
    return result;
  }
  LOG(kInfo) << "ANMID: " << individual_results.at(0)
             << ", ANSMID: " << individual_results.at(1)
             << ", ANTMID: " << individual_results.at(2)
             << ", PMID path: " << individual_results.at(3);

  result = AssessJointResult(individual_results);
  if (result != kSuccess) {
    LOG(kError) << "One of the operations for Anonymous Packets failed. "
                << "Turn on INFO for feedback on which one. ";
    return kDeleteSignaturePacketsFailure;
  }

  return kSuccess;
}

void UserCredentialsImpl::DeleteAnmid(OperationResults& results) {
  std::shared_ptr<asymm::Keys> anmid(
      new asymm::Keys(passport_.SignaturePacketDetails(passport::kAnmid, true)));
  DeleteSignaturePacket(anmid, results, 0);
}

void UserCredentialsImpl::DeleteAnsmid(OperationResults& results) {
  std::shared_ptr<asymm::Keys> ansmid(
      new asymm::Keys(passport_.SignaturePacketDetails(passport::kAnsmid, true)));
  DeleteSignaturePacket(ansmid, results, 1);
}

void UserCredentialsImpl::DeleteAntmid(OperationResults& results) {
  std::shared_ptr<asymm::Keys> antmid(
      new asymm::Keys(passport_.SignaturePacketDetails(passport::kAntmid, true)));
  DeleteSignaturePacket(antmid, results, 2);
}

void UserCredentialsImpl::DeletePmid(OperationResults& results) {
  asymm::Keys pmid(passport_.SignaturePacketDetails(passport::kPmid, true));
  std::shared_ptr<asymm::Keys> maid(
      new asymm::Keys(passport_.SignaturePacketDetails(passport::kMaid, true)));

  std::string pmid_name(pca::ApplyTypeToName(pmid.identity, pca::kSignaturePacket));
  if (!remote_chunk_store_.Delete(pmid_name,
                                  [&] (bool result) { DeleteMaid(result, results, maid); },
                                  maid)) {
    LOG(kError) << "Failed to delete PMID.";
    DeleteMaid(false, results, nullptr);
  }
}

void UserCredentialsImpl::DeleteMaid(bool result,
                                     OperationResults& results,
                                     std::shared_ptr<asymm::Keys> maid) {
  if (!result) {
    LOG(kError) << "Failed to delete PMID.";
    OperationCallback(false, results, 3);
    return;
  }

  std::shared_ptr<asymm::Keys> anmaid(
      new asymm::Keys(passport_.SignaturePacketDetails(passport::kAnmaid, true)));
  std::string maid_name(pca::ApplyTypeToName(maid->identity, pca::kSignaturePacket));
  if (!remote_chunk_store_.Delete(maid_name,
                                  [&] (bool result) {
                                    DeleteAnmaid(result, results, anmaid);
                                  },
                                  anmaid)) {
    LOG(kError) << "Failed to delete MAID.";
    DeleteAnmaid(false, results, nullptr);
  }
}

void UserCredentialsImpl::DeleteAnmaid(bool result,
                                       OperationResults& results,
                                       std::shared_ptr<asymm::Keys> anmaid) {
  if (!result) {
    LOG(kError) << "Failed to delete MAID.";
    OperationCallback(false, results, 3);
    return;
  }

  DeleteSignaturePacket(anmaid, results, 3);
}

void UserCredentialsImpl::DeleteSignaturePacket(std::shared_ptr<asymm::Keys> packet,
                                                OperationResults& results,
                                                int index) {
  std::string packet_name(pca::ApplyTypeToName(packet->identity, pca::kSignaturePacket));
  if (!remote_chunk_store_.Delete(packet_name,
                                  [&] (bool result) {
                                    OperationCallback(result, results, index);
                                  },
                                  packet)) {
    LOG(kError) << "Failed to delete packet: " << index;
    OperationCallback(false, results, index);
  }
}

void UserCredentialsImpl::SessionSaver(const bptime::seconds& interval,
                                       const boost::system::error_code& error_code) {
  LOG(kInfo) << "UserCredentialsImpl::SessionSaver!!! Wooohooooo";
  if (error_code) {
    if (error_code != boost::asio::error::operation_aborted) {
      LOG(kError) << "Refresh timer error: " << error_code.message();
    } else {
      return;
    }
  }

  if (!session_saver_timer_active_) {
    LOG(kInfo) << "Timer process cancelled.";
    return;
  }

  int result(UpdateLid(false));
  if (result != kSuccess) {
    LOG(kError) << "Failed to update LID: " << result;
    // TODO(Alison) - do anything else about this?
  } else {
    LOG(kInfo) << "SessionSaver - Updated LID.";
  }
  if (session_.state() == kLoggedIn) {
    int result(SaveSession(false));
    LOG(kInfo) << "Session saver result: " << result;
  } else {
    LOG(kInfo) << "Not fully logged in - don't save session";
  }

  session_saver_timer_.expires_from_now(bptime::seconds(interval));
  session_saver_timer_.async_wait([=] (const boost::system::error_code& error_code) {
                                    this->SessionSaver(bptime::seconds(interval), error_code);
                                  });
}

}  // namespace lifestuff

}  // namespace maidsafe
