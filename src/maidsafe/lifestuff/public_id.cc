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

#include "maidsafe/lifestuff/public_id.h"

#include <vector>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/maidsafe.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/utils.h"
#include "maidsafe/lifestuff/store_components/packet_manager.h"

namespace args = std::placeholders;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

namespace {

void SendContactInfoCallback(const int &response,
                             boost::mutex *mutex,
                             boost::condition_variable *cond_var,
                             int *result) {
  if (!mutex || !cond_var || !result)
    return;
  boost::mutex::scoped_lock lock(*mutex);
  *result = response;
  cond_var->notify_one();
}

std::string AppendableIdValue(const passport::SelectableIdentityData &data,
                              bool accepts_new_contacts,
                              const asymm::PrivateKey private_key,
                              int index) {
  pca::AppendableByAll contact_id;
  pca::SignedData *identity_key = contact_id.mutable_identity_key();
  pca::SignedData *allow_others_to_append =
      contact_id.mutable_allow_others_to_append();

  std::string public_key;
  asymm::EncodePublicKey(std::get<1>(data.at(index)), &public_key);
  identity_key->set_data(public_key);
  identity_key->set_signature(std::get<2>(data.at(index)));
  allow_others_to_append->set_data(accepts_new_contacts ?
                                      std::string(1, pca::kAppendableByAll) :
                                      std::string(1, pca::kModifiableByOwner));

  asymm::Signature packet_signature;
  int result(asymm::Sign(allow_others_to_append->data(),
                         private_key,
                         &packet_signature));
  if (result != kSuccess) {
    DLOG(ERROR) << "AppendableIdValue - Failed to sign";
    return "";
  }

  allow_others_to_append->set_signature(packet_signature);

  return contact_id.SerializeAsString();
}

std::string AnmpidName(const passport::SelectableIdentityData &data) {
  return std::get<0>(data.at(0)) + std::string (1, pca::kSignaturePacket);
}

std::string AnmpidValue(const passport::SelectableIdentityData &data) {
  std::string public_key;
  asymm::EncodePublicKey(std::get<1>(data.at(0)), &public_key);
  pca::SignedData packet;
  packet.set_data(public_key);
  packet.set_signature(std::get<2>(data.at(0)));
  return packet.SerializeAsString();
}

std::string MpidName(const passport::SelectableIdentityData &data) {
  return std::get<0>(data.at(1)) + std::string (1, pca::kSignaturePacket);
}

std::string MpidValue(const passport::SelectableIdentityData &data) {
  std::string public_key;
  asymm::EncodePublicKey(std::get<1>(data.at(1)), &public_key);
  pca::SignedData packet;
  packet.set_data(public_key);
  packet.set_signature(std::get<2>(data.at(1)));
  return packet.SerializeAsString();
}

std::string MaidsafeContactIdName(const std::string &public_username) {
  return crypto::Hash<crypto::SHA512>(public_username) +
         std::string (1, pca::kAppendableByAll);
}

std::string MaidsafeContactIdValue(const passport::SelectableIdentityData &data,
                                   bool accepts_new_contacts,
                                   const asymm::PrivateKey private_key) {
  return AppendableIdValue(data, accepts_new_contacts, private_key, 1);
}

std::string MaidsafeInboxName(const passport::SelectableIdentityData &data) {
  return std::get<0>(data.at(2)) + std::string (1, pca::kAppendableByAll);
}

std::string MaidsafeInboxValue(const passport::SelectableIdentityData &data,
                               const asymm::PrivateKey private_key) {
  return AppendableIdValue(data, true, private_key, 2);
}

}  // namespace

PublicId::PublicId(std::shared_ptr<PacketManager> packet_manager,
                   std::shared_ptr<Session> session,
                   boost::asio::io_service &asio_service)  // NOLINT (Fraser)
    : packet_manager_(packet_manager),
      session_(session),
      asio_service_(asio_service),
      get_new_contacts_timer_(asio_service),
      new_contact_signal_(new NewContactSignal),
      contact_confirmed_signal_(new ContactConfirmedSignal) {}

PublicId::~PublicId() {
  StopCheckingForNewContacts();
}

int PublicId::StartCheckingForNewContacts(bptime::seconds interval) {
  std::vector<passport::SelectableIdData> selectables;
  session_->passport_->SelectableIdentitiesList(&selectables);
  if (selectables.empty()) {
    DLOG(ERROR) << "No public username set";
    return kNoPublicIds;
  }
  get_new_contacts_timer_.expires_from_now(interval);
  get_new_contacts_timer_.async_wait(std::bind(&PublicId::GetNewContacts,
                                               this,
                                               interval,
                                               std::placeholders::_1));
  return kSuccess;
}

void PublicId::StopCheckingForNewContacts() {
  get_new_contacts_timer_.cancel();
}

int PublicId::CreatePublicId(const std::string &public_username,
                             bool accepts_new_contacts) {
  if (public_username.empty()) {
    DLOG(ERROR) << "Public ID name empty";
    return kPublicIdEmpty;
  }

  // Check chosen name is available
  if (!packet_manager_->KeyUnique(MaidsafeContactIdName(public_username), "")) {
    DLOG(ERROR) << "Public ID with name " << public_username << " unavailable";
    return kPublicIdExists;
  }

  // Create packets (pending) in passport
  int result(session_->passport_->CreateSelectableIdentity(public_username));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to create Public ID with name " << public_username;
    return result;
  }

  passport::SelectableIdentityData data;
  // Retrieves ANMPID, MPID, and MMID's <name, value, signature>
  result = session_->passport_->GetSelectableIdentityData(public_username,
                                                          false,
                                                          &data);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get own public ID data: " << result;
    return kGetPublicIdError;
  }
  BOOST_ASSERT(data.size() == 3U);

  // Store packets
  boost::mutex mutex;
  boost::condition_variable cond_var;
  int anmpid_result(kPendingResult),
      mpid_result(kPendingResult),
      mmid_result(kPendingResult),
      msid_result(kPendingResult);
  asymm::PrivateKey inbox_private_key(session_->passport_->PacketPrivateKey(
                                          passport::kMmid,
                                          false,
                                          public_username));
  asymm::PrivateKey contact_id_private_key(
      session_->passport_->PacketPrivateKey(passport::kMpid,
                                            false,
                                            public_username));

  packet_manager_->StorePacket(MaidsafeInboxName(data),
                               MaidsafeInboxValue(data, inbox_private_key),
                               std::get<0>(data.at(2)),
                               std::bind(&SendContactInfoCallback, args::_1,
                                         &mutex, &cond_var, &msid_result));
  packet_manager_->StorePacket(AnmpidName(data),
                               AnmpidValue(data),
                               std::get<0>(data.at(0)),
                               std::bind(&SendContactInfoCallback, args::_1,
                                         &mutex, &cond_var, &anmpid_result));
  packet_manager_->StorePacket(MpidName(data),
                               MpidValue(data),
                               std::get<0>(data.at(0)),
                               std::bind(&SendContactInfoCallback, args::_1,
                                         &mutex, &cond_var, &mpid_result));
  packet_manager_->StorePacket(MaidsafeContactIdName(public_username),
                               MaidsafeContactIdValue(data,
                                                      accepts_new_contacts,
                                                      contact_id_private_key),
                               std::get<0>(data.at(1)),
                               std::bind(&SendContactInfoCallback, args::_1,
                                         &mutex, &cond_var, &mmid_result));
  try {
    boost::mutex::scoped_lock lock(mutex);
    if (!cond_var.timed_wait(lock,
                             bptime::seconds(30),
                             [&]()->bool {
                               return anmpid_result != kPendingResult &&
                                      mpid_result != kPendingResult &&
                                      mmid_result != kPendingResult &&
                                      msid_result != kPendingResult;
                             })) {
      DLOG(ERROR) << "Timed out storing packets.";
      return kPublicIdTimeout;
    }
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Failed to store packets: " << e.what();
    return kPublicIdException;
  }
  if (anmpid_result != kSuccess || mpid_result != kSuccess ||
      mmid_result != kSuccess || msid_result != kSuccess) {
    DLOG(ERROR) << "Failed to store packets.  ANMPID: " << anmpid_result
                << "   MPID: " << mpid_result << "   MMID: " << mmid_result
                << "   MSID: " << msid_result;
    return kStorePublicIdFailure;
  }

  // Confirm packets as stored
  result = session_->passport_->ConfirmSelectableIdentity(public_username);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to confirm Public ID with name " << public_username;
    return result;
  }
  return kSuccess;
}

int PublicId::SendContactInfo(const std::string &public_username,
                              const std::string &recipient_public_username) {
  // Get our MMID name, and MPID private key
  passport::SelectableIdentityData data;
  // Retrieves ANMPID, MPID, and MMID's <name, value, signature>
  int result(session_->passport_->GetSelectableIdentityData(public_username,
                                                            true,
                                                            &data));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get own public ID data: " << result;
    return kGetPublicIdError;
  }
  BOOST_ASSERT(data.size() == 3U);

  // Get recipient's public key
  asymm::PublicKey recipient_public_key;
  result = GetValidatedMpidPublicKey(recipient_public_username,
                                     std::get<0>(data.at(1)),
                                     packet_manager_,
                                     &recipient_public_key);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get public key for " << recipient_public_username;
    return result;
  }

  std::vector<passport::SelectableIdData> selectables;
  session_->passport_->SelectableIdentitiesList(&selectables);
  passport::SelectableIdData selectable_id;
  auto it(std::find_if(selectables.begin(),
                       selectables.end(),
                       [public_username]
                           (const passport::SelectableIdData &selectable) {
                         return (std::get<0>(selectable) == public_username);
                       }));

  if (it == selectables.end()) {
    DLOG(ERROR) << "Failed to get own MPID private key";
    return kGetPublicIdError;
  }

  // Create MCID, encrypted for recipient
  std::string mmid_name(std::get<0>(data.at(2)));
  std::string encrypted_mmid_name;
  result = asymm::Encrypt(mmid_name,
                          recipient_public_key,
                          &encrypted_mmid_name);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to encrypt MCID's MMID name: " << result;
    return kEncryptingError;
  }

  std::string encrypted_public_username;
  result = asymm::Encrypt(public_username,
                          recipient_public_key,
                          &encrypted_public_username);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to encrypt MCID's public username: " << result;
    return kEncryptingError;
  }

  pca::Introduction introduction;
  introduction.set_mmid_name(encrypted_mmid_name);
  introduction.set_public_username(encrypted_public_username);

  asymm::Signature signature;
  result = asymm::Sign(introduction.SerializeAsString(),
                       std::get<2>(*it),
                       &signature);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to sign MCID data: " << result;
    return kSigningError;
  }

  // Store encrypted MCID at recipient's MPID's name
  boost::mutex mutex;
  boost::condition_variable cond_var;
  result = kPendingResult;
  VoidFuncOneInt callback(std::bind(&SendContactInfoCallback, args::_1, &mutex,
                                    &cond_var, &result));

  pca::SignedData signed_data;
  signed_data.set_data(introduction.SerializeAsString());
  signed_data.set_signature(signature);
  packet_manager_->ModifyPacket(
      MaidsafeContactIdName(recipient_public_username),
      signed_data.SerializeAsString(),
      std::get<0>(data.at(1)),
      callback);

  try {
    boost::mutex::scoped_lock lock(mutex);
    if (!cond_var.timed_wait(lock,
                             bptime::seconds(30),
                             [&result]()->bool {
                               return result != kPendingResult;
                             })) {
      DLOG(ERROR) << "Timed out storing packet.";
      return kPublicIdTimeout;
    }
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Failed to store packet: " << e.what();
    return kPublicIdException;
  }
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to store packet.  Result: " << result;
    return kSendContactInfoFailure;
  }

  session_->contacts_handler()->AddContact(recipient_public_username, "", "",
                                           "", "", '\0', 0, 0, "", 'U', 0, 0);

  return kSuccess;
}

int PublicId::DisablePublicId(const std::string &public_username) {
  int result(ModifyAppendability(public_username, pca::kModifiableByOwner));
  if (result != kSuccess)
    DLOG(ERROR) << "Failed to Disable PublicId";
  return result;
}

int PublicId::EnablePublicId(const std::string &public_username) {
  int result(ModifyAppendability(public_username, pca::kAppendableByAll));
  if (result != kSuccess)
    DLOG(ERROR) << "Failed to Enable PublicId";
  return result;
}

int PublicId::ModifyAppendability(const std::string &public_username,
                                  const char appendability) {
  if (public_username.empty()) {
    DLOG(ERROR) << "Public ID name empty";
    return kPublicIdEmpty;
  }

  // Retrieves ANMPID, MPID, and MMID's <name, value, signature>
  passport::SelectableIdentityData data;
  int result(session_->passport_->GetSelectableIdentityData(public_username,
                                                            true,
                                                            &data));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get own public ID data: " << result;
    return kGetPublicIdError;
  }
  BOOST_ASSERT(data.size() == 3U);

  // Retriveves own MPID, MMID private keys
  asymm::PrivateKey MPID_private_key(
      session_->passport_->PacketPrivateKey(passport::kMpid,
                                            true,
                                            public_username));
  asymm::PrivateKey MMID_private_key(
      session_->passport_->PacketPrivateKey(passport::kMmid,
                                            true,
                                            public_username));
  // Composes ModifyAppendableByAll packet disabling appendability
  std::string appendability_string(1, appendability);
  pca::SignedData signed_allow_others_to_append;
  std::string signature;

  rsa::Sign(appendability_string, MPID_private_key, &signature);
  signed_allow_others_to_append.set_data(appendability_string);
  signed_allow_others_to_append.set_signature(signature);
  pca::ModifyAppendableByAll modify_mcid;
  modify_mcid.mutable_allow_others_to_append()
      ->CopyFrom(signed_allow_others_to_append);

  signature.clear();
  rsa::Sign(appendability_string, MMID_private_key, &signature);
  signed_allow_others_to_append.set_signature(signature);
  pca::ModifyAppendableByAll modify_mmid;
  modify_mmid.mutable_allow_others_to_append()
      ->CopyFrom(signed_allow_others_to_append);

  // Invalidates the MCID,MMID by modify them as kModifiableByOwner via
  // ModifyAppendableByAll packet
  boost::mutex mutex;
  boost::condition_variable cond_var;
  int mcid_result(kPendingResult), mmid_result(kPendingResult);
  packet_manager_->ModifyPacket(
      MaidsafeContactIdName(public_username),
      modify_mcid.SerializeAsString(),
      std::get<0>(data.at(1)),
      std::bind(&SendContactInfoCallback, args::_1,
                &mutex, &cond_var, &mcid_result));
  packet_manager_->ModifyPacket(
      MaidsafeInboxName(data),
      modify_mmid.SerializeAsString(),
      std::get<0>(data.at(2)),
      std::bind(&SendContactInfoCallback, args::_1,
                &mutex, &cond_var, &mmid_result));
  try {
    boost::mutex::scoped_lock lock(mutex);
    if (!cond_var.timed_wait(lock,
                             bptime::seconds(30),
                             [&]()->bool {
                               return mcid_result != kPendingResult &&
                                      mmid_result != kPendingResult;
                             })) {
      DLOG(ERROR) << "Timed out modifying MCID/MMID when disable public_id.";
      return kPublicIdTimeout;
    }
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Failed to modifying MCID/MMID when disable public_id: "
                << e.what();
    return kPublicIdException;
  }
  if (mcid_result != kSuccess || mmid_result != kSuccess) {
    DLOG(ERROR) << "Failed to modifying MCID/MMID when disable public_id.  "
                << " with MCID Result : " << mcid_result
                << " , MMID result :" << mmid_result;
    return kModifyFailure;
  }

  return kSuccess;
}

PublicId::NewContactSignalPtr PublicId::new_contact_signal() const {
  return new_contact_signal_;
}

PublicId::ContactConfirmedSignalPtr PublicId::contact_confirmed_signal() const {
  return contact_confirmed_signal_;
}

void PublicId::GetNewContacts(const bptime::seconds &interval,
                              const boost::system::error_code &error_code) {
  if (error_code) {
    if (error_code != ba::error::operation_aborted) {
      DLOG(ERROR) << "Refresh timer error: " << error_code.message();
    } else {
      return;
    }
  }

  std::vector<passport::SelectableIdData> selectables;
  session_->passport_->SelectableIdentitiesList(&selectables);
  for (auto it(selectables.begin()); it != selectables.end(); ++it) {
    if (std::get<3>(*it)) {
      passport::SelectableIdentityData data;
      session_->passport_->GetSelectableIdentityData(std::get<0>(*it),
                                                     true,
                                                     &data);
      std::vector<std::string> mpid_values;
      int result(packet_manager_->GetPacket(
                     MaidsafeContactIdName(std::get<0>(*it)),
                     std::get<0>(data.at(1)),
                     &mpid_values));
      if (result == kSuccess) {
        ProcessRequests(*it, mpid_values);
      } else if (result == kGetPacketEmptyData) {
        DLOG(INFO) << "No new add requests for " << std::get<0>(*it);
      } else {
        DLOG(ERROR) << "Failed to get MPID contents for " << std::get<0>(*it)
                    << ": " << result;
      }
    }
  }

  get_new_contacts_timer_.expires_at(get_new_contacts_timer_.expires_at() +
                                     interval);
  get_new_contacts_timer_.async_wait(std::bind(&PublicId::GetNewContacts,
                                               this,
                                               interval,
                                               std::placeholders::_1));
}

void PublicId::ProcessRequests(const passport::SelectableIdData &data,
                               const std::vector<std::string> &mpid_values) {
  BOOST_ASSERT(mpid_values.size() == 1U);
  pca::AppendableByAll mcid;
  if (!mcid.ParseFromString(mpid_values.at(0))) {
    DLOG(ERROR) << "Failed to parse as AppendableByAll";
    return;
  }

  for (int it(0); it < mcid.appendices_size(); ++it) {
    pca::Introduction introduction;
    if (!introduction.ParseFromString(mcid.appendices(it).data())) {
      DLOG(ERROR) << "Failed to parse as Introduction";
      continue;
    }

    std::string mmid_name;
    int n(asymm::Decrypt(introduction.mmid_name(),
                         std::get<2>(data),
                         &mmid_name));
    if (n != kSuccess || mmid_name.empty()) {
      DLOG(ERROR) << "Failed to decrypt MMID name: " << n;
      continue;
    } else {
      DLOG(ERROR) << "MMID name received in contact: "
                  << Base32Substr(mmid_name);
    }
    std::string public_username;
    n = asymm::Decrypt(introduction.public_username(),
                       std::get<2>(data),
                       &public_username);
    if (n != kSuccess || public_username.empty()) {
      DLOG(ERROR) << "Failed to decrypt public username: " << n;
      continue;
    }

    // TODO(Team#5#): 2011-12-02 - Validate signature of each Introduction

    mi_contact mic;
    n = session_->contacts_handler()->GetContactInfo(public_username, &mic);
    if (n == 0 && mic.confirmed_ == 'U') {
      if (session_->contacts_handler()->UpdateContactConfirmed(public_username,
                                                               'C') == 0 &&
          session_->contacts_handler()->UpdateContactKey(public_username,
                                                         mmid_name) == 0) {
        (*contact_confirmed_signal_)(public_username);
      }
    } else {
      session_->contacts_handler()->AddContact(public_username,
                                               mmid_name,
                                               "", "", "", '\0', 0,
                                               0, "", 'P', 0, 0);
      (*new_contact_signal_)(std::get<0>(data), public_username);
    }
  }
}

int PublicId::ConfirmContact(const std::string &public_username,
                             const std::string &recipient_public_username) {
  mi_contact mic;
  int result(session_->contacts_handler()->GetContactInfo(
                 recipient_public_username,
                 &mic));
  if (result != 0 || mic.confirmed_ != 'P') {
    DLOG(ERROR) << "No such pending username found: "
                << recipient_public_username;
    return -1;
  }

  result = SendContactInfo(public_username, recipient_public_username);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to send confirmation to "
                << recipient_public_username;
    return -1;
  }

  if (session_->contacts_handler()->UpdateContactConfirmed(
          recipient_public_username, 'C') != 0) {
    DLOG(ERROR) << "Failed to confirm " << recipient_public_username;
    return -1;
  }

  return kSuccess;
}

std::vector<std::string> PublicId::ContactList() const {
  std::vector<std::string> contacts;
  std::vector<mi_contact> session_contacts;
  int n(session_->contacts_handler()->GetContactList(&session_contacts, 2));
  if (n != 0) {
    DLOG(ERROR) << "Failed to retrive list";
  } else {
    for (auto it(session_contacts.begin()); it != session_contacts.end(); ++it)
      contacts.push_back((*it).pub_name_);
  }
  return contacts;
}

std::vector<std::string> PublicId::PublicIdsList() const {
  std::vector<std::string> public_ids;
  std::vector<passport::SelectableIdData> selectables;
  session_->passport_->SelectableIdentitiesList(&selectables);
  for (auto it(selectables.begin()); it != selectables.end(); ++it)
    public_ids.push_back(std::get<0>(*it));
  return public_ids;
}

}  // namespace lifestuff

}  // namespace maidsafe
