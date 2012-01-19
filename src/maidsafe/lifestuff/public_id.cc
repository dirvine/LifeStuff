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
#include "maidsafe/lifestuff/return_codes.h"
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

std::string ComposeModifyAppendableByAll(const asymm::PrivateKey &signing_key,
                                         const char appendability) {
  std::string appendability_string(1, appendability);
  pca::SignedData signed_data;
  std::string signature;

  asymm::Sign(appendability_string, signing_key, &signature);
  signed_data.set_data(appendability_string);
  signed_data.set_signature(signature);
  pca::ModifyAppendableByAll modify;
  modify.mutable_allow_others_to_append()->CopyFrom(signed_data);
  return modify.SerializeAsString();
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

std::string MaidsafeInboxName(const std::string &data) {
  return data + std::string (1, pca::kAppendableByAll);
}

std::string MaidsafeInboxValue(const passport::SelectableIdentityData &data,
                               const asymm::PrivateKey private_key) {
  return AppendableIdValue(data, true, private_key, 2);
}

std::string MaidsafeInboxValue(const passport::PacketData &data,
                               const asymm::PrivateKey private_key) {
  pca::AppendableByAll contact_id;
  pca::SignedData *identity_key = contact_id.mutable_identity_key();
  pca::SignedData *allow_others_to_append =
      contact_id.mutable_allow_others_to_append();

  std::string public_key;
  asymm::EncodePublicKey(std::get<1>(data), &public_key);
  identity_key->set_data(public_key);
  identity_key->set_signature(std::get<2>(data));
  allow_others_to_append->set_data(std::string(1, pca::kAppendableByAll));

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
  std::vector<int> results;
  results.push_back(kPendingResult);
  results.push_back(kPendingResult);
  results.push_back(kPendingResult);
  results.push_back(kPendingResult);
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
                                         &mutex, &cond_var, &results[0]));
  packet_manager_->StorePacket(AnmpidName(data),
                               AnmpidValue(data),
                               std::get<0>(data.at(0)),
                               std::bind(&SendContactInfoCallback, args::_1,
                                         &mutex, &cond_var, &results[1]));
  packet_manager_->StorePacket(MpidName(data),
                               MpidValue(data),
                               std::get<0>(data.at(0)),
                               std::bind(&SendContactInfoCallback, args::_1,
                                         &mutex, &cond_var, &results[2]));
  packet_manager_->StorePacket(MaidsafeContactIdName(public_username),
                               MaidsafeContactIdValue(data,
                                                      accepts_new_contacts,
                                                      contact_id_private_key),
                               std::get<0>(data.at(1)),
                               std::bind(&SendContactInfoCallback, args::_1,
                                         &mutex, &cond_var, &results[3]));
  result = AwaitingResponse(mutex, cond_var, results);
  if (result != kSuccess)
    return result;

  if (results[0] != kSuccess || results[1] != kSuccess ||
      results[2] != kSuccess || results[3] != kSuccess) {
    DLOG(ERROR) << "Failed to store packets.  ANMPID: " << results[1]
                << "   MPID: " << results[2] << "   MMID: " << results[3]
                << "   MSID: " << results[0];
    return kStorePublicIdFailure;
  }

  // Confirm packets as stored
  result = session_->passport_->ConfirmSelectableIdentity(public_username);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to confirm Public ID with name " << public_username;
    return result;
  }

  auto n(session_->contact_handler_map().insert(
             std::make_pair(public_username,
                            ContactsHandlerPtr(new ContactsHandler))));
  if (!n.second) {
    DLOG(ERROR) << "Failed to add contact handler for " << public_username;
    return result;
  }

  return kSuccess;
}

int PublicId::SendContactInfo(const std::string &public_username,
                              const std::string &recipient_public_username,
                              bool add_contact) {
  std::vector<std::string> contacts;
  contacts.push_back(recipient_public_username);
  int result(InformContactInfo(public_username, contacts));
  if (result == kSuccess && add_contact)
    result = session_->contact_handler_map()[public_username]->AddContact(
                 recipient_public_username,
                 "", "",
                 asymm::PublicKey(),
                 asymm::PublicKey(),
                 kRequestSent,
                 0, 0);
  return result;
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
  // Change appendability of MCID,MMID by modify them via ModifyAppendableByAll
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);
  results.push_back(kPendingResult);
  packet_manager_->ModifyPacket(
      MaidsafeContactIdName(public_username),
      ComposeModifyAppendableByAll(MPID_private_key, appendability),
      std::get<0>(data.at(1)),
      std::bind(&SendContactInfoCallback, args::_1,
                &mutex, &cond_var, &results[0]));
  packet_manager_->ModifyPacket(
      MaidsafeInboxName(data),
      ComposeModifyAppendableByAll(MMID_private_key, appendability),
      std::get<0>(data.at(2)),
      std::bind(&SendContactInfoCallback, args::_1,
                &mutex, &cond_var, &results[1]));
  result = AwaitingResponse(mutex, cond_var, results);
  if (result != kSuccess)
    return result;

  if (results[0] != kSuccess || results[1] != kSuccess) {
    DLOG(ERROR) << "Failed to modifying MCID/MMID when modify public_id.  "
                << " with MCID Result : " << results[0]
                << " , MMID result :" << results[1];
    return kModifyAppendabilityFailure;
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
      DLOG(WARNING) << "Refresh timer error: " << error_code.message();
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
      DLOG(INFO) << "MMID name received in contact: "
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

    Contact mic;
    n = session_->contact_handler_map()[std::get<0>(data)]->ContactInfo(
            public_username,
            &mic);
    if (n == kSuccess) {
      if (mic.status == kRequestSent) {
        int stat(session_->contact_handler_map()[std::get<0>(data)]->UpdateStatus(
                    public_username,
                    kConfirmed));
        int mmid(
            session_->contact_handler_map()[std::get<0>(data)]->UpdateMmidName(
                public_username,
                mmid_name));
        if (stat == kSuccess && mmid == kSuccess) {
          (*contact_confirmed_signal_)(public_username);
        }
      } else if (mic.status == kConfirmed) {
        int mmid(
            session_->contact_handler_map()[std::get<0>(data)]->UpdateMmidName(
                public_username,
                mmid_name));
        if (mmid != kSuccess) {
          DLOG(ERROR) << "Failed to update MMID";
        }
      }
    } else {
      n = session_->contact_handler_map()[std::get<0>(data)]->AddContact(
              public_username,
              "",
              mmid_name,
              asymm::PublicKey(),
              asymm::PublicKey(),
              kPendingResponse,
              0, 0);
      if (n == kSuccess)
        (*new_contact_signal_)(std::get<0>(data), public_username);
    }
  }
}

int PublicId::ConfirmContact(const std::string &public_username,
                             const std::string &recipient_public_username) {
  Contact mic;
  int result(session_->contact_handler_map()[public_username]->ContactInfo(
                 recipient_public_username,
                 &mic));
  if (result != 0 || mic.status != kPendingResponse) {
    DLOG(ERROR) << "No such pending username found: "
                << recipient_public_username;
    return -1;
  }

  result = SendContactInfo(public_username, recipient_public_username, false);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to send confirmation to "
                << recipient_public_username;
    return -1;
  }

  if (session_->contact_handler_map()[public_username]->UpdateStatus(
          recipient_public_username,
          kConfirmed) != 0) {
    DLOG(ERROR) << "Failed to confirm " << recipient_public_username;
    return -1;
  }

  return kSuccess;
}

int PublicId::RemoveContact(const std::string &public_username,
                            const std::string &contact_name) {
  if (public_username.empty() || contact_name.empty()) {
    DLOG(ERROR) << "Public ID name empty";
    return kPublicIdEmpty;
  }

  if (session_->contact_handler_map()[public_username]->TouchContact(
               contact_name) != kSuccess)
    return kLiveContactNotFound;

  asymm::PrivateKey old_inbox_private_key(
      session_->passport_->PacketPrivateKey(passport::kMmid,
                                            true,
                                            public_username));
  // Generate a new MMID and store it
  passport::PacketData new_MMID, old_MMID;
  int result(session_->passport_->MoveMaidsafeInbox(public_username,
                                                    &old_MMID,
                                                    &new_MMID));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to generate a new MMID: " << result;
    return kGenerateNewMMIDFailure;
  }

  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);
  asymm::PrivateKey new_inbox_private_key(
      session_->passport_->PacketPrivateKey(passport::kMmid,
                                            false,
                                            public_username));
  packet_manager_->StorePacket(MaidsafeInboxName(std::get<0>(new_MMID)),
                               MaidsafeInboxValue(new_MMID,
                                                  new_inbox_private_key),
                               std::get<0>(new_MMID),
                               std::bind(&SendContactInfoCallback, args::_1,
                                         &mutex, &cond_var,
                                         &results[0]));
  result = AwaitingResponse(mutex, cond_var, results);
  if (result != kSuccess)
    return result;
  if (results[0] != kSuccess) {
    DLOG(ERROR) << "Failed to store new MMID when remove a contact.";
    return kModifyFailure;
  }

  result = session_->contact_handler_map()[public_username]->DeleteContact(
               contact_name);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to remove contact : " << contact_name;
    return result;
  }
  // Invalidate previous MMID, i.e. put it into kModifiableByOwner
  results.clear();
  results.push_back(kPendingResult);
  packet_manager_->ModifyPacket(
      MaidsafeInboxName(std::get<0>(old_MMID)),
      ComposeModifyAppendableByAll(old_inbox_private_key,
                                   pca::kModifiableByOwner),
      std::get<0>(old_MMID),
      std::bind(&SendContactInfoCallback, args::_1,
                &mutex, &cond_var, &results[0]));
  result = AwaitingResponse(mutex, cond_var, results);
  if (result != kSuccess)
    return result;
  if (results[0] != kSuccess) {
    DLOG(ERROR) << "Failed to invalidate previous MMID when remove a contact.";
    return kModifyFailure;
  }

  session_->passport_->ConfirmMovedMaidsafeInbox(public_username);
  // Informs each contact in the list about the new MMID
  result = InformContactInfo(public_username, ContactList(public_username));

  return result;
}

int PublicId::InformContactInfo(const std::string &public_username,
                                const std::vector<std::string> &contacts) {
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
  std::string mmid_name(std::get<0>(data.at(2)));

  // Retrieves MPID private_key
  asymm::PrivateKey MPID_private_key(
      session_->passport_->PacketPrivateKey(passport::kMpid,
                                            true,
                                            public_username));
  // Inform each contat in the contact list of the MMID contact info
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  int size(contacts.size());

  for (int i = 0; i < size; ++i) {
    std::string recipient_public_username(contacts[i]);
    // Get recipient's public key
    asymm::PublicKey recipient_public_key;
    int result(GetValidatedMpidPublicKey(recipient_public_username,
                                         std::get<0>(data.at(1)),
                                         packet_manager_,
                                         &recipient_public_key));
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed to get public key for "
                  << recipient_public_username;
      return result;
    }
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
                         MPID_private_key,
                         &signature);
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed to sign MCID data: " << result;
      return kSigningError;
    }
    pca::SignedData signed_data;
    signed_data.set_data(introduction.SerializeAsString());
    signed_data.set_signature(signature);

    // Store encrypted MCID at recipient's MPID's name
    results.push_back(kPendingResult);
    packet_manager_->ModifyPacket(
        MaidsafeContactIdName(recipient_public_username),
        signed_data.SerializeAsString(),
        std::get<0>(data.at(1)),
        std::bind(&SendContactInfoCallback, args::_1, &mutex,
                  &cond_var, &results[i]));
  }
  result = AwaitingResponse(mutex, cond_var, results);
  if (result != kSuccess)
    return result;

  for (int i = 0; i < size; ++i) {
    if (results[i] != kSuccess)
      return kSendContactInfoFailure;
  }

  return kSuccess;
}

int PublicId::AwaitingResponse(boost::mutex &mutex,
                               boost::condition_variable &cond_var,
                               std::vector<int> &results) {
  int size(results.size());
  try {
    boost::mutex::scoped_lock lock(mutex);
    if (!cond_var.timed_wait(lock,
                             bptime::seconds(30),
                             [&]()->bool {
                               for (int i = 0; i < size; ++i) {
                                 if (results[i] == kPendingResult)
                                   return false;
                               }
                               return true;
                             })) {
      DLOG(ERROR) << "Timed out during waiting response.";
      return kPublicIdTimeout;
    }
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Exception Failure during waiting response : " << e.what();
    return kPublicIdException;
  }
  return kSuccess;
}

std::vector<std::string> PublicId::ContactList(
    const std::string &public_username) const {
  std::vector<std::string> contacts;
  std::vector<Contact> session_contacts;
  int n(session_->contact_handler_map()[public_username]->OrderedContacts(
            &session_contacts,
            kLastContacted));
  if (n != 0) {
    DLOG(ERROR) << "Failed to retrive list";
  } else {
    for (auto it(session_contacts.begin()); it != session_contacts.end(); ++it)
      contacts.push_back((*it).public_username);
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
