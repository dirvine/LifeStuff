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
#include "maidsafe/lifestuff/data_atlas_pb.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/rcs_helper.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/utils.h"

namespace args = std::placeholders;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

namespace {

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

std::string MaidsafeContactIdName(const std::string &public_id) {
  return crypto::Hash<crypto::SHA512>(public_id) +
         std::string(1, pca::kAppendableByAll);
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

std::vector<std::string> MapToVector(
    const std::map<std::string, ContactStatus> &map) {
  std::vector<std::string> vector;
  for (auto it(map.begin()); it != map.end(); ++it)
    vector.push_back((*it).first);
  return vector;
}

}  // namespace

PublicId::PublicId(
    std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
    std::shared_ptr<Session> session,
    ba::io_service &asio_service)  // NOLINT (Fraser)
    : remote_chunk_store_(remote_chunk_store),
      session_(session),
      get_new_contacts_timer_(asio_service),
      check_online_contacts_timer_(asio_service),
      new_contact_signal_(new NewContactSignal),
      contact_confirmed_signal_(new ContactConfirmedSignal),
      asio_service_(asio_service) {}

PublicId::~PublicId() {
  StopCheckingForNewContacts();
}

void PublicId::StartUp(bptime::seconds interval) {
  GetContactsHandle();
  StartCheckingForNewContacts(interval);
}

void PublicId::ShutDown() { StopCheckingForNewContacts(); }

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

int PublicId::CreatePublicId(const std::string &public_id,
                             bool accepts_new_contacts) {
  if (public_id.empty()) {
    DLOG(ERROR) << "Public ID name empty";
    return kPublicIdEmpty;
  }

  // Create packets (pending) in passport
  int result(session_->passport_->CreateSelectableIdentity(public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to create Public ID with name " << public_id;
    return result;
  }

  passport::SelectableIdentityData data;
  // Retrieves ANMPID, MPID, and MMID's <name, value, signature>
  result = session_->passport_->GetSelectableIdentityData(public_id,
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
                                          public_id));
  asymm::PrivateKey contact_id_private_key(
      session_->passport_->PacketPrivateKey(passport::kMpid,
                                            false,
                                            public_id));
  pcs::RemoteChunkStore::ValidationData validation_data_mmid;
  pcs::RemoteChunkStore::ValidationData validation_data_mpid;
  pcs::RemoteChunkStore::ValidationData validation_data_anmpid;
  KeysAndProof(public_id, passport::kMmid, false, &validation_data_mmid);
  KeysAndProof(public_id, passport::kMpid, false, &validation_data_mpid);
  KeysAndProof(public_id,
               passport::kAnmpid,
               false,
               &validation_data_anmpid);

  std::string inbox_name(MaidsafeInboxName(data));
  VoidFunctionOneBool callback(std::bind(&SendContactInfoCallback, args::_1,
                                         &mutex, &cond_var, &results[0]));
  remote_chunk_store_->Store(inbox_name,
                             MaidsafeInboxValue(
                                 data,
                                 validation_data_mmid.key_pair.private_key),
                             callback,
                             validation_data_mmid);

  std::string anmpid_name(AnmpidName(data));
  callback = std::bind(&SendContactInfoCallback, args::_1,
                       &mutex, &cond_var, &results[1]);
  remote_chunk_store_->Store(anmpid_name,
                             AnmpidValue(data),
                             callback,
                             validation_data_anmpid);

  std::string mpid_name(MpidName(data));
  callback = std::bind(&SendContactInfoCallback, args::_1,
                       &mutex, &cond_var, &results[2]);
  remote_chunk_store_->Store(mpid_name,
                             MpidValue(data),
                             callback,
                             validation_data_anmpid);

  std::string mcid_name(MaidsafeContactIdName(public_id));
  callback = std::bind(&SendContactInfoCallback, args::_1,
                       &mutex, &cond_var, &results[3]);
  remote_chunk_store_->Store(mcid_name,
                             MaidsafeContactIdValue(
                                 data,
                                 accepts_new_contacts,
                                 validation_data_mpid.key_pair.private_key),
                             callback,
                             validation_data_mpid);

  result = AwaitingResponse(&mutex, &cond_var, &results);
  if (result != kSuccess)
    return result;

  if (!(results[0] == kSuccess && results[1] == kSuccess &&
        results[2] == kSuccess && results[3] == kSuccess)) {
    DLOG(ERROR) << "Failed to store packets.  "
                << "ANMPID: " << results[1]
                << "\tMPID: " << results[2]
                << "\tMCID: " << results[3]
                << "\tMMID: "<< results[0];
    return kStorePublicIdFailure;
  }

  // Confirm packets as stored
  result = session_->passport_->ConfirmSelectableIdentity(public_id);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to confirm Public ID with name " << public_id;
    return result;
  }

  auto n(session_->contact_handler_map().insert(
             std::make_pair(public_id,
                            ContactsHandlerPtr(new ContactsHandler))));
  if (!n.second) {
    DLOG(ERROR) << "Failed to add contact handler for " << public_id;
    return result;
  }

  if (!session_->set_profile_picture_data_map(public_id,
                                              kBlankProfilePicture)) {
    DLOG(ERROR) << "Failed to add contact handler for " << public_id;
    return kSetProfilePictureError;
  }

  return kSuccess;
}

int PublicId::SendContactInfo(const std::string &own_public_id,
                              const std::string &recipient_public_id,
                              bool add_contact) {
  std::vector<std::string> contacts;
  contacts.push_back(recipient_public_id);
  int result(InformContactInfo(own_public_id, contacts));
  if (result == kSuccess && add_contact)
    result = session_->contact_handler_map()[own_public_id]->AddContact(
                 recipient_public_id,
                 "", "", "",
                 asymm::PublicKey(),
                 asymm::PublicKey(),
                 kRequestSent,
                 0, 0);
  return result;
}

int PublicId::DisablePublicId(const std::string &public_id) {
  int result(ModifyAppendability(public_id, pca::kModifiableByOwner));
  if (result != kSuccess)
    DLOG(ERROR) << "Failed to Disable PublicId";
  return result;
}

int PublicId::EnablePublicId(const std::string &public_id) {
  int result(ModifyAppendability(public_id, pca::kAppendableByAll));
  if (result != kSuccess)
    DLOG(ERROR) << "Failed to Enable PublicId";
  return result;
}

int PublicId::ModifyAppendability(const std::string &public_id,
                                  const char appendability) {
  if (public_id.empty()) {
    DLOG(ERROR) << "Public ID name empty";
    return kPublicIdEmpty;
  }

  // Retrieves ANMPID, MPID, and MMID's <name, value, signature>
  passport::SelectableIdentityData data;
  int result(session_->passport_->GetSelectableIdentityData(public_id,
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
                                            public_id));
  asymm::PrivateKey MMID_private_key(
      session_->passport_->PacketPrivateKey(passport::kMmid,
                                            true,
                                            public_id));
  // Change appendability of MCID,MMID by modify them via ModifyAppendableByAll
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);
  results.push_back(kPendingResult);

  pcs::RemoteChunkStore::ValidationData validation_data_mpid;
  KeysAndProof(public_id, passport::kMpid, true, &validation_data_mpid);
  std::string packet_name(MaidsafeContactIdName(public_id));
  VoidFunctionOneBool callback(std::bind(&SendContactInfoCallback, args::_1,
                                         &mutex, &cond_var, &results[0]));
  remote_chunk_store_->Modify(packet_name,
                              ComposeModifyAppendableByAll(MPID_private_key,
                                                           appendability),
                              callback,
                              validation_data_mpid);

  pcs::RemoteChunkStore::ValidationData validation_data_mmid;
  KeysAndProof(public_id, passport::kMmid, true, &validation_data_mmid);
  packet_name = MaidsafeInboxName(data);
  callback = std::bind(&SendContactInfoCallback, args::_1,
                       &mutex, &cond_var, &results[1]);
  remote_chunk_store_->Modify(packet_name,
                              ComposeModifyAppendableByAll(MMID_private_key,
                                                           appendability),
                              callback,
                              validation_data_mmid);

  result = AwaitingResponse(&mutex, &cond_var, &results);
  if (result != kSuccess)
    return result;

  if (!(results[0] == kSuccess && results[1] == kSuccess)) {
    DLOG(ERROR) << "Failed to modifying MCID/MMID when modify public_id.  "
                << " with MCID Result : " << results[0]
                << " , MMID result :" << results[1];
    return kModifyAppendabilityFailure;
  }

  return kSuccess;
}

void PublicId::GetNewContacts(const bptime::seconds &interval,
                              const boost::system::error_code &error_code) {
  if (error_code) {
    if (error_code != ba::error::operation_aborted) {
      DLOG(WARNING) << "Refresh timer error: " << error_code.message();
    } else {
      DLOG(INFO) << "Timer cancel triggered: " << error_code.message();
      return;
    }
  }
  GetContactsHandle();
  get_new_contacts_timer_.expires_at(get_new_contacts_timer_.expires_at() +
                                     interval);
  get_new_contacts_timer_.async_wait(std::bind(&PublicId::GetNewContacts,
                                               this,
                                               interval,
                                               std::placeholders::_1));
}

void PublicId::GetContactsHandle() {
  std::vector<passport::SelectableIdData> selectables;
  session_->passport_->SelectableIdentitiesList(&selectables);
  for (auto it(selectables.begin()); it != selectables.end(); ++it) {
    if (std::get<3>(*it)) {
      passport::SelectableIdentityData data;
      session_->passport_->GetSelectableIdentityData(std::get<0>(*it),
                                                     true,
                                                     &data);
      pcs::RemoteChunkStore::ValidationData validation_data_mpid;
      KeysAndProof(std::get<0>(*it),
                   passport::kMpid,
                   true,
                   &validation_data_mpid);
      std::string mpid_value(
          remote_chunk_store_->Get(MaidsafeContactIdName(std::get<0>(*it)),
                                   validation_data_mpid));
      if (mpid_value.empty()) {
        DLOG(ERROR) << "Failed to get MPID contents for " << std::get<0>(*it);
      } else {
        ProcessRequests(*it, mpid_value);
      }
    }
  }
}

void PublicId::ProcessRequests(const passport::SelectableIdData &data,
                               const std::string &mpid_value) {
  pca::AppendableByAll mcid;
  if (!mcid.ParseFromString(mpid_value)) {
    DLOG(ERROR) << "Failed to parse as AppendableByAll";
    return;
  }

  for (int it(0); it < mcid.appendices_size(); ++it) {
    std::string encrypted_introduction;
    int n(asymm::Decrypt(mcid.appendices(it).data(),
                         std::get<2>(data),
                         &encrypted_introduction));
    if (n != kSuccess || encrypted_introduction.empty()) {
      DLOG(ERROR) << "Failed to decrypt Introduction: " << n;
      continue;
    }

    Introduction introduction;
    if (!introduction.ParseFromString(encrypted_introduction)) {
      DLOG(ERROR) << "Failed to parse as Introduction";
      continue;
    }

    // TODO(Team#5#): 2011-12-02 - Validate signature of each Introduction
    // TODO(Team#5#): 2012-04-03 - Handle case where the request comes from
    //                             someone who is already accepted, ie, might
    //                             have blocked us and wants in again.
    std::string public_id(introduction.public_id()),
                inbox_name(introduction.inbox_name()),
                profile_picture_data_map(
                    introduction.profile_picture_data_map());

    Contact mic;
    n = session_->contact_handler_map()[std::get<0>(data)]->ContactInfo(
            public_id,
            &mic);
    if (n == kSuccess) {
      if (mic.status == kRequestSent) {
        mic.status = kConfirmed;
        mic.inbox_name = inbox_name;
        mic.profile_picture_data_map = profile_picture_data_map;
        int update(session_->contact_handler_map()
                       [std::get<0>(data)]->UpdateContact(mic));
        if (update == kSuccess) {
          (*contact_confirmed_signal_)(std::get<0>(data),
                                       public_id,
                                       introduction.timestamp());
        }
      } else if (mic.status == kConfirmed) {
        int mmid(
            session_->contact_handler_map()[std::get<0>(data)]->UpdateMmidName(
                public_id,
                inbox_name));
        if (mmid != kSuccess) {
          DLOG(ERROR) << "Failed to update MMID.";
        }
      }
    } else {
      n = session_->contact_handler_map()[std::get<0>(data)]->AddContact(
              public_id,
              "",
              inbox_name,
              profile_picture_data_map,
              asymm::PublicKey(),
              asymm::PublicKey(),
              kPendingResponse,
              0, 0);
      if (n == kSuccess)
        (*new_contact_signal_)(std::get<0>(data),
                               public_id,
                               introduction.timestamp());
    }
  }
}

int PublicId::ConfirmContact(const std::string &own_public_id,
                             const std::string &recipient_public_id,
                             bool confirm) {
  if (confirm) {
    Contact mic;
    int result(
        session_->contact_handler_map()[own_public_id]->ContactInfo(
            recipient_public_id,
            &mic));
    if (result != 0 || mic.status != kPendingResponse) {
      DLOG(ERROR) << "No such pending username found: "
                  << recipient_public_id;
      return -1;
    }

    result = SendContactInfo(own_public_id,
                             recipient_public_id,
                             false);
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed to send confirmation to "
                  << recipient_public_id;
      return -1;
    }

    if (session_->contact_handler_map()[own_public_id]->UpdateStatus(
            recipient_public_id,
            kConfirmed) != 0) {
      DLOG(ERROR) << "Failed to confirm " << recipient_public_id;
      return -1;
    }

    return kSuccess;
  } else {
    return session_->contact_handler_map()[own_public_id]->DeleteContact(
               recipient_public_id);
  }
}

void PublicId::RemoveContactHandle(const std::string &public_id,
                                   const std::string &contact_name) {
  asio_service_.post(std::bind(&PublicId::RemoveContact, this,
                               public_id, contact_name));
}

int PublicId::RemoveContact(const std::string &public_id,
                            const std::string &contact_name) {
  if (public_id.empty() || contact_name.empty()) {
    DLOG(ERROR) << "Public ID name empty";
    return kPublicIdEmpty;
  }

  if (session_->contact_handler_map()
          [public_id]->TouchContact(contact_name) != kSuccess)
    return kLiveContactNotFound;

  asymm::PrivateKey old_inbox_private_key(
      session_->passport_->PacketPrivateKey(passport::kMmid,
                                            true,
                                            public_id));
  // Generate a new MMID and store it
  passport::PacketData new_MMID, old_MMID;
  int result(session_->passport_->MoveMaidsafeInbox(public_id,
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
                                            public_id));
  pcs::RemoteChunkStore::ValidationData validation_data_mmid;
  KeysAndProof(public_id, passport::kMmid, false, &validation_data_mmid);
  std::string inbox_name(MaidsafeInboxName(std::get<0>(new_MMID)));
  VoidFunctionOneBool callback(std::bind(&SendContactInfoCallback, args::_1,
                                         &mutex, &cond_var, &results[0]));
  remote_chunk_store_->Store(inbox_name,
                             MaidsafeInboxValue(new_MMID,
                                                new_inbox_private_key),
                             callback,
                             validation_data_mmid);

  result = AwaitingResponse(&mutex, &cond_var, &results);
  if (result != kSuccess)
    return result;
  if (results[0] != kSuccess) {
    DLOG(ERROR) << "Failed to store new MMID when remove a contact.";
    return kRemoveContactFailure;
  }

  result = session_->contact_handler_map()[public_id]->DeleteContact(
               contact_name);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to remove contact : " << contact_name;
    return result;
  }
  // Invalidate previous MMID, i.e. put it into kModifiableByOwner
  results[0] = kPendingResult;

  validation_data_mmid = pcs::RemoteChunkStore::ValidationData();
  KeysAndProof(public_id, passport::kMmid, true, &validation_data_mmid);
  callback = std::bind(&SendContactInfoCallback, args::_1,
                       &mutex, &cond_var, &results[0]);
  inbox_name = MaidsafeInboxName(std::get<0>(old_MMID));
  remote_chunk_store_->Modify(inbox_name,
                              ComposeModifyAppendableByAll(
                                  old_inbox_private_key,
                                  pca::kModifiableByOwner),
                              callback,
                              validation_data_mmid);

  result = AwaitingResponse(&mutex, &cond_var, &results);
  if (result != kSuccess)
    return result;
  if (results[0] != kSuccess) {
    DLOG(ERROR) << "Failed to invalidate previous MMID when remove a contact.";
    return kRemoveContactFailure;
  }

  session_->passport_->ConfirmMovedMaidsafeInbox(public_id);
  // Informs each contact in the list about the new MMID
  result = InformContactInfo(public_id,
                             MapToVector(ContactList(public_id)));

  return result;
}

int PublicId::InformContactInfo(const std::string &public_id,
                                const std::vector<std::string> &contacts) {
  // Get our MMID name, and MPID private key
  passport::SelectableIdentityData data;
  // Retrieves ANMPID, MPID, and MMID's <name, value, signature>
  int result(session_->passport_->GetSelectableIdentityData(public_id,
                                                            true,
                                                            &data));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get own public ID data: " << result;
    return kGetPublicIdError;
  }
  BOOST_ASSERT(data.size() == 3U);
  std::string inbox_name(std::get<0>(data.at(2)));

  // Retrieves MPID private_key
  asymm::PrivateKey MPID_private_key(
      session_->passport_->PacketPrivateKey(passport::kMpid,
                                            true,
                                            public_id));
  // Inform each contact in the contact list of the MMID contact info
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results(contacts.size(), kPendingResult);
  size_t size(contacts.size());

  pcs::RemoteChunkStore::ValidationData validation_data_mpid;
  KeysAndProof(public_id, passport::kMpid, true, &validation_data_mpid);

  for (size_t i = 0; i < size; ++i) {
    std::string recipient_public_id(contacts[i]);
    // Get recipient's public key
    asymm::PublicKey recipient_public_key;
    int result(GetValidatedMpidPublicKey(recipient_public_id,
                                         validation_data_mpid,
                                         remote_chunk_store_,
                                         &recipient_public_key));
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed to get public key for "
                  << recipient_public_id;
      return result;
    }

    Introduction introduction;
    introduction.set_inbox_name(inbox_name);
    introduction.set_public_id(public_id);
    introduction.set_profile_picture_data_map(
        session_->profile_picture_data_map(public_id));
    introduction.set_timestamp(IsoTimeWithMicroSeconds());

    std::string encrypted_introduction;
    result = asymm::Encrypt(introduction.SerializeAsString(),
                            recipient_public_key,
                            &encrypted_introduction);
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed to encrypt MCID's public username: " << result;
      return kEncryptingError;
    }

    asymm::Signature signature;
    result = asymm::Sign(encrypted_introduction,
                         MPID_private_key,
                         &signature);
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed to sign MCID data: " << result;
      return kSigningError;
    }
    pca::SignedData signed_data;
    signed_data.set_data(encrypted_introduction);
    signed_data.set_signature(signature);

    // Store encrypted MCID at recipient's MPID's name
    std::string contact_id(MaidsafeContactIdName(recipient_public_id));
    VoidFunctionOneBool callback(std::bind(&SendContactInfoCallback, args::_1,
                                           &mutex, &cond_var, &results[i]));
    remote_chunk_store_->Modify(contact_id,
                                signed_data.SerializeAsString(),
                                callback,
                                validation_data_mpid);
  }
  result = AwaitingResponse(&mutex, &cond_var, &results);
  if (result != kSuccess)
    return result;

  for (size_t j = 0; j < size; ++j) {
    if (results[j] != kSuccess)
      return kSendContactInfoFailure;
  }

  return kSuccess;
}

int PublicId::AwaitingResponse(boost::mutex *mutex,
                               boost::condition_variable *cond_var,
                               std::vector<int> *results) {
  size_t size(results->size());
  try {
    boost::mutex::scoped_lock lock(*mutex);
    if (!cond_var->timed_wait(lock,
                              bptime::seconds(30),
                              [&]()->bool {
                                for (size_t i(0); i < size; ++i) {
                                  if (results->at(i) == kPendingResult)
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

std::map<std::string, ContactStatus> PublicId::ContactList(
    const std::string &public_id,
    ContactOrder type,
    uint16_t bitwise_status) const {
  std::map<std::string, ContactStatus> contacts;
  std::vector<Contact> session_contacts;
  session_->contact_handler_map()[public_id]->OrderedContacts(
            &session_contacts,
            type,
            bitwise_status);
  for (auto it(session_contacts.begin()); it != session_contacts.end(); ++it)
    contacts.insert(std::make_pair((*it).public_id, (*it).status));

  return contacts;
}

void PublicId::KeysAndProof(
    const std::string &public_id,
    passport::PacketType pt,
    bool confirmed,
    pcs::RemoteChunkStore::ValidationData *validation_data) {
  if (pt != passport::kAnmpid &&
      pt != passport::kMpid &&
      pt != passport::kMmid) {
    DLOG(ERROR) << "Not valid public ID packet, what'r'u playing at?";
    return;
  }

  validation_data->key_pair.identity =
      session_->passport_->PacketName(pt, confirmed, public_id);
  validation_data->key_pair.public_key =
      session_->passport_->SignaturePacketValue(pt, confirmed, public_id);
  validation_data->key_pair.private_key =
      session_->passport_->PacketPrivateKey(pt, confirmed, public_id);
  validation_data->key_pair.validation_token =
      session_->passport_->PacketSignature(pt, confirmed, public_id);
  pca::SignedData signed_data;
  signed_data.set_data(RandomString(64));
  asymm::Sign(signed_data.data(),
              validation_data->key_pair.private_key,
              &validation_data->ownership_proof);
  signed_data.set_signature(validation_data->ownership_proof);
  validation_data->ownership_proof = signed_data.SerializeAsString();
}

bs2::connection PublicId::ConnectToNewContactSignal(
    const NewContactFunction &new_contact_slot) {
  return new_contact_signal_->connect(new_contact_slot);
}

bs2::connection PublicId::ConnectToContactConfirmedSignal(
    const ContactConfirmationFunction &contact_confirmation_slot) {
  return contact_confirmed_signal_->connect(contact_confirmation_slot);
}

}  // namespace lifestuff

}  // namespace maidsafe
