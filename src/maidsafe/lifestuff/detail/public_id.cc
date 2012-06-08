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

#include "maidsafe/lifestuff/detail/public_id.h"

#include <vector>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/rcs_helper.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

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
  pca::SignedData *allow_others_to_append = contact_id.mutable_allow_others_to_append();

  std::string public_key;
  asymm::EncodePublicKey(std::get<1>(data.at(index)), &public_key);
  identity_key->set_data(public_key);
  identity_key->set_signature(std::get<2>(data.at(index)));
  allow_others_to_append->set_data(accepts_new_contacts ? std::string(1, pca::kAppendableByAll) :
                                                          std::string(1, pca::kModifiableByOwner));

  asymm::Signature packet_signature;
  int result(asymm::Sign(allow_others_to_append->data(), private_key, &packet_signature));
  if (result != kSuccess) {
    LOG(kError) << "AppendableIdValue - Failed to sign";
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
  return crypto::Hash<crypto::SHA512>(public_id) + std::string(1, pca::kAppendableByAll);
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
  pca::SignedData *allow_others_to_append = contact_id.mutable_allow_others_to_append();

  std::string public_key;
  asymm::EncodePublicKey(std::get<1>(data), &public_key);
  identity_key->set_data(public_key);
  identity_key->set_signature(std::get<2>(data));
  allow_others_to_append->set_data(std::string(1, pca::kAppendableByAll));

  asymm::Signature packet_signature;
  int result(asymm::Sign(allow_others_to_append->data(), private_key, &packet_signature));
  if (result != kSuccess) {
    LOG(kError) << "AppendableIdValue - Failed to sign";
    return "";
  }

  allow_others_to_append->set_signature(packet_signature);

  return contact_id.SerializeAsString();
}

}  // namespace

PublicId::PublicId(std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
                   Session& session,
                   ba::io_service &asio_service)
    : remote_chunk_store_(remote_chunk_store),
      session_(session),
      get_new_contacts_timer_(asio_service),
      check_online_contacts_timer_(asio_service),
      new_contact_signal_(new NewContactSignal),
      contact_confirmed_signal_(new ContactConfirmedSignal),
      asio_service_(asio_service) {}

PublicId::~PublicId() { StopCheckingForNewContacts(); }

void PublicId::StartUp(const bptime::seconds &interval) {
  GetContactsHandle();
  StartCheckingForNewContacts(interval);
}

void PublicId::ShutDown() { StopCheckingForNewContacts(); }

int PublicId::StartCheckingForNewContacts(const bptime::seconds &interval) {
  std::vector<passport::SelectableIdData> selectables;
  session_.passport().SelectableIdentitiesList(&selectables);
  if (selectables.empty()) {
    LOG(kError) << "No public username set";
    return kNoPublicIds;
  }
  get_new_contacts_timer_.expires_from_now(interval);
  get_new_contacts_timer_.async_wait(std::bind(&PublicId::GetNewContacts,
                                               this,
                                               interval,
                                               std::placeholders::_1));
  return kSuccess;
}

void PublicId::StopCheckingForNewContacts() { get_new_contacts_timer_.cancel(); }

int PublicId::CreatePublicId(const std::string &public_id, bool accepts_new_contacts) {
  if (public_id.empty()) {
    LOG(kError) << "Public ID name empty";
    return kPublicIdEmpty;
  }

  // Create packets (pending) in passport
  int result(session_.passport().CreateSelectableIdentity(public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed to create Public ID with name " << public_id;
    return result;
  }

  passport::SelectableIdentityData data;
  // Retrieves ANMPID, MPID, and MMID's <name, value, signature>
  result = session_.passport().GetSelectableIdentityData(public_id, false, &data);
  if (result != kSuccess) {
    LOG(kError) << "Failed to get own public ID data: " << result;
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

  std::string inbox_name(MaidsafeInboxName(data));
  VoidFunctionOneBool callback(std::bind(&ChunkStoreOperationCallback, args::_1,
                                         &mutex, &cond_var, &results[0]));
  std::shared_ptr<asymm::Keys> key_mmid_shared(
      session_.passport().SignaturePacketDetails(passport::kMmid, false, public_id));
  remote_chunk_store_->Store(inbox_name,
                             MaidsafeInboxValue(data, key_mmid_shared->private_key),
                             callback,
                             key_mmid_shared);

  std::string anmpid_name(AnmpidName(data));
  callback = std::bind(&ChunkStoreOperationCallback, args::_1, &mutex, &cond_var, &results[1]);
  std::shared_ptr<asymm::Keys> key_anmpid_shared(
      session_.passport().SignaturePacketDetails(passport::kAnmpid, false, public_id));
  remote_chunk_store_->Store(anmpid_name, AnmpidValue(data), callback, key_anmpid_shared);

  std::string mpid_name(MpidName(data));
  callback = std::bind(&ChunkStoreOperationCallback, args::_1, &mutex, &cond_var, &results[2]);
  remote_chunk_store_->Store(mpid_name, MpidValue(data), callback, key_anmpid_shared);

  std::string mcid_name(MaidsafeContactIdName(public_id));
  callback = std::bind(&ChunkStoreOperationCallback, args::_1, &mutex, &cond_var, &results[3]);
  std::shared_ptr<asymm::Keys> key_mpid_shared(
      session_.passport().SignaturePacketDetails(passport::kMpid, false, public_id));
  remote_chunk_store_->Store(mcid_name,
                             MaidsafeContactIdValue(data,
                                                    accepts_new_contacts,
                                                    key_mpid_shared->private_key),
                             callback,
                             key_mpid_shared);

  result = WaitForResultsPtr(&mutex, &cond_var, &results);
  if (result != kSuccess)
    return result;

  if (!(results[0] == kSuccess &&
        results[1] == kSuccess &&
        results[2] == kSuccess &&
        results[3] == kSuccess)) {
    LOG(kError) << "Failed to store packets.  "
                << "ANMPID: " << results[1]
                << "\tMPID: " << results[2]
                << "\tMCID: " << results[3]
                << "\tMMID: "<< results[0];
    return kStorePublicIdFailure;
  }

  // Confirm packets as stored
  result = session_.passport().ConfirmSelectableIdentity(public_id);
  if (result != kSuccess) {
    LOG(kError) << "Failed to confirm Public ID with name " << public_id;
    return result;
  }

  auto n(session_.contact_handler_map().insert(
             std::make_pair(public_id, ContactsHandlerPtr(new ContactsHandler))));
  if (!n.second) {
    LOG(kError) << "Failed to add contact handler for " << public_id;
    return result;
  }

  if (!session_.set_profile_picture_data_map(public_id, kBlankProfilePicture)) {
    LOG(kError) << "Failed to add contact handler for " << public_id;
    return kSetProfilePictureError;
  }

  return kSuccess;
}

int PublicId::AddContact(const std::string &own_public_id,
                         const std::string &recipient_public_id) {
  Contact recipient_contact;
  recipient_contact.status = kRequestSent;
  recipient_contact.public_id = recipient_public_id;
  int result(GetPublicKey(crypto::Hash<crypto::SHA512>(recipient_public_id), recipient_contact, 0));
  if (result != kSuccess) {
    LOG(kError) << "Failed to retrieve public key of contact: " << recipient_public_id;
    return result;
  }

  std::vector<Contact> contacts(1, recipient_contact);
  result = InformContactInfo(own_public_id, contacts);
  if (result == kSuccess)
    result = session_.contact_handler_map()[own_public_id]->AddContact(recipient_contact);
  return result;
}

int PublicId::DisablePublicId(const std::string &public_id) {
  int result(ModifyAppendability(public_id, pca::kModifiableByOwner));
  if (result != kSuccess)
    LOG(kError) << "Failed to Disable PublicId";
  return result;
}

int PublicId::EnablePublicId(const std::string &public_id) {
  int result(ModifyAppendability(public_id, pca::kAppendableByAll));
  if (result != kSuccess)
    LOG(kError) << "Failed to Enable PublicId";
  return result;
}

int PublicId::ModifyAppendability(const std::string &public_id, const char appendability) {
  if (public_id.empty()) {
    LOG(kError) << "Public ID name empty";
    return kPublicIdEmpty;
  }

  // Retrieves ANMPID, MPID, and MMID's <name, value, signature>
  passport::SelectableIdentityData data;
  int result(session_.passport().GetSelectableIdentityData(public_id, true, &data));
  if (result != kSuccess) {
    LOG(kError) << "Failed to get own public ID data: " << result;
    return kGetPublicIdError;
  }
  BOOST_ASSERT(data.size() == 3U);

  // Change appendability of MCID,MMID by modify them via ModifyAppendableByAll
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);
  results.push_back(kPendingResult);


  std::string packet_name(MaidsafeContactIdName(public_id));
  VoidFunctionOneBool callback(std::bind(&ChunkStoreOperationCallback, args::_1,
                                         &mutex, &cond_var, &results[0]));
  std::shared_ptr<asymm::Keys> key_mpid_shared(
      session_.passport().SignaturePacketDetails(passport::kMpid, true, public_id));
  remote_chunk_store_->Modify(packet_name,
                              ComposeModifyAppendableByAll(key_mpid_shared->private_key,
                                                           appendability),
                              callback,
                              key_mpid_shared);

  packet_name = MaidsafeInboxName(data);
  callback = std::bind(&ChunkStoreOperationCallback, args::_1, &mutex, &cond_var, &results[1]);
  std::shared_ptr<asymm::Keys> key_mmid_shared(
              session_.passport().SignaturePacketDetails(passport::kMmid, true, public_id));
  remote_chunk_store_->Modify(packet_name,
                              ComposeModifyAppendableByAll(key_mpid_shared->private_key,
                                                           appendability),
                              callback,
                              key_mmid_shared);

  result = WaitForResultsPtr(&mutex, &cond_var, &results);
  if (result != kSuccess)
    return result;

  if (!(results[0] == kSuccess && results[1] == kSuccess)) {
    LOG(kError) << "Failed to modifying MCID/MMID when modify public_id with MCID Result : "
                << results[0] << " , MMID result :" << results[1];
    return kModifyAppendabilityFailure;
  }

  return kSuccess;
}

void PublicId::GetNewContacts(const bptime::seconds &interval,
                              const boost::system::error_code &error_code) {
  if (error_code) {
    if (error_code != ba::error::operation_aborted) {
      LOG(kWarning) << "Refresh timer error: " << error_code.message();
    } else {
      LOG(kInfo) << "Timer cancel triggered: " << error_code.message();
      return;
    }
  }
  GetContactsHandle();
  get_new_contacts_timer_.expires_at(get_new_contacts_timer_.expires_at() + interval);
  get_new_contacts_timer_.async_wait(std::bind(&PublicId::GetNewContacts,
                                               this,
                                               interval,
                                               std::placeholders::_1));
}

void PublicId::GetContactsHandle() {
  std::vector<std::string> selectables(session_.PublicIdentities());
  for (auto it(selectables.begin()); it != selectables.end(); ++it) {

    std::shared_ptr<asymm::Keys> key_mpid_shared(
        session_.passport().SignaturePacketDetails(passport::kMpid, true, *it));
    std::string mpid_value(remote_chunk_store_->Get(MaidsafeContactIdName(*it), key_mpid_shared));
    if (mpid_value.empty()) {
      LOG(kError) << "Failed to get MPID contents for " << (*it);
    } else {
      ProcessRequests(*it, mpid_value);
    }
  }
}

void PublicId::ProcessRequests(const std::string &mpid_name,
                               const std::string &retrieved_mpid_packet) {
  pca::AppendableByAll mcid;
  if (!mcid.ParseFromString(retrieved_mpid_packet)) {
    LOG(kError) << "Failed to parse as AppendableByAll";
    return;
  }

  for (int it(0); it < mcid.appendices_size(); ++it) {
    std::string encrypted_introduction;
    int n(asymm::Decrypt(mcid.appendices(it).data(),
                         session_.passport().PacketPrivateKey(passport::kMpid, true, mpid_name),
                         &encrypted_introduction));
    if (n != kSuccess || encrypted_introduction.empty()) {
      LOG(kError) << "Failed to decrypt Introduction: " << n;
      continue;
    }

    Introduction introduction;
    if (!introduction.ParseFromString(encrypted_introduction)) {
      LOG(kError) << "Failed to parse as Introduction";
      continue;
    }

    // TODO(Team#5#): 2011-12-02 - Validate signature of each Introduction
    // TODO(Team#5#): 2012-04-03 - Handle case where the request comes from
    //                             someone who is already accepted, ie, might
    //                             have blocked us and wants in again.
    std::string public_id(introduction.public_id()),
                inbox_name(introduction.inbox_name()),
                profile_picture_data_map(introduction.profile_picture_data_map());

    Contact mic;
    n = session_.contact_handler_map()[mpid_name]->ContactInfo(public_id, &mic);
    if (n == kSuccess) {
      if (mic.status == kRequestSent) {  // Contact confirmation
        mic.status = kConfirmed;
        mic.profile_picture_data_map = profile_picture_data_map;
        n = GetPublicKey(inbox_name, mic, 1);
        if (n == kSuccess) {
          n = session_.contact_handler_map()[mpid_name]->UpdateContact(mic);
          if (n == kSuccess) {
            (*contact_confirmed_signal_)(mpid_name, public_id, introduction.timestamp());
          } else {
            LOG(kError) << "Failed to update contact after confirmation.";
          }
        } else {
          LOG(kError) << "Failed to update contact after confirmation.";
        }
      } else if (mic.status == kConfirmed) {  // Contact moving its inbox
        n = GetPublicKey(inbox_name, mic, 1);
        if (n == kSuccess) {
          n = session_.contact_handler_map()[mpid_name]->UpdateContact(mic);
          if (n != kSuccess) {
            LOG(kError) << "Failed to update MMID.";
          }
        } else {
          LOG(kError) << "Failed to update contact after inbox move.";
        }
      }
    } else {  // New contact
      mic.status = kPendingResponse;
      mic.public_id = public_id;
      mic.profile_picture_data_map = profile_picture_data_map;
      n = GetPublicKey(crypto::Hash<crypto::SHA512>(public_id), mic, 0);
      n += GetPublicKey(inbox_name, mic, 1);
      if (n == kSuccess) {
        n = session_.contact_handler_map()[mpid_name]->AddContact(mic);
        if (n == kSuccess)
          (*new_contact_signal_)(mpid_name, public_id, introduction.timestamp());
      } else {
        LOG(kError) << "Failed get keys of new contact.";
      }
    }
  }
}

int PublicId::ConfirmContact(const std::string &own_public_id,
                             const std::string &recipient_public_id) {
  Contact mic;
  int result(session_.contact_handler_map()[own_public_id]->ContactInfo(recipient_public_id,
                                                                        &mic));
  if (result != 0 || mic.status != kPendingResponse) {
    LOG(kError) << "No such pending username found: " << recipient_public_id;
    return -1;
  }

  std::vector<Contact> contacts(1, mic);
  result = InformContactInfo(own_public_id, contacts);
  if (result != kSuccess) {
    LOG(kError) << "Failed to send confirmation to " << recipient_public_id;
    return -1;
  }

  result = session_.contact_handler_map()[own_public_id]->UpdateStatus(recipient_public_id,
                                                                       kConfirmed);
  if (result != kSuccess) {
    LOG(kError) << "Failed to confirm " << recipient_public_id;
    return -1;
  }

  return kSuccess;
}

int PublicId::RejectContact(const std::string &own_public_id,
                            const std::string &recipient_public_id) {
  return session_.contact_handler_map()[own_public_id]->DeleteContact(recipient_public_id);
}

void PublicId::RemoveContactHandle(const std::string &public_id, const std::string &contact_name) {
  asio_service_.post(std::bind(&PublicId::RemoveContact, this, public_id, contact_name));
}

int PublicId::RemoveContact(const std::string &public_id, const std::string &contact_name) {
  if (public_id.empty() || contact_name.empty()) {
    LOG(kError) << "Public ID name empty";
    return kPublicIdEmpty;
  }

  if (session_.contact_handler_map()[public_id]->TouchContact(contact_name) != kSuccess)
    return kLiveContactNotFound;

  asymm::PrivateKey old_inbox_private_key(session_.passport().PacketPrivateKey(passport::kMmid,
                                                                               true,
                                                                               public_id));
  // Generate a new MMID and store it
  passport::PacketData new_MMID, old_MMID;
  int result(session_.passport().MoveMaidsafeInbox(public_id, &old_MMID, &new_MMID));
  if (result != kSuccess) {
    LOG(kError) << "Failed to generate a new MMID: " << result;
    return kGenerateNewMMIDFailure;
  }

  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);

  std::string inbox_name(MaidsafeInboxName(std::get<0>(new_MMID)));
  VoidFunctionOneBool callback(std::bind(&ChunkStoreOperationCallback, args::_1,
                                         &mutex, &cond_var, &results[0]));
  std::shared_ptr<asymm::Keys> new_key_mmid_shared(
      session_.passport().SignaturePacketDetails(passport::kMmid, false, public_id));
  remote_chunk_store_->Store(inbox_name,
                             MaidsafeInboxValue(new_MMID, new_key_mmid_shared->private_key),
                             callback,
                             new_key_mmid_shared);

  result = WaitForResultsPtr(&mutex, &cond_var, &results);
  if (result != kSuccess)
    return result;
  if (results[0] != kSuccess) {
    LOG(kError) << "Failed to store new MMID when remove a contact.";
    return kRemoveContactFailure;
  }

  result = session_.contact_handler_map()[public_id]->DeleteContact(contact_name);
  if (result != kSuccess) {
    LOG(kError) << "Failed to remove contact : " << contact_name;
    return result;
  }
  // Invalidate previous MMID, i.e. put it into kModifiableByOwner
  results[0] = kPendingResult;

  std::shared_ptr<asymm::Keys> old_key_mmid_shared(
      session_.passport().SignaturePacketDetails(passport::kMmid, true, public_id));
  callback = std::bind(&ChunkStoreOperationCallback, args::_1, &mutex, &cond_var, &results[0]);

  inbox_name = MaidsafeInboxName(std::get<0>(old_MMID));
  remote_chunk_store_->Modify(inbox_name,
                              ComposeModifyAppendableByAll(old_key_mmid_shared->private_key,
                                                           pca::kModifiableByOwner),
                              callback,
                              old_key_mmid_shared);

  result = WaitForResultsPtr(&mutex, &cond_var, &results);
  if (result != kSuccess)
    return result;
  if (results[0] != kSuccess) {
    LOG(kError) << "Failed to invalidate previous MMID when remove a contact.";
    return kRemoveContactFailure;
  }

  session_.passport().ConfirmMovedMaidsafeInbox(public_id);
  // Informs each contact in the list about the new MMID
  ContactsHandler chm(*session_.contact_handler_map()[public_id]);
  std::vector<Contact> contacts;
  uint16_t status(kConfirmed | kRequestSent);
  chm.OrderedContacts(&contacts, kAlphabetical, status);
  result = InformContactInfo(public_id, contacts);

  return result;
}

int PublicId::InformContactInfo(const std::string &public_id,
                                const std::vector<Contact> &contacts) {
  // Get our MMID name, and MPID private key
  passport::SelectableIdentityData data;
  // Retrieves ANMPID, MPID, and MMID's <name, value, signature>
  int result(session_.passport().GetSelectableIdentityData(public_id, true, &data));
  if (result != kSuccess) {
    LOG(kError) << "Failed to get own public ID data: " << result;
    return kGetPublicIdError;
  }
  BOOST_ASSERT(data.size() == 3U);
  std::string inbox_name(std::get<0>(data.at(2)));

  // Inform each contact in the contact list of the MMID contact info
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results(contacts.size(), kPendingResult);
  size_t size(contacts.size());

  std::shared_ptr<asymm::Keys> key_mpid_shared(
      session_.passport().SignaturePacketDetails(passport::kMpid, true, public_id));

  for (size_t i = 0; i < size; ++i) {
    std::string recipient_public_id(contacts[i].public_id);
    // Get recipient's public key
    asymm::PublicKey recipient_public_key(contacts[i].mpid_public_key);

    Introduction introduction;
    introduction.set_inbox_name(inbox_name);
    introduction.set_public_id(public_id);
    introduction.set_profile_picture_data_map(session_.profile_picture_data_map(public_id));
    introduction.set_timestamp(IsoTimeWithMicroSeconds());

    std::string encrypted_introduction;
    int result = asymm::Encrypt(introduction.SerializeAsString(),
                                recipient_public_key,
                                &encrypted_introduction);
    if (result != kSuccess) {
      LOG(kError) << "Failed to encrypt MCID's public username: " << result;
      return kEncryptingError;
    }

    asymm::Signature signature;
    result = asymm::Sign(encrypted_introduction, key_mpid_shared->private_key, &signature);
    if (result != kSuccess) {
      LOG(kError) << "Failed to sign MCID data: " << result;
      return kSigningError;
    }
    pca::SignedData signed_data;
    signed_data.set_data(encrypted_introduction);
    signed_data.set_signature(signature);

    // Store encrypted MCID at recipient's MPID's name
    std::string contact_id(MaidsafeContactIdName(recipient_public_id));
    VoidFunctionOneBool callback(std::bind(&ChunkStoreOperationCallback, args::_1,
                                           &mutex, &cond_var, &results[i]));
    remote_chunk_store_->Modify(contact_id,
                                signed_data.SerializeAsString(),
                                callback,
                                key_mpid_shared);
  }
  result = WaitForResultsPtr(&mutex, &cond_var, &results);
  if (result != kSuccess)
    return result;

  for (size_t j = 0; j < size; ++j) {
    if (results[j] != kSuccess)
      return kSendContactInfoFailure;
  }

  return kSuccess;
}

std::map<std::string, ContactStatus> PublicId::ContactList(const std::string &public_id,
                                                           ContactOrder type,
                                                           uint16_t bitwise_status) const {
  std::map<std::string, ContactStatus> contacts;
  std::vector<Contact> session_contacts;
  session_.contact_handler_map()[public_id]->OrderedContacts(&session_contacts,
                                                              type,
                                                              bitwise_status);
  for (auto it(session_contacts.begin()); it != session_contacts.end(); ++it)
    contacts.insert(std::make_pair((*it).public_id, (*it).status));

  return contacts;
}

int PublicId::GetPublicKey(const std::string& packet_name, Contact& contact, int type) {
  std::string chunk_type(1, pca::kAppendableByAll);
  std::string network_packet(remote_chunk_store_->Get(packet_name + chunk_type));
  if (network_packet.empty()) {
    LOG(kError) << "Failed to obtain packet from network.";
    return kGetPublicKeyFailure;
  }

  pca::SignedData packet;
  if (!packet.ParseFromString(network_packet)) {
    LOG(kError) << "Failed to parse public key packet for " << contact.public_id;
    return kGetPublicKeyFailure;
  }

  asymm::PublicKey public_key;
  asymm::DecodePublicKey(packet.data(), &public_key);
  if (!asymm::ValidateKey(public_key)) {
    LOG(kError) << "Failed to validate public key for " << contact.public_id;
    return kGetPublicKeyFailure;
  }

  switch (type) {
    case 0: contact.mpid_public_key = public_key;
            contact.mpid_name = packet_name;
            break;
    case 1: contact.inbox_public_key = public_key;
            contact.inbox_name = packet_name;
            break;
    default: return kGetPublicKeyFailure;
  }

  return kSuccess;
}


bs2::connection PublicId::ConnectToNewContactSignal(const NewContactFunction &new_contact_slot) {
  return new_contact_signal_->connect(new_contact_slot);
}

bs2::connection PublicId::ConnectToContactConfirmedSignal(
    const ContactConfirmationFunction &contact_confirmation_slot) {
  return contact_confirmed_signal_->connect(contact_confirmation_slot);
}

}  // namespace lifestuff

}  // namespace maidsafe
