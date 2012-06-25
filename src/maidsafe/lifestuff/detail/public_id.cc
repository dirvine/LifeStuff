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

std::string AppendableIdValue(const asymm::Keys& data, bool accepts_new_contacts) {
  pca::AppendableByAll contact_id;
  pca::SignedData *identity_key = contact_id.mutable_identity_key();
  pca::SignedData *allow_others_to_append = contact_id.mutable_allow_others_to_append();

  std::string public_key;
  asymm::EncodePublicKey(data.public_key, &public_key);
  identity_key->set_data(public_key);
  identity_key->set_signature(data.validation_token);
  allow_others_to_append->set_data(accepts_new_contacts ? std::string(1, pca::kAppendableByAll) :
                                                          std::string(1, pca::kModifiableByOwner));

  asymm::Signature packet_signature;
  int result(asymm::Sign(allow_others_to_append->data(), data.private_key, &packet_signature));
  if (result != kSuccess) {
    LOG(kError) << "AppendableIdValue - Failed to sign";
    return "";
  }

  allow_others_to_append->set_signature(packet_signature);

  return contact_id.SerializeAsString();
}

std::string MaidsafeContactIdName(const std::string &public_id) {
  return crypto::Hash<crypto::SHA512>(public_id) + std::string(1, pca::kAppendableByAll);
}

std::string SignaturePacketName(const std::string& name) {
  return name + std::string (1, pca::kSignaturePacket);
}

std::string AppendableByAllName(const std::string& name) {
  return name + std::string (1, pca::kAppendableByAll);
}

std::string SignaturePacketValue(const asymm::Keys& keys) {
  pca::SignedData signed_data;
  std::string serialised_public_key;
  asymm::EncodePublicKey(keys.public_key, &serialised_public_key);
  if (serialised_public_key.empty())
    return "";

  signed_data.set_data(serialised_public_key);
  signed_data.set_signature(keys.validation_token);
  return signed_data.SerializeAsString();
}

}  // namespace

PublicId::PublicId(std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
                   Session& session,
                   ba::io_service &asio_service)
    : remote_chunk_store_(remote_chunk_store),
      session_(session),
      passport_(session_.passport()),
      get_new_contacts_timer_(asio_service),
      get_new_contacts_timer_active_(false),
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
  get_new_contacts_timer_active_ = true;
  if (session_.PublicIdentities().empty()) {
    LOG(kError) << "No public identites.";
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
  get_new_contacts_timer_active_ = false;
  get_new_contacts_timer_.cancel();
}

int PublicId::CreatePublicId(const std::string &public_id, bool accepts_new_contacts) {
  if (public_id.empty()) {
    LOG(kError) << "Public ID name empty";
    return kPublicIdEmpty;
  }

  // Create packets (pending) in passport
  int result(passport_.CreateSelectableIdentity(public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed to create Public ID with name " << public_id;
    return result;
  }

  // Retrieves ANMPID, MPID, and MMID's <name, value, signature>
  std::shared_ptr<asymm::Keys> anmpid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kAnmpid, false, public_id)));
  std::shared_ptr<asymm::Keys> mpid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kMpid, false, public_id)));
  std::shared_ptr<asymm::Keys> mmid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kMmid, false, public_id)));
  if (!(anmpid && mpid && mmid)) {
    LOG(kError) << "Failed to get own public ID data.";
    return kGetPublicIdError;
  }

  // Store packets
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);
  results.push_back(kPendingResult);
  results.push_back(kPendingResult);
  results.push_back(kPendingResult);

  VoidFunctionOneBool callback(std::bind(&ChunkStoreOperationCallback, args::_1,
                                         &mutex, &cond_var, &results[0]));
  if (!remote_chunk_store_->Store(AppendableByAllName(mmid->identity),
                                  AppendableIdValue(*mmid, true),
                                  callback,
                                  mmid)) {
    boost::mutex::scoped_lock lock(mutex);
    results[0] = kRemoteChunkStoreFailure;
  }

  callback = std::bind(&ChunkStoreOperationCallback, args::_1, &mutex, &cond_var, &results[1]);
  std::string anmpid_name(SignaturePacketName(anmpid->identity));
  if (!remote_chunk_store_->Store(anmpid_name, SignaturePacketValue(*anmpid), callback, anmpid)) {
    boost::mutex::scoped_lock lock(mutex);
    results[1] = kRemoteChunkStoreFailure;
  }

  std::string mpid_name(SignaturePacketName(mpid->identity));
  callback = std::bind(&ChunkStoreOperationCallback, args::_1, &mutex, &cond_var, &results[2]);
  if (!remote_chunk_store_->Store(mpid_name, SignaturePacketValue(*mpid), callback, anmpid)) {
    boost::mutex::scoped_lock lock(mutex);
    results[2] = kRemoteChunkStoreFailure;
  }

  std::string mcid_name(MaidsafeContactIdName(public_id));
  callback = std::bind(&ChunkStoreOperationCallback, args::_1, &mutex, &cond_var, &results[3]);
  if (!remote_chunk_store_->Store(mcid_name,
                                  AppendableIdValue(*mpid, accepts_new_contacts),
                                  callback,
                                  mpid)) {
    boost::mutex::scoped_lock lock(mutex);
    results[3] = kRemoteChunkStoreFailure;
  }

  result = WaitForResults(mutex, cond_var, results);
  if (result != kSuccess) {
      LOG(kError) << "Timed out.";
    return result;
  }

  if (!(results[0] == kSuccess &&
        results[1] == kSuccess &&
        results[2] == kSuccess &&
        results[3] == kSuccess)) {
    LOG(kError) << "Failed to store packets. " << "ANMPID: " << results[1] << ", MPID: "
                << results[2] << ", MCID: " << results[3] << ", MMID: "<< results[0];
    return kStorePublicIdFailure;
  }

  // Confirm packets as stored
  result = passport_.ConfirmSelectableIdentity(public_id);
  if (result != kSuccess) {
    LOG(kError) << "Failed to confirm Public ID with name " << public_id;
    return result;
  }

  result = session_.AddPublicId(public_id);
  if (result != kSuccess) {
    LOG(kError) << "Failed to add entry for " << public_id;
    return result;
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
  if (result == kSuccess) {
    ContactsHandler& contacts_handler(session_.contacts_handler(own_public_id, result));
    if (result != kSuccess) {
      LOG(kError) << "User does not hold public ID: " << own_public_id;
      return result;
    }
    result = contacts_handler.AddContact(recipient_contact);
  }

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

  // Change appendability of MCID,MMID by modify them via ModifyAppendableByAll
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);
  results.push_back(kPendingResult);

  std::shared_ptr<asymm::Keys> mpid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kMpid, true, public_id)));
  std::shared_ptr<asymm::Keys> mmid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kMmid, true, public_id)));
  if (mpid->identity.empty() || mmid->identity.empty()) {
    LOG(kError) << "Failed to find keys for " << public_id;
    return kGetPublicIdError;
  }

  VoidFunctionOneBool callback(std::bind(&ChunkStoreOperationCallback, args::_1,
                                         &mutex, &cond_var, &results[0]));
  if (!remote_chunk_store_->Modify(MaidsafeContactIdName(public_id),
                                   ComposeModifyAppendableByAll(mpid->private_key, appendability),
                                   callback,
                                   mpid)) {
    LOG(kError) << "Immediate modify failure for MPID.";
    boost::mutex::scoped_lock lock(mutex);
    results[0] = kRemoteChunkStoreFailure;
  }

  callback = std::bind(&ChunkStoreOperationCallback, args::_1, &mutex, &cond_var, &results[1]);
  if (!remote_chunk_store_->Modify(AppendableByAllName(mmid->identity),
                                   ComposeModifyAppendableByAll(mmid->private_key, appendability),
                                   callback,
                                   mmid)) {
    LOG(kError) << "Immediate modify failure for MMID.";
    boost::mutex::scoped_lock lock(mutex);
    results[1] = kRemoteChunkStoreFailure;
  }

  int result = WaitForResults(mutex, cond_var, results);
  if (result != kSuccess) {
    LOG(kError) << "Timed out wating for updates: " << public_id;
    return result;
  }

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

  if (!get_new_contacts_timer_active_) {
    LOG(kInfo) << "Process has been stopped.";
    return;
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
    LOG(kError) << "PublicId::GetNewContacts: " << (*it);
    std::shared_ptr<asymm::Keys> mpid(new asymm::Keys(
        passport_.SignaturePacketDetails(passport::kMpid, true, *it)));
    std::string mpid_packet(remote_chunk_store_->Get(MaidsafeContactIdName(*it), mpid));
    if (mpid_packet.empty()) {
      LOG(kError) << "Failed to get MPID contents for " << (*it);
    } else {
      ProcessRequests(*it, mpid_packet, mpid);
    }
  }
}

void PublicId::ProcessRequests(const std::string &own_public_id,
                               const std::string &retrieved_mpid_packet,
                               std::shared_ptr<asymm::Keys> mpid) {
  pca::AppendableByAll mcid;
  if (!mcid.ParseFromString(retrieved_mpid_packet)) {
    LOG(kError) << "Failed to parse as AppendableByAll";
    return;
  }

  int result(0);
  for (int it(0); it < mcid.appendices_size(); ++it) {
    std::string encrypted_introduction;
    result = asymm::Decrypt(mcid.appendices(it).data(),
                            mpid->private_key,
                            &encrypted_introduction);
    if (result != kSuccess || encrypted_introduction.empty()) {
      LOG(kError) << "Failed to decrypt Introduction: " << result;
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

    ContactsHandler& contacts_handler(session_.contacts_handler(own_public_id, result));
    if (result != kSuccess) {
      LOG(kError) << "User does not hold such public id: " << own_public_id;
      continue;
    }

    Contact mic;
    result = contacts_handler.ContactInfo(public_id, &mic);
    if (result == kSuccess) {
      if (mic.status == kRequestSent) {  // Contact confirmation
        mic.status = kConfirmed;
        mic.profile_picture_data_map = profile_picture_data_map;
        result = GetPublicKey(inbox_name, mic, 1);
        if (result == kSuccess) {
          result = contacts_handler.UpdateContact(mic);
          if (result == kSuccess) {
            (*contact_confirmed_signal_)(own_public_id, public_id, introduction.timestamp());
          } else {
            LOG(kError) << "Failed to update contact after confirmation.";
          }
        } else {
          LOG(kError) << "Failed to update contact after confirmation.";
        }
      } else if (mic.status == kConfirmed) {  // Contact moving its inbox
        result = GetPublicKey(inbox_name, mic, 1);
        if (result == kSuccess) {
          result = contacts_handler.UpdateContact(mic);
          if (result != kSuccess) {
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
      result = GetPublicKey(crypto::Hash<crypto::SHA512>(public_id), mic, 0);
      result += GetPublicKey(inbox_name, mic, 1);
      if (result == kSuccess) {
        result = contacts_handler.AddContact(mic);
        if (result == kSuccess)
          (*new_contact_signal_)(own_public_id, public_id, introduction.timestamp());
      } else {
        LOG(kError) << "Failed get keys of new contact.";
      }
    }
  }
}

int PublicId::ConfirmContact(const std::string &own_public_id,
                             const std::string &recipient_public_id) {
  int result(0);
  ContactsHandler& contacts_handler(session_.contacts_handler(own_public_id, result));
  if (result != kSuccess) {
    LOG(kError) << "User does not hold public id: " << own_public_id;
    return result;
  }

  Contact mic;
  result = contacts_handler.ContactInfo(recipient_public_id, &mic);
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

  result = contacts_handler.UpdateStatus(recipient_public_id, kConfirmed);
  if (result != kSuccess) {
    LOG(kError) << "Failed to confirm " << recipient_public_id;
    return -1;
  }

  return kSuccess;
}

int PublicId::RejectContact(const std::string &own_public_id,
                            const std::string &recipient_public_id) {
  int result(0);
  ContactsHandler& contacts_handler(session_.contacts_handler(own_public_id, result));
  if (result != kSuccess) {
    LOG(kError) << "User does not hold public id: " << own_public_id;
    return result;
  }

  return contacts_handler.DeleteContact(recipient_public_id);
}

void PublicId::RemoveContactHandle(const std::string &public_id, const std::string &contact_name) {
  asio_service_.post(std::bind(&PublicId::RemoveContact, this, public_id, contact_name));
}

int PublicId::RemoveContact(const std::string &public_id, const std::string &contact_name) {
  if (public_id.empty() || contact_name.empty()) {
    LOG(kError) << "Public ID name empty";
    return kPublicIdEmpty;
  }

  int result(0);
  ContactsHandler& contacts_handler(session_.contacts_handler(public_id, result));
  if (result != kSuccess) {
    LOG(kError) << "User does not have public id: " << public_id;
    return result;
  }

  if (contacts_handler.TouchContact(contact_name) != kSuccess) {
    LOG(kError) << "Contact doesn't exist in list: " << contact_name;
    return kContactNotFoundFailure;
  }

  // Generate a new MMID and store it
  result = passport_.MoveMaidsafeInbox(public_id);
  if (result != kSuccess) {
    LOG(kError) << "Failed to generate a new MMID: " << result;
    return kGenerateNewMMIDFailure;
  }

  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);

  VoidFunctionOneBool callback(std::bind(&ChunkStoreOperationCallback, args::_1,
                                         &mutex, &cond_var, &results[0]));
  std::shared_ptr<asymm::Keys> new_mmid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kMmid, false, public_id)));
  if (!remote_chunk_store_->Store(AppendableByAllName(new_mmid->identity),
                                  AppendableIdValue(*new_mmid, true),
                                  callback,
                                  new_mmid)) {
    boost::mutex::scoped_lock lock(mutex);
    results[0] = kRemoteChunkStoreFailure;
  }
  result = WaitForResults(mutex, cond_var, results);
  if (result != kSuccess) {
    LOG(kError) << "Timed out.";
    return result;
  }
  if (results[0] != kSuccess) {
    LOG(kError) << "Failed to store new MMID when remove a contact.";
    return kRemoveContactFailure;
  }

  result = contacts_handler.DeleteContact(contact_name);
  if (result != kSuccess) {
    LOG(kError) << "Failed to remove contact : " << contact_name;
    return result;
  }

  // Invalidate previous MMID, i.e. put it into kModifiableByOwner
  results[0] = kPendingResult;
  std::shared_ptr<asymm::Keys> old_mmid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kMmid, true, public_id)));
  callback = std::bind(&ChunkStoreOperationCallback, args::_1, &mutex, &cond_var, &results[0]);
  if (!remote_chunk_store_->Modify(AppendableByAllName(old_mmid->identity),
                                   ComposeModifyAppendableByAll(old_mmid->private_key,
                                                                pca::kModifiableByOwner),
                                   callback,
                                   old_mmid)) {
    boost::mutex::scoped_lock lock(mutex);
    results[0] = kRemoteChunkStoreFailure;
  }

  result = WaitForResults(mutex, cond_var, results);
  if (result != kSuccess) {
    LOG(kError) << "Timed out.";
    return result;
  }
  if (results[0] != kSuccess) {
    LOG(kError) << "Failed to invalidate previous MMID when remove a contact.";
    return kRemoveContactFailure;
  }

  passport_.ConfirmMovedMaidsafeInbox(public_id);
  // Informs each contact in the list about the new MMID
  std::vector<Contact> contacts;
  uint16_t status(kConfirmed | kRequestSent);
  contacts_handler.OrderedContacts(&contacts, kAlphabetical, status);
  result = InformContactInfo(public_id, contacts);

  return result;
}

int PublicId::InformContactInfo(const std::string &public_id,
                                const std::vector<Contact> &contacts) {
  // Get our MMID name, and MPID private key
  asymm::Keys inbox(passport_.SignaturePacketDetails(passport::kMmid, true, public_id));
  std::shared_ptr<asymm::Keys> mpid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kMpid, true, public_id)));
  if (!mpid || mpid->identity.empty() || inbox.identity.empty()) {
    LOG(kError) << "Failed to get own public ID data: " << public_id;
    return kGetPublicIdError;
  }

  // Inform each contact in the contact list of the MMID contact info
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results(contacts.size(), kPendingResult);
  size_t size(contacts.size());

  for (size_t i = 0; i < size; ++i) {
    std::string recipient_public_id(contacts[i].public_id);
    // Get recipient's public key
    asymm::PublicKey recipient_public_key(contacts[i].mpid_public_key);

    Introduction introduction;
    introduction.set_inbox_name(inbox.identity);
    introduction.set_public_id(public_id);
    introduction.set_timestamp(IsoTimeWithMicroSeconds());
    int result(0);
    session_.profile_picture_data_map(public_id, result);
    introduction.set_profile_picture_data_map(session_.profile_picture_data_map(public_id, result));
    if (result != kSuccess)
      LOG(kInfo) << "Failure to find profile picture data map for public id: " << public_id;

    std::string encrypted_introduction;
    result = asymm::Encrypt(introduction.SerializeAsString(),
                            recipient_public_key,
                            &encrypted_introduction);
    if (result != kSuccess) {
      LOG(kError) << "Failed to encrypt MCID's public username: " << result;
      return kEncryptingError;
    }

    asymm::Signature signature;
    result = asymm::Sign(encrypted_introduction, mpid->private_key, &signature);
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
    if (!remote_chunk_store_->Modify(contact_id,
                                     signed_data.SerializeAsString(),
                                     callback,
                                     mpid)) {
      boost::mutex::scoped_lock lock(mutex);
      results[i] = kRemoteChunkStoreFailure;
    }
  }
  int result(WaitForResults(mutex, cond_var, results));
  if (result != kSuccess) {
    LOG(kError) << "Timed out.";
    return result;
  }

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
  int result(0);
  ContactsHandler& ch(session_.contacts_handler(public_id, result));
  if (result != kSuccess) {
    LOG(kError) << "No such public id: " << public_id;
    return contacts;
  }
  ch.OrderedContacts(&session_contacts, type, bitwise_status);
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
