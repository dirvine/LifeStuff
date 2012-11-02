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

#include "boost/thread/mutex.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_id.h"
#include "maidsafe/private/utils/utilities.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/session.h"

namespace maidsafe {

namespace pca = priv::chunk_actions;
namespace utils = priv::utils;

namespace lifestuff {

const NonEmptyString kDefaultUnfriendMessage("You have been unfriended by: ");
const NonEmptyString kDefaultConfirmationMessage("You have been confirmed by: ");
const NonEmptyString kDefaultAsyncFixMessage("Async fix happening with: ");
const NonEmptyString kDefaultRequestMessage("Accepting as confirmation request by: ");
const NonEmptyString kDefaultCarChangeMessage("Lifestuff card change by: ");

PublicId::PublicId(priv::chunk_store::RemoteChunkStore& remote_chunk_store,
                   Session& session,
                   boost::asio::io_service& asio_service)
    : remote_chunk_store_(remote_chunk_store),
      session_(session),
      passport_(session_.passport()),
      get_new_contacts_timer_(asio_service),
      get_new_contacts_timer_active_(false),
      new_contact_signal_(),
      contact_confirmed_signal_(),
      contact_deletion_received_signal_(),
      contact_deletion_processed_signal_(),
      lifestuff_card_updated_signal_(),
      asio_service_(asio_service) {}

PublicId::~PublicId() {}

void PublicId::StartUp(const bptime::seconds& interval) {
  GetContactsHandle();
  StartCheckingForNewContacts(interval);
}

void PublicId::ShutDown() { StopCheckingForNewContacts(); }

int PublicId::StartCheckingForNewContacts(const bptime::seconds& interval) {
  get_new_contacts_timer_active_ = true;
  if (session_.PublicIdentities().empty()) {
    LOG(kError) << "No public identites.";
    return kStartContactsNoPublicIds;
  }
  get_new_contacts_timer_.expires_from_now(interval);
  get_new_contacts_timer_.async_wait([=] (const boost::system::error_code error_code) {
                                       GetNewContacts(interval, error_code);
                                     });
  return kSuccess;
}

void PublicId::StopCheckingForNewContacts() {
  if (get_new_contacts_timer_active_) {
    get_new_contacts_timer_active_ = false;
    // boost::this_thread::disable_interruption disable_interruption;
    get_new_contacts_timer_.cancel();
  }
}

int PublicId::CreatePublicId(const NonEmptyString& public_id, bool accepts_new_contacts) {
  int result(CheckPublicIdValidity(public_id));
  if (result != kSuccess) {
    LOG(kError) << "Public ID invalid.";
    return result;
  }

  // Create packets (pending) in passport
  passport_.CreateSelectableIdentity(public_id);

  // Retrieves ANMPID, MPID, and MMID's <name, value, signature>
  Fob anmpid(passport_.SignaturePacketDetails(passport::kAnmpid, false, public_id));
  Fob mmid(passport_.SignaturePacketDetails(passport::kMmid, false, public_id));

  // Store packets
  std::vector<int> individual_results(2, utils::kPendingResult);
  std::condition_variable condition_variable;
  std::mutex mutex;
  OperationResults results(mutex, condition_variable, individual_results);

  VoidFunctionOneBool callback = [&] (const bool& response) {
                                   OperationCallback(response, results, 0);
                                 };
  if (!remote_chunk_store_.Store(AppendableByAllName(mmid.identity),
                                 AppendableIdValue(mmid, true),
                                 callback,
                                 mmid)) {
    LOG(kError) << "Failed to store MMID";
    OperationCallback(false, results, 0);
  }

  callback = [&] (const bool& response) {
               StoreMpid(response, results, public_id, accepts_new_contacts);
             };
  priv::ChunkId anmpid_name(SignaturePacketName(anmpid.identity));
  if (!remote_chunk_store_.Store(anmpid_name, SignaturePacketValue(anmpid), callback, anmpid)) {
    LOG(kError) << "Failed to store ANMPID";
    OperationCallback(false, results, 1);
  }

  result = utils::WaitForResults(mutex, condition_variable, individual_results);
  if (result != kSuccess) {
      LOG(kError) << "Timed out.";
    return result;
  }

  if (individual_results[0] != kSuccess || individual_results[1] != kSuccess) {
    LOG(kError) << "Failed to store packets. " << "ANMPID path: " << individual_results[1]
                << ", MMID: "<< individual_results[0];
    return kStorePublicIdFailure;
  }

  // Confirm packets as stored
  result = passport_.ConfirmSelectableIdentity(public_id);
  if (result != kSuccess) {
    LOG(kError) << "Failed to confirm Public ID with name " << public_id.string();
    return result;
  }

  // Store the lifestuff card
  Identity lifestuff_card_address;
  result = StoreLifestuffCard(mmid, lifestuff_card_address);
  if (result != kSuccess) {
    LOG(kError) << "Failed to add entry for " << public_id.string();
  }

  result = session_.AddPublicId(public_id, lifestuff_card_address);
  if (result != kSuccess) {
    LOG(kError) << "Failed to add entry for " << public_id.string();
    return result;
  }

  return kSuccess;
}

int PublicId::AddContact(const NonEmptyString& own_public_id,
                         const NonEmptyString& recipient_public_id,
                         const NonEmptyString& message) {
  if (session_.OwnPublicId(recipient_public_id)) {
    LOG(kInfo) << "Cannot add own Public Id as a contact.";
    return kCannotAddOwnPublicId;
  }

  Contact recipient_contact;
  recipient_contact.status = kRequestSent;
  recipient_contact.public_id = recipient_public_id;
  int result(GetPublicKey(crypto::Hash<crypto::SHA512>(recipient_public_id), recipient_contact, 0));
  if (result != kSuccess) {
    LOG(kError) << "Failed to retrieve public key of contact: " << recipient_public_id.string();
    return result;
  }

  std::vector<Contact> contacts(1, recipient_contact);
  result = InformContactInfo(own_public_id, contacts, message, kFriendRequest);
  if (result == kSuccess) {
    const ContactsHandlerPtr contacts_handler(session_.contacts_handler(own_public_id));
    if (!contacts_handler) {
      LOG(kError) << "User does not hold public ID: " << own_public_id.string();
      return result;
    }
    result = contacts_handler->AddContact(recipient_contact);
  }

  if (result == kSuccess)
    session_.set_changed(true);

  return result;
}

int PublicId::DisablePublicId(const NonEmptyString& public_id) {
  int result(ModifyAppendability(public_id, false));
  if (result != kSuccess)
    LOG(kError) << "Failed to Disable PublicId";
  return result;
}

int PublicId::EnablePublicId(const NonEmptyString& public_id) {
  int result(ModifyAppendability(public_id, true));
  if (result != kSuccess)
    LOG(kError) << "Failed to Enable PublicId";
  return result;
}

int PublicId::DeletePublicId(const NonEmptyString& public_id) {
  std::vector<int> individual_results(4, utils::kPendingResult);
  std::condition_variable condition_variable;
  std::mutex mutex;
  OperationResults results(mutex, condition_variable, individual_results);

  Fob inbox_keys(passport_.SignaturePacketDetails(passport::kMmid, true, public_id));
  Fob mpid(passport_.SignaturePacketDetails(passport::kMpid, true, public_id));
  Fob anmpid(passport_.SignaturePacketDetails(passport::kAnmpid, true, public_id));
  priv::ChunkId inbox_name(AppendableByAllName(inbox_keys.identity)),
                mpid_name(SignaturePacketName(mpid.identity)),
                anmpid_name(SignaturePacketName(anmpid.identity)),
                mcid_name(MaidsafeContactIdName(public_id));

  Identity card_address;
  int result(0);
  SocialInfoDetail social_info(session_.social_info(public_id));
  if (social_info.first) {
    {
      std::lock_guard<std::mutex> lock(*social_info.first);
      card_address = social_info.second->card_address;
    }
    result = RemoveLifestuffCard(card_address, inbox_keys);
    LOG(kInfo) << "Deleting LS card: " << result;
  }

  if (!remote_chunk_store_.Delete(inbox_name,
                                  [&] (bool result) { OperationCallback(result, results, 0); },  // NOLINT (Dan)
                                  inbox_keys)) {
    LOG(kError) << "Failed to delete inbox.";
    OperationCallback(false, results, 0);
  }

  if (!remote_chunk_store_.Delete(mcid_name,
                                  [&] (bool result) { OperationCallback(result, results, 1); },  // NOLINT (Dan)
                                  mpid)) {
    LOG(kError) << "Failed to delete MCID.";
    OperationCallback(false, results, 1);
  }

  if (!remote_chunk_store_.Delete(mpid_name,
                                  [&] (bool result) { OperationCallback(result, results, 2); },  // NOLINT (Dan)
                                  anmpid)) {
    LOG(kError) << "Failed to delete MPID.";
    OperationCallback(false, results, 2);
  }

  if (!remote_chunk_store_.Delete(anmpid_name,
                                  [&] (bool result) { OperationCallback(result, results, 3); },  // NOLINT (Dan)
                                  anmpid)) {
    LOG(kError) << "Failed to delete ANMPID.";
    OperationCallback(false, results, 3);
  }

  result = utils::WaitForResults(mutex, condition_variable, individual_results);
  if (result != kSuccess) {
    LOG(kError) << "Wait for results timed out: " << result;
    LOG(kError) << "inbox: " << individual_results.at(0)
              << ", MCID: " << individual_results.at(1)
              << ", MPID: " << individual_results.at(2)
              << ", ANMPID: " << individual_results.at(3);
    return result;
  }

  LOG(kInfo) << "inbox: " << individual_results.at(0)
             << ", MCID: " << individual_results.at(1)
             << ", MPID: " << individual_results.at(2)
             << ", ANMPID: " << individual_results.at(3);
  result = AssessJointResult(individual_results);
  if (result != kSuccess) {
    LOG(kError) << "One of the operations for " << public_id.string() << " failed. "
                << "Turn on INFO for feedback on which one. ";
    return kDeletePublicIdFailure;
  }

  result = session_.DeletePublicId(public_id);
  if (result != kSuccess) {
    LOG(kError) << "Failed to delete from session: " << public_id.string();
    return kDeletePublicIdFailure;
  }

  return kSuccess;
}

int PublicId::ConfirmContact(const NonEmptyString& own_public_id,
                             const NonEmptyString& recipient_public_id) {
  const ContactsHandlerPtr contacts_handler(session_.contacts_handler(own_public_id));
  if (!contacts_handler) {
    LOG(kError) << "User does not hold public id: " << own_public_id.string();
    return kPublicIdNotFoundFailure;
  }

  Contact mic;
  int result(contacts_handler->ContactInfo(recipient_public_id, &mic));
  if (result != 0 || mic.status != kPendingResponse) {
    LOG(kError) << "No such pending username found: " << recipient_public_id.string();
    return kConfirmContactGetInfoFailure;
  }
  std::vector<Contact> contacts(1, mic);
  result = InformContactInfo(own_public_id, contacts, kDefaultConfirmationMessage, kFriendResponse);
  if (result != kSuccess) {
    LOG(kError) << "Failed to send confirmation to " << recipient_public_id.string();
    return kConfirmContactInformFailure;
  }

  result = contacts_handler->UpdateStatus(recipient_public_id, kConfirmed);
  if (result != kSuccess) {
    LOG(kError) << "Failed to confirm " << recipient_public_id.string();
    return kConfirmContactStatusFailure;
  }
  session_.set_changed(true);

  return kSuccess;
}

int PublicId::RejectContact(const NonEmptyString& own_public_id,
                            const NonEmptyString& recipient_public_id) {
  const ContactsHandlerPtr contacts_handler(session_.contacts_handler(own_public_id));
  if (!contacts_handler) {
    LOG(kError) << "User does not hold public id: " << own_public_id.string();
    return kPublicIdNotFoundFailure;
  }

  Contact contact;
  if (contacts_handler->ContactInfo(recipient_public_id, &contact) != kSuccess) {
    LOG(kError) << "Can't find contact info";
    return kContactNotFoundFailure;
  }

  if (contact.status != kPendingResponse) {
    LOG(kError) << "Cannot reject contact with status: " << contact.status;
    return kCanOnlyRejectPendingResponseContact;
  }

  int result(contacts_handler->DeleteContact(recipient_public_id));
  if (result == kSuccess)
    session_.set_changed(true);

  return result;
}

int PublicId::RemoveContact(const NonEmptyString& own_public_id,
                            const NonEmptyString& contact_public_id,
                            const NonEmptyString& removal_message,
                            const NonEmptyString& timestamp,
                            const bool& instigator) {
  const ContactsHandlerPtr contacts_handler(session_.contacts_handler(own_public_id));
  if (!contacts_handler) {
    LOG(kError) << "User does not have public id: " << own_public_id.string();
    return kPublicIdNotFoundFailure;
  }

  if (contacts_handler->TouchContact(contact_public_id) != kSuccess) {
    LOG(kError) << "Contact doesn't exist in list: " << contact_public_id.string();
    return kContactNotFoundFailure;
  }

  // Get current inbox identity so we can send a deletion message without our new inbox location
  Identity old_inbox_identity(
      passport_.SignaturePacketDetails(passport::kMmid,
                                       true,
                                       own_public_id).identity);

  // Generate a new MMID and store it
  int result(passport_.MoveMaidsafeInbox(own_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed to generate a new MMID: " << result;
    return kGenerateNewMMIDFailure;
  }

  std::mutex mutex;
  std::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(utils::kPendingResult);

  VoidFunctionOneBool callback = [&] (const bool& response) {
                                   utils::ChunkStoreOperationCallback(response,
                                                                      &mutex,
                                                                      &cond_var,
                                                                      &results[0]);
                                 };
  Fob new_mmid(passport_.SignaturePacketDetails(passport::kMmid, false, own_public_id));
  if (!remote_chunk_store_.Store(AppendableByAllName(new_mmid.identity),
                                 AppendableIdValue(new_mmid, true),
                                 callback,
                                 new_mmid)) {
    std::lock_guard<std::mutex> lock(mutex);
    results[0] = kRemoteChunkStoreFailure;
  }
  result = utils::WaitForResults(mutex, cond_var, results);
  if (result != kSuccess) {
    LOG(kError) << "Timed out.";
    return result;
  }
  if (results[0] != kSuccess) {
    LOG(kError) << "Failed to store new MMID when removing a contact.";
    return kRemoveContactFailure;
  }

  Identity new_card_address;
  result = StoreLifestuffCard(new_mmid, new_card_address);
  if (result != kSuccess) {
    LOG(kError) << "Failed to store new lifestuff card when removing a contact.";
    return kRemoveContactFailure;
  }

  SocialInfoDetail social_info(session_.social_info(own_public_id));
  Identity old_card_address;
  if (social_info.first) {
    std::lock_guard<std::mutex> lock(*social_info.first);
    old_card_address = social_info.second->card_address;
    social_info.second->card_address = new_card_address;
  }

  // Get contact we're deleting so we can message him later
  Contact deleted_contact;
  result = contacts_handler->ContactInfo(contact_public_id, &deleted_contact);
  if (result != kSuccess) {
    LOG(kInfo) << "Failed to remove contact: " << contact_public_id.string();
    return result;
  }

  result = contacts_handler->DeleteContact(contact_public_id);
  if (result != kSuccess) {
    LOG(kError) << "Failed to remove contact : " << contact_public_id.string();
    return result;
  }

  // Invalidate previous MMID, i.e. put it into kModifiableByOwner
  results[0] = utils::kPendingResult;
  Fob old_mmid(passport_.SignaturePacketDetails(passport::kMmid, true, own_public_id));
  callback = [&] (const bool& response) {
               utils::ChunkStoreOperationCallback(response, &mutex, &cond_var, &results[0]);
             };
  if (!remote_chunk_store_.Modify(AppendableByAllName(old_mmid.identity),
                                  ComposeModifyAppendableByAll(old_mmid.keys.private_key, false),
                                  callback,
                                  old_mmid)) {
    std::lock_guard<std::mutex> lock(mutex);
    results[0] = kRemoteChunkStoreFailure;
  }

  result = utils::WaitForResults(mutex, cond_var, results);
  if (result != kSuccess) {
    LOG(kError) << "Timed out.";
    return result;
  }
  if (results[0] != kSuccess) {
    LOG(kError) << "Failed to invalidate previous MMID when removing a contact.";
    return kRemoveContactFailure;
  }

  passport_.ConfirmMovedMaidsafeInbox(own_public_id);
  result = RemoveLifestuffCard(old_card_address, old_mmid);
  if (result != kSuccess) {
    LOG(kError) << "Failed to remove old lifestuff card.";
    return result;
  }

  session_.set_changed(true);

  if (instigator) {
    // Inform the deleted contact that we have deleted him
    std::vector<Contact> deleted_contact_vector(1, deleted_contact);
    result = InformContactInfo(own_public_id,
                               deleted_contact_vector,
                               removal_message,
                               kDefriend,
                               old_inbox_identity.string());
    if (result != kSuccess) {
      LOG(kError) << "Failed to notify deleted contact of the deletion.";
      return result;
    }
  }
  // Informs each contact in the list about the new MMID
  std::vector<Contact> contacts;
  uint16_t status(kConfirmed | kRequestSent);
  contacts_handler->OrderedContacts(&contacts, kAlphabetical, status);
  result = InformContactInfo(own_public_id, contacts, kDefaultUnfriendMessage, kMovedInbox);

  if (!instigator) {
    contact_deletion_processed_signal_(own_public_id,
                                       contact_public_id,
                                       removal_message,
                                       timestamp);
  }

  return result;
}

int PublicId::GetLifestuffCard(const NonEmptyString& my_public_id,
                               const std::string& contact_public_id,
                               SocialInfoMap& social_info) {
  Identity card_address(contact_public_id.empty() ?
                               GetOwnCardAddress(my_public_id) :
                               GetContactCardAddress(my_public_id,
                                                     NonEmptyString(contact_public_id)));

  return RetrieveLifestuffCard(card_address, social_info);
}

int PublicId::SetLifestuffCard(const NonEmptyString& my_public_id,
                               const SocialInfoMap& social_info) {
  LifeStuffCard lifestuff_card;
  lifestuff_card.set_timestamp(IsoTimeWithMicroSeconds());
  if (social_info.empty()) {
    lifestuff_card.set_empty(true);
  } else {
    lifestuff_card.set_empty(false);
    std::for_each(social_info.begin(),
                  social_info.end(),
                  [&lifestuff_card] (const SocialInfoMap::value_type &element) {
                  lifestuff_card.add_key(element.first.string());
                    lifestuff_card.add_value(element.second);
                  });
  }

  pca::SignedData signed_data;
  signed_data.set_data(lifestuff_card.SerializeAsString());
  Fob mmid(session_.passport().SignaturePacketDetails(passport::kMmid,
                                                      true,
                                                      NonEmptyString(my_public_id)));
  asymm::Signature signature(asymm::Sign(asymm::PlainText(signed_data.data()),
                                         mmid.keys.private_key));
  signed_data.set_signature(signature.string());

  Identity card_address;
  SocialInfoDetail detail(session_.social_info(my_public_id));
  if (!detail.first) {
    LOG(kError) << "No such public id " << my_public_id.string();
    return kPublicIdNotFoundFailure;
  } else {
    std::lock_guard<std::mutex> lock(*detail.first);
    card_address = detail.second->card_address;
  }

  std::mutex mutex;
  std::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(utils::kPendingResult);

  VoidFunctionOneBool callback = [&] (const bool& response) {
                                   utils::ChunkStoreOperationCallback(response,
                                                                      &mutex,
                                                                      &cond_var,
                                                                      &results[0]);
                                 };
  if (!remote_chunk_store_.Modify(ModifiableName(card_address),
                                  NonEmptyString(signed_data.SerializeAsString()),
                                  callback,
                                  mmid)) {
    LOG(kError) << "Immediate chunkstore error.";
    return kRemoteChunkStoreFailure;
  }

  int wait_result(utils::WaitForResults(mutex, cond_var, results));
  if (wait_result != kSuccess) {
    LOG(kError) << "Timed out";
    return wait_result;
  }

  if (results[0] != kSuccess) {
    LOG(kError) << "Error modifying lifestuff card.";
    return kRemoteChunkStoreFailure;
  }

  std::vector<Contact> contacts;
  session_.contacts_handler(my_public_id)->OnlineContacts(&contacts);
  wait_result = InformContactInfo(my_public_id,
                                  contacts,
                                  kDefaultCarChangeMessage,
                                  kLifestuffCardChanged);
  if (wait_result != kSuccess) {
    LOG(kError) << "Failed to inform all contacts.";
    return wait_result;
  }

  return kSuccess;
}

bs2::connection PublicId::ConnectToNewContactSignal(const NewContactFunction& new_contact_slot) {
  return new_contact_signal_.connect(new_contact_slot);
}

bs2::connection PublicId::ConnectToContactConfirmedSignal(
    const ContactConfirmationFunction& contact_confirmation_slot) {
  return contact_confirmed_signal_.connect(contact_confirmation_slot);
}

bs2::connection PublicId::ConnectToContactDeletionReceivedSignal(
    const ContactDeletionReceivedFunction& contact_deletion_received_slot) {
  return contact_deletion_received_signal_.connect(contact_deletion_received_slot);
}

bs2::connection PublicId::ConnectToContactDeletionProcessedSignal(
    const ContactDeletionFunction& contact_deletion_slot) {
  return contact_deletion_processed_signal_.connect(contact_deletion_slot);
}

bs2::connection PublicId::ConnectToLifestuffCardUpdatedSignal(
    const LifestuffCardUpdateFunction& lifestuff_card_update_slot) {
  return lifestuff_card_updated_signal_.connect(lifestuff_card_update_slot);
}

void PublicId::GetNewContacts(const bptime::seconds& interval,
                              const boost::system::error_code& error_code) {
  if (error_code) {
    if (error_code != boost::asio::error::operation_aborted) {
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
  get_new_contacts_timer_.async_wait([=] (const boost::system::error_code error_code) {
                                       GetNewContacts(interval, error_code);
                                     });
}

void PublicId::GetContactsHandle() {
  std::vector<NonEmptyString> selectables(session_.PublicIdentities());
  for (auto it(selectables.begin()); it != selectables.end(); ++it) {
    LOG(kInfo) << "PublicId::GetNewContacts: " << (*it).string();
    Fob mpid(passport_.SignaturePacketDetails(passport::kMpid, true, NonEmptyString(*it)));
    std::string mpid_packet(remote_chunk_store_.Get(MaidsafeContactIdName(*it), mpid));
    if (mpid_packet.empty()) {
      LOG(kError) << "Failed to get MPID contents for " << (*it).string();
    } else {
      ProcessRequests(*it, NonEmptyString(mpid_packet), mpid);
    }
  }
}

void PublicId::ProcessRequests(const NonEmptyString& own_public_id,
                               const NonEmptyString& retrieved_mpid_packet,
                               const Fob& mpid) {
  pca::AppendableByAll mcid;
  if (!mcid.ParseFromString(retrieved_mpid_packet.string())) {
    LOG(kError) << "Failed to parse as AppendableByAll";
    return;
  }

  for (int it(0); it < mcid.appendices_size(); ++it) {
    asymm::PlainText decrypted_introduction(
        asymm::Decrypt(asymm::CipherText(mcid.appendices(it).data()),
                       mpid.keys.private_key));

    Introduction introduction;
    if (!introduction.ParseFromString(decrypted_introduction.string())) {
      LOG(kError) << "Failed to parse as Introduction";
      continue;
    }

    const ContactsHandlerPtr contacts_handler(session_.contacts_handler(own_public_id));
    if (!contacts_handler) {
      LOG(kError) << "User does not hold such public id: " << own_public_id.string();
      continue;
    }
    Contact contact;
    int result(contacts_handler->ContactInfo(NonEmptyString(introduction.public_id()), &contact));
    if (result == kSuccess) {
      if (!asymm::CheckSignature(asymm::PlainText(mcid.appendices(it).data()),
                                 asymm::Signature(mcid.appendices(it).signature()),
                                 contact.mpid_public_key)) {
        LOG(kError) << "User has sent a message incorrectly signed: " << contact.public_id.string();
        continue;
      }
    }

    int type(introduction.type());
    switch (type) {
      case kFriendRequest:
        if (result != kSuccess) {
          ProcessNewContact(contact,
                            contacts_handler,
                            own_public_id,
                            introduction,
                            mcid.appendices(it));
        } else {
          if (contact.status == kConfirmed &&
              introduction.inbox_name() == contact.inbox_name.string())
            ProcessMisplacedContactRequest(contact, own_public_id);
          else if (contact.status == kRequestSent)
            ProcessRequestWhenExpectingResponse(contact,
                                                contacts_handler,
                                                own_public_id,
                                                introduction);
          else
            LOG(kError) << "Introduction of type kFriendRequest doesn't match current state!";
        }
        break;
      case kFriendResponse:
        if (result == kSuccess && contact.status == kRequestSent)
          ProcessContactConfirmation(contact, contacts_handler, own_public_id, introduction);
        else
          LOG(kError) << "Introduction of type kFriendResponse doesn't match current state!";
        break;
      case kDefriend:
        contact_deletion_received_signal_(own_public_id,
                                          NonEmptyString(introduction.public_id()),
                                          NonEmptyString(introduction.message()),
                                          NonEmptyString(introduction.timestamp()));
          break;
      case kMovedInbox:
        if (result == kSuccess &&
            (contact.status == kConfirmed || contact.status == kPendingResponse) &&
            introduction.inbox_name() != contact.inbox_name.string())
          ProcessContactMoveInbox(contact,
                                  contacts_handler,
                                  Identity(introduction.inbox_name()),
                                  Identity(introduction.pointer_to_info()));
        else
          LOG(kError) << "Introduction of type kMovedInbox doesn't match current state!";
        break;
      case kFixAsync:
        if (result == kSuccess && contact.status == kRequestSent)
          ProcessContactConfirmation(contact, contacts_handler, own_public_id, introduction);
        else
          LOG(kError) << "Introduction of type kFixAsync doesn't match current state!";
        break;
      case kLifestuffCardChanged:
        if (result == kSuccess &&
            (contact.status == kConfirmed || contact.status == kPendingResponse))
          lifestuff_card_updated_signal_(own_public_id,
                                         contact.public_id,
                                         NonEmptyString(introduction.timestamp()));
        else
          LOG(kError) << "Introduction of type kLifestuffCardChanged doesn't match current state!";
        break;
      default: LOG(kError) << "Introduction of unrecognised type!";
    }
  }
}

void PublicId::ProcessContactConfirmation(Contact& contact,
                                          const ContactsHandlerPtr contacts_handler,
                                          const NonEmptyString& own_public_id,
                                          const Introduction& introduction) {
  contact.status = kConfirmed;
  contact.profile_picture_data_map = NonEmptyString(introduction.profile_picture_data_map());
  contact.pointer_to_info = Identity(introduction.pointer_to_info());
  int result = GetPublicKey(Identity(introduction.inbox_name()), contact, 1);
  if (result == kSuccess) {
    result = contacts_handler->UpdateContact(contact);
    if (result == kSuccess) {
      contact_confirmed_signal_(own_public_id,
                                NonEmptyString(introduction.public_id()),
                                NonEmptyString(introduction.timestamp()));
      session_.set_changed(true);
    } else {
      LOG(kError) << "Failed to update contact after confirmation.";
    }
  } else {
    LOG(kError) << "Failed to update contact after confirmation.";
  }
}

void PublicId::ProcessContactMoveInbox(Contact& contact,
                                       const ContactsHandlerPtr contacts_handler,
                                       const Identity& inbox_name,
                                       const Identity& pointer_to_info) {
  int result = GetPublicKey(inbox_name, contact, 1);
  contact.pointer_to_info = pointer_to_info;
  if (result == kSuccess) {
    result = contacts_handler->UpdateContact(contact);
    if (result != kSuccess) {
      LOG(kError) << "Failed to update MMID.";
    } else {
      session_.set_changed(true);
    }
  } else {
    LOG(kError) << "Failed to update contact after inbox move.";
  }
}

void PublicId::ProcessNewContact(Contact& contact,
                                 const ContactsHandlerPtr contacts_handler,
                                 const NonEmptyString& own_public_id,
                                 const Introduction& introduction,
                                 const pca::SignedData& singed_introduction) {
  contact.status = kPendingResponse;
  NonEmptyString public_id(introduction.public_id());
  contact.public_id = public_id;
  contact.profile_picture_data_map = NonEmptyString(introduction.profile_picture_data_map());
  contact.pointer_to_info = Identity(introduction.pointer_to_info());
  int result = GetPublicKey(crypto::Hash<crypto::SHA512>(public_id), contact, 0);
  result += GetPublicKey(Identity(introduction.inbox_name()), contact, 1);
  if (result != kSuccess) {
    LOG(kError) << "Failed get keys of new contact.";
    return;
  }

  if (!asymm::CheckSignature(asymm::PlainText(singed_introduction.data()),
                             asymm::Signature(singed_introduction.signature()),
                             contact.mpid_public_key)) {
    LOG(kError) << "User has sent a message incorrectly signed: " << contact.public_id.string();
    return;
  }

  result = contacts_handler->AddContact(contact);
  if (result == kSuccess) {
    session_.set_changed(true);
    new_contact_signal_(own_public_id,
                        public_id,
                        NonEmptyString(introduction.message()),
                        NonEmptyString(introduction.timestamp()));
  } else {
    LOG(kInfo) << "Dropping contact " << contact.public_id.string();
  }
}

int PublicId::ProcessRequestWhenExpectingResponse(Contact& contact,
                                                  const ContactsHandlerPtr contacts_handler,
                                                  const NonEmptyString& own_public_id,
                                                  const Introduction& introduction) {
  NonEmptyString recipient_public_id(introduction.public_id());
  int result(contacts_handler->ContactInfo(recipient_public_id, &contact));
  if (result != 0 || contact.status != kRequestSent) {
    LOG(kError) << "No such kRequestSent username found: " << recipient_public_id.string();
    return kPRWERGetInfoFailure;
  }

  contact.status = kConfirmed;
  contact.profile_picture_data_map = NonEmptyString(introduction.profile_picture_data_map());
  contact.pointer_to_info = Identity(introduction.pointer_to_info());
  result = GetPublicKey(Identity(introduction.inbox_name()), contact, 1);
  if (result != kSuccess) {
    LOG(kError) << "Failed to get contact's public key!";
    return kPRWERPublicKeyFailure;
  }

  std::vector<Contact> contacts(1, contact);
  result = InformContactInfo(own_public_id, contacts, kDefaultRequestMessage, kFriendResponse);
  if (result != kSuccess) {
    LOG(kError) << "Failed to send confirmation to " << recipient_public_id.string();
    return kPRWERInformFailure;
  }

  result = contacts_handler->UpdateContact(contact);
  if (result != kSuccess) {
    LOG(kError) << "Failed to update contact after confirmation.";
    return kPRWERStatusFailure;
  }

  contact_confirmed_signal_(own_public_id,
                            recipient_public_id,
                            NonEmptyString(introduction.timestamp()));
  session_.set_changed(true);

  return kSuccess;
}

void PublicId::ProcessMisplacedContactRequest(Contact& contact,
                                              const NonEmptyString& own_public_id) {
  std::vector<Contact> contacts(1, contact);
  int result = InformContactInfo(own_public_id, contacts, kDefaultAsyncFixMessage, kFixAsync);
  if (result != kSuccess) {
    LOG(kError) << "Failed to send confirmation to " << contact.public_id.string();
  }
}

int PublicId::ModifyAppendability(const NonEmptyString& own_public_id, const bool appendability) {
  // Change appendability of MCID,MMID by modify them via ModifyAppendableByAll
  std::mutex mutex;
  std::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(utils::kPendingResult);
  results.push_back(utils::kPendingResult);

  Fob mpid(passport_.SignaturePacketDetails(passport::kMpid, true, own_public_id));
  Fob mmid(passport_.SignaturePacketDetails(passport::kMmid, true, own_public_id));

  VoidFunctionOneBool callback = [&] (const bool& response) {
                                   utils::ChunkStoreOperationCallback(response, &mutex, &cond_var,
                                                                      &results[0]);
                                 };
  if (!remote_chunk_store_.Modify(MaidsafeContactIdName(own_public_id),
                                  ComposeModifyAppendableByAll(mpid.keys.private_key,
                                                               appendability),
                                  callback,
                                  mpid)) {
    LOG(kError) << "Immediate modify failure for MPID.";
    std::lock_guard<std::mutex> lock(mutex);
    results[0] = kRemoteChunkStoreFailure;
  }

  callback = [&] (const bool& response) {
               utils::ChunkStoreOperationCallback(response, &mutex, &cond_var, &results[1]);
             };
  if (!remote_chunk_store_.Modify(AppendableByAllName(mmid.identity),
                                  ComposeModifyAppendableByAll(mmid.keys.private_key,
                                                               appendability),
                                  callback,
                                  mmid)) {
    LOG(kError) << "Immediate modify failure for MMID.";
    std::lock_guard<std::mutex> lock(mutex);
    results[1] = kRemoteChunkStoreFailure;
  }

  int result = utils::WaitForResults(mutex, cond_var, results);
  if (result != kSuccess) {
    LOG(kError) << "Timed out wating for updates: " << own_public_id.string();
    return result;
  }

  if (!(results[0] == kSuccess && results[1] == kSuccess)) {
    LOG(kError) << "Failed to modifying MCID/MMID when modify public_id with MCID Result : "
                << results[0] << " , MMID result :" << results[1];
    return kModifyAppendabilityFailure;
  }

  return kSuccess;
}

int PublicId::InformContactInfo(const NonEmptyString& public_id,
                                const std::vector<Contact>& contacts,
                                const NonEmptyString& message,
                                const IntroductionType& type,
                                const std::string& inbox_name) {
  // Get our MMID name, and MPID private key
  Identity inbox_identity;
  if (inbox_name.empty())
    inbox_identity = passport_.SignaturePacketDetails(passport::kMmid,
                                                      true,
                                                      public_id).identity;
  else
    inbox_identity = Identity(inbox_name);

  Fob mpid(passport_.SignaturePacketDetails(passport::kMpid, true, public_id));

  // Inform each contact in the contact list of the MMID contact info
  std::mutex mutex;
  std::condition_variable cond_var;
  std::vector<int> results(contacts.size(), utils::kPendingResult);
  size_t size(contacts.size());

  for (size_t i = 0; i < size; ++i) {
    NonEmptyString recipient_public_id(contacts[i].public_id);
    // Get recipient's public key
    asymm::PublicKey recipient_public_key(contacts[i].mpid_public_key);

    Introduction introduction;
    introduction.set_inbox_name(inbox_identity.string());
    introduction.set_public_id(public_id.string());
    introduction.set_timestamp(IsoTimeWithMicroSeconds());
    introduction.set_type(type);
    introduction.set_message(message.string());

    SocialInfoDetail social_info(session_.social_info(public_id));
    if (social_info.first) {
      std::lock_guard<std::mutex> lock(*social_info.first);
      introduction.set_profile_picture_data_map(social_info.second->profile_picture_datamap.string());
      introduction.set_pointer_to_info(social_info.second->card_address.string());
    } else {
      LOG(kInfo) << "Failure to find profile picture data map for public id: "
                 << public_id.string();
    }

    asymm::CipherText encrypted_introduction(
        asymm::Encrypt(crypto::PlainText(introduction.SerializeAsString()),
                                         recipient_public_key));
    asymm::Signature signature(asymm::Sign(encrypted_introduction, mpid.keys.private_key));
    pca::SignedData signed_data;
    signed_data.set_data(encrypted_introduction.string());
    signed_data.set_signature(signature.string());

    // Store encrypted MCID at recipient's MPID's name
    priv::ChunkId contact_id(MaidsafeContactIdName(recipient_public_id));
    VoidFunctionOneBool callback = [&] (const bool& response) {
                                     utils::ChunkStoreOperationCallback(response, &mutex, &cond_var,
                                                                        &results[i]);
                                   };
    if (!remote_chunk_store_.Modify(contact_id,
                                    NonEmptyString(signed_data.SerializeAsString()),
                                    callback,
                                    mpid)) {
      LOG(kError) << "Failed to send out the message to: " << contact_id.string();
      std::lock_guard<std::mutex> lock(mutex);
      results[i] = kRemoteChunkStoreFailure;
    }
  }
  int result(utils::WaitForResults(mutex, cond_var, results));
  if (result != kSuccess) {
    LOG(kError) << "Timed out.";
    return result;
  }

  for (size_t j = 0; j < size; ++j) {
    if (results[j] != kSuccess) {
      LOG(kError) << "Failed on element: " << j;
      return kSendContactInfoFailure;
    }
  }
  return kSuccess;
}

int PublicId::GetPublicKey(const Identity& packet_name, Contact& contact, int type) {
  priv::ChunkId public_key_chunk_name(AppendableByAllName(packet_name));
  std::string network_packet(remote_chunk_store_.Get(public_key_chunk_name, Fob()));
  if (network_packet.empty()) {
    LOG(kError) << "Failed to obtain packet from network.";
    return kGetPublicKeyFailure;
  }

  pca::SignedData packet;
  if (!packet.ParseFromString(network_packet)) {
    LOG(kError) << "Failed to parse public key packet for " << contact.public_id.string();
    return kGetPublicKeyFailure;
  }

  asymm::PublicKey public_key(asymm::DecodeKey(asymm::EncodedPublicKey(packet.data())));
  if (!asymm::ValidateKey(public_key)) {
    LOG(kError) << "Failed to validate public key for " << contact.public_id.string();
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

NonEmptyString EmptyCardContent(const asymm::PrivateKey& private_key) {
  pca::SignedData signed_data;
  LifeStuffCard lifestuff_card;
  lifestuff_card.set_empty(true);
  lifestuff_card.set_timestamp(IsoTimeWithMicroSeconds());
  signed_data.set_data(lifestuff_card.SerializeAsString());

  asymm::Signature signature(asymm::Sign(NonEmptyString(signed_data.data()), private_key));
  signed_data.set_signature(signature.string());

  return NonEmptyString(signed_data.SerializeAsString());
}

int PublicId::StoreLifestuffCard(const Fob& mmid, Identity& lifestuff_card_address) {
  int attempts(0), wait_result(kSuccess);
  Identity card_address;
  NonEmptyString empty_card_content(EmptyCardContent(mmid.keys.private_key));
  std::vector<int> results(1, utils::kPendingResult);
  std::mutex mutex;
  std::condition_variable cond_var;
  VoidFunctionOneBool callback = [&] (const bool& response) {
                                   utils::ChunkStoreOperationCallback(response,
                                                                      &mutex,
                                                                      &cond_var,
                                                                      &results[0]);
                                 };
  while (attempts++ < 10) {
    results[0] = utils::kPendingResult;
    card_address = Identity(RandomString(64));
    if (!remote_chunk_store_.Store(ModifiableName(card_address),
                                   empty_card_content,
                                   callback,
                                   mmid)) {
      LOG(kInfo) << "Failed to store lifestuff card, attempt: " << (attempts - 1);
      return kRemoteChunkStoreFailure;
    }

    wait_result = utils::WaitForResults(mutex, cond_var, results);
    if (wait_result == kSuccess && results[0] == kSuccess) {
      LOG(kInfo) << "Success storing the lifestuff card.";
      break;
    }
  }

  lifestuff_card_address = card_address;

  return kSuccess;
}

int PublicId::RemoveLifestuffCard(const Identity& lifestuff_card_address, const Fob& mmid) {
  std::vector<int> results(1, utils::kPendingResult);
  std::mutex mutex;
  std::condition_variable cond_var;
  VoidFunctionOneBool callback = [&] (const bool& response) {
                                   utils::ChunkStoreOperationCallback(response,
                                                                      &mutex,
                                                                      &cond_var,
                                                                      &results[0]);
                                 };
  if (!remote_chunk_store_.Delete(ModifiableName(lifestuff_card_address), callback, mmid)) {
    LOG(kError) << "Failed to delete lifestuff card.";
    return kRemoteChunkStoreFailure;
  }

  int wait_result(utils::WaitForResults(mutex, cond_var, results));
  if (wait_result != kSuccess) {
    LOG(kInfo) << "Timed out deleting the lifestuff card.";
    return wait_result;
  }

  if (results[0] != kSuccess) {
    LOG(kInfo) << "Failure deleting the lifestuff card.";
    return kRemoteChunkStoreFailure;
  }

  return kSuccess;
}

Identity PublicId::GetOwnCardAddress(const NonEmptyString& my_public_id) {
  const SocialInfoDetail details(session_.social_info(my_public_id));
  std::lock_guard<std::mutex> lock(*details.first);
  return details.second->card_address;
}

Identity PublicId::GetContactCardAddress(const NonEmptyString& my_public_id,
                                         const NonEmptyString& contact_public_id) {
  const ContactsHandlerPtr contact_handler(session_.contacts_handler(my_public_id));
  Contact contact;
  contact_handler->ContactInfo(contact_public_id, &contact);

  return contact.pointer_to_info;
}

int PublicId::RetrieveLifestuffCard(const Identity& lifestuff_card_address,
                                    SocialInfoMap& social_info) {
  priv::ChunkId card_address(ModifiableName(lifestuff_card_address));
  std::string net_lifestuff_card(remote_chunk_store_.Get(card_address, Fob()));

  pca::SignedData signed_data;
  if (!signed_data.ParseFromString(net_lifestuff_card)) {
    LOG(kError) << "Network data doesn't parse for " << Base32Substr(lifestuff_card_address);
    return kRemoteChunkStoreFailure;
  }

  LifeStuffCard lifestuff_card;
  if (!lifestuff_card.ParseFromString(signed_data.data())) {
    LOG(kError) << "Network data doesn't parse for " << Base32Substr(lifestuff_card_address);
    return kRemoteChunkStoreFailure;
  }

  if (lifestuff_card.empty()) {
    LOG(kInfo) << "Card is empty for " << Base32Substr(lifestuff_card_address);
    return kSuccess;
  }

  int size(lifestuff_card.key_size() > lifestuff_card.value_size() ? lifestuff_card.value_size() :
                                                                     lifestuff_card.key_size());
  for (int n(0); n < size; ++n)
    social_info[NonEmptyString(lifestuff_card.key(n))] = lifestuff_card.value(n);

  return kSuccess;
}

void PublicId::StoreMpid(bool response,
                         OperationResults& results,
                         const NonEmptyString& public_id,
                         bool accepts_new_contacts) {
  if (!response) {
    LOG(kError) << "Anmpid failed to store.";
    OperationCallback(false, results, 1);
    return;
  }

  Fob anmpid(passport_.SignaturePacketDetails(passport::kAnmpid, false, public_id));
  Fob mpid(passport_.SignaturePacketDetails(passport::kMpid, false, public_id));
  VoidFunctionOneBool callback = [&] (const bool& response) {
                                   StoreMcid(response, results, public_id, accepts_new_contacts);
                                 };
  priv::ChunkId mpid_name(SignaturePacketName(mpid.identity));
  if (!remote_chunk_store_.Store(mpid_name, SignaturePacketValue(mpid), callback, anmpid)) {
    LOG(kError) << "Failed to store ANMPID";
    OperationCallback(false, results, 1);
  }
}

void PublicId::StoreMcid(bool response,
                         OperationResults& results,
                         const NonEmptyString& public_id,
                         bool accepts_new_contacts) {
  if (!response) {
    LOG(kError) << "Mpid failed to store.";
    OperationCallback(false, results, 1);
    return;
  }
  Fob mpid(passport_.SignaturePacketDetails(passport::kMpid, false, public_id));
  priv::ChunkId mcid_name(MaidsafeContactIdName(public_id));
  VoidFunctionOneBool callback = [&] (const bool& response) {
                                   OperationCallback(response, results, 1);
                                 };
  if (!remote_chunk_store_.Store(mcid_name,
                                 AppendableIdValue(mpid, accepts_new_contacts),
                                 callback,
                                 mpid)) {
    LOG(kError) << "Mcid failed to store";
    OperationCallback(false, results, 1);
  }
}

}  // namespace lifestuff

}  // namespace maidsafe
