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

#include "maidsafe/lifestuff/message_handler.h"

#include <vector>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#include "maidsafe/encrypt/data_map.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/utils.h"

namespace args = std::placeholders;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

namespace {

void SendMessageCallback(const bool &response,
                         boost::mutex *mutex,
                         boost::condition_variable *cond_var,
                         int *result) {
  if (!mutex || !cond_var || !result)
    return;
  boost::mutex::scoped_lock lock(*mutex);
  if (response)
    *result = kSuccess;
  else
    *result = kMessageHandlerError;
  cond_var->notify_one();
}

std::string AppendableByAllType(const std::string &mmid) {
  return mmid + std::string(1, pca::kAppendableByAll);
}

}  // namespace

MessageHandler::MessageHandler(
    std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
    std::shared_ptr<Session> session,
    boost::asio::io_service &asio_service)  // NOLINT (Fraser)
    : remote_chunk_store_(remote_chunk_store),
      session_(session),
      get_new_messages_timer_(asio_service),
      chat_signal_(new ChatMessageSignal),
      file_transfer_signal_(new FileTransferSignal),
      share_invitation_signal_(new ShareInvitationSignal),
      share_deletion_signal_(new ShareDeletionSignal),
      share_update_signal_(new ShareUpdateSignal),
      member_access_level_signal_(new MemberAccessLevelSignal),
      save_share_data_signal_(new SaveShareDataSignal),
      share_user_leaving_signal_(new ShareUserLeavingSignal),
      contact_presence_signal_(new ContactPresenceSignal),
      contact_profile_picture_signal_(new ContactProfilePictureSignal),
      contact_deletion_signal_(new ContactDeletionSignal),
      parse_and_save_data_map_signal_(new ParseAndSaveDataMapSignal),
      received_messages_(),
      asio_service_(asio_service),
      start_up_done_(false) {}

MessageHandler::~MessageHandler() {
  StopCheckingForNewMessages();
}

void MessageHandler::StartUp(bptime::seconds interval) {
  // Retrive once all messages
  RetrieveMessagesForAllIds();
  EnqueuePresenceMessages(kOnline);
  start_up_done_ = true;
  StartCheckingForNewMessages(interval);
}

void MessageHandler::ShutDown() {
  StopCheckingForNewMessages();
  EnqueuePresenceMessages(kOffline);
}

void MessageHandler::EnqueuePresenceMessages(ContactPresence presence) {
  // Get online contacts and message them to notify online status
  std::vector<Contact> contacts;
  for (auto it(session_->contact_handler_map().begin());
       it != session_->contact_handler_map().end();
       ++it) {
    (*it).second->OrderedContacts(&contacts, kAlphabetical, kConfirmed);
    for (auto item(contacts.begin()); item != contacts.end(); ++item) {
      SendPresenceMessage((*it).first, (*item).public_username, presence);
    }
  }
}

int MessageHandler::StartCheckingForNewMessages(bptime::seconds interval) {
  std::vector<passport::SelectableIdData> selectables;
  session_->passport_->SelectableIdentitiesList(&selectables);
  if (selectables.empty()) {
    DLOG(ERROR) << "No public username set";
    return kNoPublicIds;
  }
  get_new_messages_timer_.expires_from_now(interval);
  get_new_messages_timer_.async_wait(std::bind(&MessageHandler::GetNewMessages,
                                               this,
                                               interval,
                                               std::placeholders::_1));
  return kSuccess;
}

void MessageHandler::StopCheckingForNewMessages() {
//   get_new_messages_timer_.cancel();
  get_new_messages_timer_.expires_at(boost::posix_time::pos_infin);
}

int MessageHandler::Send(const std::string &public_username,
                         const std::string &recipient_public_username,
                         const InboxItem &inbox_item) {
  Message message;
  if (!InboxToProtobuf(inbox_item, &message)) {
    DLOG(ERROR) << "Invalid message. Won't send. Good day. I said: 'Good day!'";
    return -7;
  }
  Contact recipient_contact;
  int result(session_->contact_handler_map()[public_username]->ContactInfo(
                 recipient_public_username,
                 &recipient_contact));
  if (result != kSuccess || recipient_contact.mmid_name.empty()) {
    DLOG(ERROR) << "Failed to get MMID for " << recipient_public_username
                << ", type: " <<inbox_item.item_type;
    return result == kSuccess ? kGeneralError : result;
  }

  // Retrieves ANMPID, MPID, and MMID's <name, value, signature>
  passport::SelectableIdentityData data;
  result = session_->passport_->GetSelectableIdentityData(public_username,
                                                          true,
                                                          &data);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get own public ID data: " << result;
    return kGetPublicIdError;
  }
  BOOST_ASSERT(data.size() == 3U);

  // Get recipient's public key
  pcs::RemoteChunkStore::ValidationData validation_data_mmid;
  KeysAndProof(public_username,
                  passport::kMmid,
                  true,
                  &validation_data_mmid);
  asymm::PublicKey recipient_public_key;
  result = GetValidatedMmidPublicKey(recipient_contact.mmid_name,
                                     validation_data_mmid,
                                     remote_chunk_store_,
                                     &recipient_public_key);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get public key for " << recipient_public_username;
    return result;
  }

  // Encrypt the message for the recipient
  std::string encrypted_message;
  result = asymm::Encrypt(message.SerializeAsString(),
                          recipient_public_key,
                          &encrypted_message);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get own public ID data: " << result;
    return kGetPublicIdError;
  }

  pca::SignedData signed_data;
  signed_data.set_data(encrypted_message);

  // Get PrivateKey for this user
  asymm::PrivateKey mmid_private_key(session_->passport_->PacketPrivateKey(
                                         passport::kMmid,
                                         true,
                                         public_username));

  std::string message_signature;
  result = asymm::Sign(signed_data.data(),
                       mmid_private_key,
                       &message_signature);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to sign message: " << result;
    return result;
  }

  signed_data.set_signature(message_signature);

  // Store encrypted MMID at recipient's MPID's name
  boost::mutex mutex;
  boost::condition_variable cond_var;
  result = kPendingResult;

  std::string inbox_id(AppendableByAllType(recipient_contact.mmid_name));
  VoidFunctionOneBool callback(std::bind(&SendMessageCallback, args::_1, &mutex,
                                         &cond_var, &result));
  remote_chunk_store_->Modify(inbox_id,
                              signed_data.SerializeAsString(),
                              callback,
                              validation_data_mmid);

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
    return kMessageHandlerException;
  }
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to store packet.  Result: " << result;
    return result;
  }

  return kSuccess;
}

void MessageHandler::GetNewMessages(
    const bptime::seconds &interval,
    const boost::system::error_code &error_code) {
  if (error_code) {
    if (error_code != ba::error::operation_aborted) {
      DLOG(WARNING) << "Refresh timer error: " << error_code.message();
    } else {
      return;
    }
  }

  ClearExpiredReceivedMessages();
  RetrieveMessagesForAllIds();

  get_new_messages_timer_.expires_at(get_new_messages_timer_.expires_at() +
                                     interval);
  get_new_messages_timer_.async_wait(std::bind(&MessageHandler::GetNewMessages,
                                               this,
                                               interval,
                                               std::placeholders::_1));
}

void MessageHandler::ProcessRetrieved(const passport::SelectableIdData &data,
                                      const std::string &mmid_value) {
  pca::AppendableByAll mmid;
  if (!mmid.ParseFromString(mmid_value)) {
    DLOG(ERROR) << "Failed to parse as AppendableByAll";
    return;
  }

  for (int it(0); it < mmid.appendices_size(); ++it) {
    pca::SignedData signed_data(mmid.appendices(it));
    asymm::PublicKey mmid_pub_key(session_->passport_->SignaturePacketValue(
                                      passport::kMmid,
                                      true,
                                      std::get<0>(data)));
    std::string serialised_pub_key;
    asymm::EncodePublicKey(mmid_pub_key, &serialised_pub_key);
    asymm::PrivateKey mmid_private_key(session_->passport_->PacketPrivateKey(
                                           passport::kMmid,
                                           true,
                                           std::get<0>(data)));

    std::string decrypted_message;
    int n(asymm::Decrypt(signed_data.data(),
                         mmid_private_key,
                         &decrypted_message));
    if (n != kSuccess) {
      DLOG(ERROR) << "Failed to decrypt message: " << n;
      continue;
    }

    Message mmid_message;
    if (!mmid_message.ParseFromString(decrypted_message)) {
      DLOG(ERROR) << "Failed to parse decrypted message";
      continue;
    }

    InboxItem inbox_item;
    if (ProtobufToInbox(mmid_message, &inbox_item) &&
        !MessagePreviouslyReceived(decrypted_message)) {
      switch (inbox_item.item_type) {
        case kChat: (*chat_signal_)(inbox_item.receiver_public_id,
                                    inbox_item.sender_public_id,
                                    inbox_item.content.at(0));
                    break;
        case kFileTransfer: SignalFileTransfer(inbox_item);
                            break;
        case kContactProfilePicture: ContactProfilePictureSlot(inbox_item);
                                     break;
        case kContactPresence: ContactPresenceSlot(inbox_item);
                               break;
        case kContactDeletion: ContactDeletionSlot(inbox_item);
                               break;
        case kShare: SignalShare(inbox_item);
                     break;
      }
    }
  }
}

bool MessageHandler::ProtobufToInbox(const Message &message,
                                     InboxItem *inbox_item) const {
  if (!message.IsInitialized()) {
    DLOG(WARNING) << "Message not initialised.";
    return false;
  }

  if (message.content_size() == 0) {
    DLOG(WARNING) << "Message with no content. Type: " << message.type();
    return false;
  }

  if (message.type() > kMaxInboxItemType) {
    DLOG(WARNING) << "Message type out of range.";
    return false;
  }

  inbox_item->item_type = static_cast<InboxItemType>(message.type());
  inbox_item->sender_public_id = message.sender_public_username();
  inbox_item->receiver_public_id = message.receiver_public_username();
  inbox_item->timestamp = message.timestamp();
  for (auto n(0); n < message.content_size(); ++n)
    inbox_item->content.push_back(message.content(n));

  return true;
}

bool MessageHandler::InboxToProtobuf(const InboxItem &inbox_item,
                                     Message *message) const {
  if (!message)
    return false;

  message->set_type(inbox_item.item_type);
  message->set_sender_public_username(inbox_item.sender_public_id);
  message->set_receiver_public_username(inbox_item.receiver_public_id);
  message->set_timestamp(inbox_item.timestamp);
  for (size_t n(0); n < inbox_item.content.size(); ++n)
    message->add_content(inbox_item.content[n]);

  return true;
}

bool MessageHandler::MessagePreviouslyReceived(const std::string &message) {
  if (received_messages_.find(message) == received_messages_.end()) {
    received_messages_.insert(
        std::make_pair(message,
                       GetDurationSinceEpoch().total_milliseconds()));
    return false;
  }

  return true;
}

void MessageHandler::ClearExpiredReceivedMessages() {
  // TODO(Team): There might be a more efficient way of doing this (BIMAP)
  uint64_t now(GetDurationSinceEpoch().total_milliseconds());
  for (auto it(received_messages_.begin()); it != received_messages_.end(); ) {
    if ((*it).second < now)
      it = received_messages_.erase(it);
    else
      ++it;
  }
}

void MessageHandler::KeysAndProof(
    const std::string &public_username,
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
      session_->passport_->PacketName(pt, confirmed, public_username);
  validation_data->key_pair.public_key =
      session_->passport_->SignaturePacketValue(pt, confirmed, public_username);
  validation_data->key_pair.private_key =
      session_->passport_->PacketPrivateKey(pt, confirmed, public_username);
  validation_data->key_pair.validation_token =
      session_->passport_->PacketSignature(pt, confirmed, public_username);
  pca::SignedData signed_data;
  signed_data.set_data(RandomString(64));
  asymm::Sign(signed_data.data(),
              validation_data->key_pair.private_key,
              &validation_data->ownership_proof);
  signed_data.set_signature(validation_data->ownership_proof);
  validation_data->ownership_proof = signed_data.SerializeAsString();
}

void MessageHandler::ContactPresenceSlot(const InboxItem &presence_message) {
  if (presence_message.content.size() != 1U) {
    // Drop silently
    DLOG(WARNING) << presence_message.sender_public_id
                  << " has sent a presence message with bad content: "
                  << presence_message.content.size();
    return;
  }

  std::string sender(presence_message.sender_public_id),
              receiver(presence_message.receiver_public_id);
  int result(0);
  if (presence_message.content[0] == "kOnline") {
    result = session_->contact_handler_map()[receiver]->UpdatePresence(sender,
                                                                       kOnline);
    if (result == kSuccess && start_up_done_)
      (*contact_presence_signal_)(receiver, sender, kOnline);
  } else if (presence_message.content[0] == "kOffline") {
    result =
        session_->contact_handler_map()[receiver]->UpdatePresence(sender,
                                                                  kOffline);
    if (result == kSuccess && start_up_done_)
      (*contact_presence_signal_)(receiver, sender, kOffline);

    // Send message so they know we're online when they come back
    asio_service_.post(std::bind(&MessageHandler::SendPresenceMessage,
                                 this, receiver, sender, kOnline));
  } else {
    DLOG(WARNING) << presence_message.sender_public_id
                  << " has sent a presence message with wrong content.";
  }
}

void MessageHandler::ContactProfilePictureSlot(
    const InboxItem &profile_picture_message) {
  if (profile_picture_message.content.size() != 1U ||
      profile_picture_message.content[0].empty()) {
    // Drop silently
    DLOG(WARNING) << profile_picture_message.sender_public_id
                  << " has sent a profile picture message with bad content.";
    return;
  }

  std::string sender(profile_picture_message.sender_public_id),
              receiver(profile_picture_message.receiver_public_id);
  if (profile_picture_message.content[0] != kBlankProfilePicture) {
    encrypt::DataMapPtr data_map(
        ParseSerialisedDataMap(profile_picture_message.content[0]));
    if (!data_map) {
      DLOG(WARNING) << "Data map didn't parse.";
      return;
    }
  }

  int result(session_->contact_handler_map()
                 [receiver]->UpdateProfilePictureDataMap(
                     sender,
                     profile_picture_message.content[0]));
  if (result != kSuccess) {
    DLOG(WARNING) << "Failed to update picture DM in session: " << result;
    return;
  }

  (*contact_profile_picture_signal_)(receiver, sender);
}

void MessageHandler::RetrieveMessagesForAllIds() {
  int result(-1);
  std::vector<passport::SelectableIdData> selectables;
  session_->passport_->SelectableIdentitiesList(&selectables);
  for (auto it(selectables.begin()); it != selectables.end(); ++it) {
    passport::SelectableIdentityData data;
    result = session_->passport_->GetSelectableIdentityData(std::get<0>(*it),
                                                            true,
                                                            &data);
    if (result != kSuccess || data.size() != 3U) {
      DLOG(ERROR) << "Failed to get own public ID data: " << result;
      continue;
    }

    pcs::RemoteChunkStore::ValidationData validation_data_mmid;
    KeysAndProof(std::get<0>(*it),
                    passport::kMmid,
                    true,
                    &validation_data_mmid);
    std::string mmid_value(
        remote_chunk_store_->Get(AppendableByAllType(std::get<1>(*it)),
                                 validation_data_mmid));

    if (mmid_value.empty()) {
      DLOG(WARNING) << "Failed to get MPID contents for " << std::get<0>(*it)
                    << ": " << result;
    } else {
      ProcessRetrieved(*it, mmid_value);
      ClearExpiredReceivedMessages();
    }
  }
}

int MessageHandler::SendPresenceMessage(
    const std::string &own_public_username,
    const std::string &recipient_public_username,
    const ContactPresence &presence) {
  InboxItem inbox_item(kContactPresence);
  inbox_item.sender_public_id  = own_public_username;
  inbox_item.receiver_public_id = recipient_public_username;

  if (presence == kOnline)
    inbox_item.content.push_back("kOnline");
  else
    inbox_item.content.push_back("kOffline");

  int result(Send(own_public_username, recipient_public_username, inbox_item));
  if (result != kSuccess) {
    DLOG(ERROR) << own_public_username << " failed to inform "
                << recipient_public_username << " of presence state "
                << presence << ", result: " << result;
    session_->contact_handler_map()
        [own_public_username]->UpdatePresence(recipient_public_username,
                                              kOffline);
  }

  return result;
}

void MessageHandler::InformConfirmedContactOnline(
    const std::string &own_public_id,
    const std::string &recipient_public_id) {
  asio_service_.post(std::bind(&MessageHandler::SendPresenceMessage, this,
                               own_public_id, recipient_public_id, kOnline));
}

void MessageHandler::SignalFileTransfer(const InboxItem &inbox_item) {
  if (inbox_item.content.size() != 2U ||
      inbox_item.content[0].empty() ||
      inbox_item.content[1].empty()) {
    DLOG(ERROR) << "Wrong number of arguments for message.";
    (*file_transfer_signal_)(inbox_item.receiver_public_id,
                             inbox_item.sender_public_id,
                             "", "");
    return;
  }

  std::string data_map_hash;
  if (!(*parse_and_save_data_map_signal_)(inbox_item.content[1],
                                          &data_map_hash)) {
    DLOG(ERROR) << "Failed to parse file DM";
    (*file_transfer_signal_)(inbox_item.receiver_public_id,
                             inbox_item.sender_public_id,
                             inbox_item.content[0],
                             "");
    return;
  }

  (*file_transfer_signal_)(inbox_item.receiver_public_id,
                           inbox_item.sender_public_id,
                           inbox_item.content[0],
                           data_map_hash);
}

void MessageHandler::SignalShare(const InboxItem &inbox_item) {
  if (inbox_item.content[1] == "remove_share") {
    (*share_deletion_signal_)(inbox_item.receiver_public_id,
                              inbox_item.content[0]);
  } else if (inbox_item.content[1] == "update_share") {
    asymm::Keys key_ring;
    if (inbox_item.content.size() > 4) {
      key_ring.identity = inbox_item.content[4];
      key_ring.validation_token = inbox_item.content[5];
      asymm::DecodePrivateKey(inbox_item.content[6], &(key_ring.private_key));
      asymm::DecodePublicKey(inbox_item.content[7], &(key_ring.public_key));
    }

    (*share_update_signal_)(inbox_item.content[0],
                        &inbox_item.content[3],
                        &inbox_item.content[2],
                        inbox_item.content.size() > 4 ? &key_ring : nullptr);
  } else if (inbox_item.content[1] == "leave_share") {
    (*share_user_leaving_signal_)(inbox_item.content[0],
                                  inbox_item.sender_public_id);
  } else {
    Message message;
    InboxToProtobuf(inbox_item, &message);
    if (!(*save_share_data_signal_)(message.SerializeAsString(),
                                    inbox_item.content[0])) {
      DLOG(ERROR) << "Failed to save received share data";
      return;
    }
  }

  if (inbox_item.content[1] == "insert_share")
    (*share_invitation_signal_)(inbox_item.receiver_public_id,
                                inbox_item.sender_public_id,
                                inbox_item.content[0],
                                inbox_item.content[0]);

  if (inbox_item.content[1] == "upgrade_share")
    (*member_access_level_signal_)(inbox_item.receiver_public_id,
                                   inbox_item.sender_public_id,
                                   inbox_item.content[0],
                                   1);
}

void MessageHandler::SendEveryone(const InboxItem &message) {
  std::vector<Contact> contacts;
  session_->contact_handler_map()
      [message.sender_public_id]->OrderedContacts(&contacts,
                                                  kAlphabetical,
                                                  kConfirmed);
  auto it_map(contacts.begin());
  while (it_map != contacts.end()) {
    InboxItem local_message(message);
    local_message.receiver_public_id = (*it_map++).public_username;
    DLOG(ERROR) << "local_message: " << local_message.content[0].size();
    asio_service_.post(std::bind(&MessageHandler::Send,
                                 this,
                                 local_message.sender_public_id,
                                 local_message.receiver_public_id,
                                 local_message));
  }
}

void MessageHandler::ContactDeletionSlot(const InboxItem &deletion_item) {
  DLOG(ERROR) << "MessageHandler::ContactDeletionSlot";
  std::string my_public_id(deletion_item.receiver_public_id),
              contact_public_id(deletion_item.sender_public_id);
  // PublicId - To run RemoveContact
  // UserStorage - To remove contact from all shares
  // UI - To do whatever it is they do out there, in that crazy world
  (*contact_deletion_signal_)(my_public_id,
                              contact_public_id,
                              deletion_item.content.at(0));
}

bs2::connection MessageHandler::ConnectToChatSignal(
    const ChatFunction &function) {
  return chat_signal_->connect(function);
}

bs2::connection MessageHandler::ConnectToFileTransferSignal(
    const FileTransferFunction &function) {
  return file_transfer_signal_->connect(function);
}

bs2::connection MessageHandler::ConnectToShareInvitationSignal(
    const ShareInvitationFunction &function) {
  return share_invitation_signal_->connect(function);
}

bs2::connection MessageHandler::ConnectToShareDeletionSignal(
    const ShareDeletionFunction &function) {
  return share_deletion_signal_->connect(function);
}

bs2::connection MessageHandler::ConnectToShareUpdateSignal(
    const ShareUpdateSignal::slot_type &function) {
  return share_update_signal_->connect(function);
}

bs2::connection MessageHandler::ConnectToMemberAccessLevelSignal(
    const MemberAccessLevelFunction &function) {
  return member_access_level_signal_->connect(function);
}

bs2::connection MessageHandler::ConnectToSaveShareDataSignal(
    const SaveShareDataSignal::slot_type &function) {
  return save_share_data_signal_->connect(function);
}

bs2::connection MessageHandler::ConnectToShareUserLeavingSignal(
    const ShareUserLeavingSignal::slot_type &function) {
  return share_user_leaving_signal_->connect(function);
}

bs2::connection MessageHandler::ConnectToContactPresenceSignal(
    const ContactPresenceFunction &function) {
  return contact_presence_signal_->connect(function);
}

bs2::connection MessageHandler::ConnectToContactProfilePictureSignal(
    const ContactProfilePictureFunction &function) {
  return contact_profile_picture_signal_->connect(function);
}

bs2::connection MessageHandler::ConnectToParseAndSaveDataMapSignal(
    const ParseAndSaveDataMapSignal::slot_type &function) {
  return parse_and_save_data_map_signal_->connect(function);
}

bs2::connection MessageHandler::ConnectToContactDeletionSignal(
    const ContactDeletionFunction &function) {
  return contact_deletion_signal_->connect(function);
}

}  // namespace lifestuff

}  // namespace maidsafe
