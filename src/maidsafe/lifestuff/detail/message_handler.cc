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

#include "maidsafe/lifestuff/detail/message_handler.h"

#include <vector>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#include "maidsafe/encrypt/data_map.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/rcs_helper.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

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
      asio_service_(asio_service),
      start_up_done_(false),
      received_messages_(),
      chat_signal_(),
      file_transfer_signal_(),
      contact_presence_signal_(),
      contact_profile_picture_signal_(),
      private_share_invitation_signal_(),
      private_share_deletion_signal_(),
      private_member_access_level_signal_(),
      open_share_invitation_signal_(),
      contact_deletion_signal_(),
      private_share_user_leaving_signal_(),
      parse_and_save_data_map_signal_(),
      private_share_details_signal_(),
      private_share_update_signal_(),
      save_private_share_data_signal_(),
      save_open_share_data_signal_() {}

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
      SendPresenceMessage((*it).first, (*item).public_id, presence);
    }
  }
}

int MessageHandler::StartCheckingForNewMessages(bptime::seconds interval) {
  std::vector<passport::SelectableIdData> selectables;
  session_->passport().SelectableIdentitiesList(&selectables);
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

int MessageHandler::Send(const InboxItem &inbox_item) {
  Message message;
  if (!InboxToProtobuf(inbox_item, &message)) {
    DLOG(ERROR) << "Invalid message. Won't send. Good day. I said: 'Good day!'";
    return -7;
  }
  Contact recipient_contact;
  int result(session_->contact_handler_map()
                 [inbox_item.sender_public_id]->ContactInfo(
                     inbox_item.receiver_public_id,
                     &recipient_contact));
  if (result != kSuccess || recipient_contact.inbox_name.empty()) {
    DLOG(ERROR) << "Failed to get MMID for " << inbox_item.receiver_public_id
                << ", type: " <<inbox_item.item_type;
    return result == kSuccess ? kGeneralError : result;
  }

  // Retrieves ANMPID, MPID, and MMID's <name, value, signature>
  passport::SelectableIdentityData data;
  result = session_->passport().GetSelectableIdentityData(
               inbox_item.sender_public_id,
               true,
               &data);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get own public ID data: " << result;
    return kGetPublicIdError;
  }
  BOOST_ASSERT(data.size() == 3U);

  // Get recipient's public key
  pcs::RemoteChunkStore::ValidationData validation_data_mmid;
  KeysAndProof(inbox_item.sender_public_id,
                  passport::kMmid,
                  true,
                  &validation_data_mmid);
  asymm::PublicKey recipient_public_key;
  result = GetValidatedMmidPublicKey(recipient_contact.inbox_name,
                                     validation_data_mmid,
                                     remote_chunk_store_,
                                     &recipient_public_key);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get public key for "
                << inbox_item.receiver_public_id;
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
  asymm::PrivateKey mmid_private_key(session_->passport().PacketPrivateKey(
                                         passport::kMmid,
                                         true,
                                         inbox_item.sender_public_id));

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

  std::string inbox_id(AppendableByAllType(recipient_contact.inbox_name));
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

int MessageHandler::SendPresenceMessage(
    const std::string &own_public_id,
    const std::string &recipient_public_id,
    const ContactPresence &presence) {
  InboxItem inbox_item(kContactPresence);
  inbox_item.sender_public_id  = own_public_id;
  inbox_item.receiver_public_id = recipient_public_id;

  if (presence == kOnline)
    inbox_item.content.push_back("kOnline");
  else
    inbox_item.content.push_back("kOffline");

  int result(Send(inbox_item));
  if (result != kSuccess) {
    DLOG(ERROR) << own_public_id << " failed to inform "
                << recipient_public_id << " of presence state "
                << presence << ", result: " << result;
    session_->contact_handler_map()
        [own_public_id]->UpdatePresence(recipient_public_id,
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

void MessageHandler::SendEveryone(const InboxItem &message) {
  std::vector<Contact> contacts;
  session_->contact_handler_map()
      [message.sender_public_id]->OrderedContacts(&contacts,
                                                  kAlphabetical,
                                                  kConfirmed);
  auto it_map(contacts.begin());
  while (it_map != contacts.end()) {
    InboxItem local_message(message);
    local_message.receiver_public_id = (*it_map++).public_id;
    asio_service_.post(std::bind(&MessageHandler::Send,
                                 this,
                                 local_message));
  }
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

//   get_new_messages_timer_.expires_at(get_new_messages_timer_.expires_at() +
//                                      interval);
  get_new_messages_timer_.expires_from_now(interval);
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
    asymm::PublicKey mmid_pub_key(session_->passport().SignaturePacketValue(
                                      passport::kMmid,
                                      true,
                                      std::get<0>(data)));
    std::string serialised_pub_key;
    asymm::EncodePublicKey(mmid_pub_key, &serialised_pub_key);
    asymm::PrivateKey mmid_private_key(session_->passport().PacketPrivateKey(
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
        case kChat: chat_signal_(inbox_item.receiver_public_id,
                                 inbox_item.sender_public_id,
                                 inbox_item.content.at(0),
                                 inbox_item.timestamp);
                    break;
        case kFileTransfer: ProcessFileTransfer(inbox_item);
                            break;
        case kContactProfilePicture: ProcessContactProfilePicture(inbox_item);
                                     break;
        case kContactPresence: ProcessContactPresence(inbox_item);
                               break;
        case kContactDeletion: ProcessContactDeletion(inbox_item);
                               break;
        case kPrivateShareInvitation:
        case kPrivateShareDeletion:
        case kPrivateShareMembershipUpgrade:
        case kPrivateShareMembershipDowngrade:
        case kPrivateShareKeysUpdate:
        case kPrivateShareMemberLeft: ProcessPrivateShare(inbox_item);
                                      break;
        case kOpenShareInvitation: ProcessOpenShareInvitation(inbox_item);
                                   break;
      }
    }
  }
}

void MessageHandler::ProcessFileTransfer(const InboxItem &inbox_item) {
  if (inbox_item.content.size() != 2U ||
      inbox_item.content[0].empty() ||
      inbox_item.content[1].empty()) {
    DLOG(ERROR) << "Wrong number of arguments for message.";
    file_transfer_signal_(inbox_item.receiver_public_id,
                          inbox_item.sender_public_id,
                          "",
                          "",
                          inbox_item.timestamp);
    return;
  }

  std::string data_map_hash;
  if (!parse_and_save_data_map_signal_(inbox_item.content[0],
                                       inbox_item.content[1],
                                       &data_map_hash)) {
    DLOG(ERROR) << "Failed to parse file DM";
    file_transfer_signal_(inbox_item.receiver_public_id,
                             inbox_item.sender_public_id,
                             inbox_item.content[0],
                             "",
                             inbox_item.timestamp);
    return;
  }

  file_transfer_signal_(inbox_item.receiver_public_id,
                           inbox_item.sender_public_id,
                           inbox_item.content[0],
                           data_map_hash,
                           inbox_item.timestamp);
}

void MessageHandler::ProcessContactPresence(const InboxItem &presence_message) {
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
      contact_presence_signal_(receiver,
                               sender,
                               presence_message.timestamp,
                               kOnline);
  } else if (presence_message.content[0] == "kOffline") {
    result =
        session_->contact_handler_map()[receiver]->UpdatePresence(sender,
                                                                  kOffline);
    if (result == kSuccess && start_up_done_)
      contact_presence_signal_(receiver,
                               sender,
                               presence_message.timestamp,
                               kOffline);

    // Send message so they know we're online when they come back
    asio_service_.post(std::bind(&MessageHandler::SendPresenceMessage,
                                 this, receiver, sender, kOnline));
  } else {
    DLOG(WARNING) << presence_message.sender_public_id
                  << " has sent a presence message with wrong content.";
  }
}

void MessageHandler::ProcessContactProfilePicture(
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

  contact_profile_picture_signal_(receiver,
                                  sender,
                                  profile_picture_message.timestamp);
}

bool CheckCorrectKeys(const std::vector<std::string> &message_keys,
                      const InboxItemType &item_type,
                      asymm::Keys *keys) {
  int offset(-1);
  if (item_type == kPrivateShareKeysUpdate) {
    if (message_keys.size() == 6U) {
      offset = 1;
    } else if (message_keys.size() == 7U) {
      offset = 2;
    } else if (message_keys.size() <= 3U) {
      return true;
    } else {
      DLOG(ERROR) << "Should have 6/7 elements: share ID, new share ID, "
                      "directory ID, and 4 Keys elements for KeysUpdate: "
                  <<  message_keys.size();
      return false;
    }
  } else if (item_type == kPrivateShareMembershipUpgrade) {
    if (message_keys.size() != 5U) {
      DLOG(ERROR) << "Should have 5 elements: share ID and 4 Keys elements "
                    "for MembershipUpgrade";
      return false;
    }
    offset = 0;
  }

  asymm::DecodePrivateKey(message_keys.at(offset + 3), &(keys->private_key));
  asymm::DecodePublicKey(message_keys.at(offset + 4), &(keys->public_key));
  if (!asymm::ValidateKey(keys->private_key) ||
      !asymm::ValidateKey(keys->public_key)) {
    DLOG(ERROR) << "Keys in message are invalid.";
    keys->private_key = asymm::PrivateKey();
    keys->public_key = asymm::PublicKey();
    return false;
  }

  keys->identity = message_keys.at(offset + 1);
  keys->validation_token = message_keys.at(offset + 2);

  return true;
}

void MessageHandler::ProcessPrivateShare(const InboxItem &inbox_item) {
  if (inbox_item.content.empty() || inbox_item.content[0].empty()) {
    DLOG(ERROR) << "No share ID.";
    return;
  }

  fs::path share_path;
  // The outer * is to refer to the result of the signal
  int result(*private_share_details_signal_(inbox_item.content[0],
                                            &share_path));
  if ((result != kSuccess || share_path.empty()) &&
      inbox_item.item_type != kPrivateShareInvitation) {
    DLOG(ERROR) << "result: " << result << ", path: " << share_path;
    return;
  }

  std::string share_name(share_path.filename().string());
  if (inbox_item.item_type == kPrivateShareDeletion) {
    private_share_deletion_signal_(inbox_item.sender_public_id,
                                   inbox_item.receiver_public_id,
                                   share_name,
                                   inbox_item.content[0],
                                   inbox_item.timestamp);
  } else if (inbox_item.item_type == kPrivateShareKeysUpdate) {
    asymm::Keys key_ring;
    if (!CheckCorrectKeys(inbox_item.content,
                          inbox_item.item_type,
                          &key_ring)) {
      DLOG(ERROR) << "Incorrect elements in message.";
      return;
    }

    std::string new_directory_id(inbox_item.content[1]),
                new_share_id(inbox_item.content[2]);
    private_share_update_signal_(inbox_item.content[0],
                                 &new_share_id,
                                 &new_directory_id,
                                 &key_ring);
  } else if (inbox_item.item_type == kPrivateShareMemberLeft) {
    private_share_user_leaving_signal_(share_name,
                                       inbox_item.content[0],
                                       inbox_item.sender_public_id);
  } else if (inbox_item.item_type == kPrivateShareMembershipDowngrade) {
    // downgrading
    private_member_access_level_signal_(inbox_item.receiver_public_id,
                                        inbox_item.sender_public_id,
                                        share_name,
                                        inbox_item.content[0],
                                        kShareReadOnly,
                                        inbox_item.timestamp);
  } else if (inbox_item.item_type == kPrivateShareMembershipUpgrade) {
    asymm::Keys key_ring;
    if (!CheckCorrectKeys(inbox_item.content,
                          inbox_item.item_type,
                          &key_ring)) {
      DLOG(ERROR) << "Incorrect elements in message.";
      return;
    }

    private_share_update_signal_(inbox_item.content[0],
                                 nullptr,
                                 nullptr,
                                 &key_ring);
    private_member_access_level_signal_(inbox_item.receiver_public_id,
                                        inbox_item.sender_public_id,
                                        share_name,
                                        inbox_item.content[0],
                                        kShareReadWrite,
                                        inbox_item.timestamp);
  } else if (inbox_item.item_type == kPrivateShareInvitation) {
    Message message;
    InboxToProtobuf(inbox_item, &message);
    if (!save_private_share_data_signal_(message.SerializeAsString(),
                                         inbox_item.content[0])) {
      DLOG(ERROR) << "Failed to save received share data";
      return;
    }
    fs::path relative_path(inbox_item.content[1]);
    private_share_invitation_signal_(inbox_item.receiver_public_id,
                                     inbox_item.sender_public_id,
                                     relative_path.filename().string(),
                                     inbox_item.content[0],
                                     inbox_item.content.size() == 7U ?
                                         kShareReadWrite : kShareReadOnly,
                                     inbox_item.timestamp);
  }
}

void MessageHandler::ProcessOpenShareInvitation(const InboxItem &inbox_item) {
  BOOST_ASSERT(inbox_item.item_type == kOpenShareInvitation);
  Message message;
  InboxToProtobuf(inbox_item, &message);
  if (!save_open_share_data_signal_(message.SerializeAsString(),
                                    inbox_item.content[0])) {
    DLOG(ERROR) << "Failed to save received share data";
    return;
  }
  open_share_invitation_signal_(inbox_item.receiver_public_id,
                                inbox_item.sender_public_id,
                                inbox_item.content[1],
                                inbox_item.content[0],
                                inbox_item.timestamp);
}

void MessageHandler::ProcessContactDeletion(const InboxItem &deletion_item) {
  DLOG(ERROR) << "MessageHandler::ContactDeletionSlot";
  std::string my_public_id(deletion_item.receiver_public_id),
              contact_public_id(deletion_item.sender_public_id);
  // PublicId - To run RemoveContact
  // UserStorage - To remove contact from all shares
  // UI - To do whatever it is they do out there, in that crazy world
  contact_deletion_signal_(my_public_id,
                           contact_public_id,
                           deletion_item.content.at(0),
                           deletion_item.timestamp);
}

void MessageHandler::RetrieveMessagesForAllIds() {
  int result(-1);
  std::vector<passport::SelectableIdData> selectables;
  session_->passport().SelectableIdentitiesList(&selectables);
  for (auto it(selectables.begin()); it != selectables.end(); ++it) {
    passport::SelectableIdentityData data;
    result = session_->passport().GetSelectableIdentityData(std::get<0>(*it),
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
  inbox_item->sender_public_id = message.sender_public_id();
  inbox_item->receiver_public_id = message.receiver_public_id();
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
  message->set_sender_public_id(inbox_item.sender_public_id);
  message->set_receiver_public_id(inbox_item.receiver_public_id);
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
      session_->passport().PacketName(pt, confirmed, public_id);
  validation_data->key_pair.public_key =
      session_->passport().SignaturePacketValue(pt, confirmed, public_id);
  validation_data->key_pair.private_key =
      session_->passport().PacketPrivateKey(pt, confirmed, public_id);
  validation_data->key_pair.validation_token =
      session_->passport().PacketSignature(pt, confirmed, public_id);
  pca::SignedData signed_data;
  signed_data.set_data(RandomString(64));
  asymm::Sign(signed_data.data(),
              validation_data->key_pair.private_key,
              &validation_data->ownership_proof);
  signed_data.set_signature(validation_data->ownership_proof);
  validation_data->ownership_proof = signed_data.SerializeAsString();
}


}  // namespace lifestuff

}  // namespace maidsafe
