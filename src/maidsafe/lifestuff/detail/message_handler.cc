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

#include "boost/thread/mutex.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/utils/utilities.h"

#include "maidsafe/encrypt/data_map.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace args = std::placeholders;
namespace pca = maidsafe::priv::chunk_actions;
namespace utils = maidsafe::priv::utilities;

namespace maidsafe {

namespace lifestuff {

namespace {

std::string AppendableByAllType(const std::string& mmid) {
  return mmid + std::string(1, pca::kAppendableByAll);
}

}  // namespace

MessageHandler::MessageHandler(std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
                               Session& session,
                               boost::asio::io_service& asio_service)
    : remote_chunk_store_(remote_chunk_store),
      session_(session),
      passport_(session_.passport()),
      get_new_messages_timer_(asio_service),
      get_new_messages_timer_active_(false),
      asio_service_(asio_service),
      start_up_done_(false),
      received_messages_(),
      chat_signal_(),
      file_transfer_signal_(),
      contact_presence_signal_(),
      contact_profile_picture_signal_(),
      parse_and_save_data_map_signal_() {}

MessageHandler::~MessageHandler() {}

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
  std::vector<std::string> public_ids(session_.PublicIdentities());
  std::vector<Contact> contacts;
  for (auto it(public_ids.begin()); it != public_ids.end(); ++it) {
    const ContactsHandlerPtr contacts_handler(session_.contacts_handler(*it));
    if (contacts_handler) {
      contacts_handler->OrderedContacts(&contacts, kAlphabetical, kConfirmed);
      for (auto item(contacts.begin()); item != contacts.end(); ++item)
        SendPresenceMessage(*it, (*item).public_id, presence);
    }
  }
}

int MessageHandler::StartCheckingForNewMessages(bptime::seconds interval) {
  if (session_.PublicIdentities().empty()) {
    LOG(kError) << "No public username set";
    return kStartMessagesNoPublicIds;
  }
  get_new_messages_timer_active_ = true;
  get_new_messages_timer_.expires_from_now(interval);
  get_new_messages_timer_.async_wait([=] (const boost::system::error_code& error_code) {
                                       GetNewMessages(interval, error_code);
                                     });
  return kSuccess;
}

void MessageHandler::StopCheckingForNewMessages() {
  if (get_new_messages_timer_active_) {
    get_new_messages_timer_active_ = false;
    get_new_messages_timer_.cancel();
  }
}

int MessageHandler::Send(const InboxItem& inbox_item) {
  Message message;
  if (!InboxToProtobuf(inbox_item, &message)) {
    LOG(kError) << "Invalid message. Won't send. Good day. I said: 'Good day!'";
    return kCannotConvertInboxItemToProtobuf;
  }

  const ContactsHandlerPtr contacts_handler(session_.contacts_handler(inbox_item.sender_public_id));
  if (!contacts_handler) {
    LOG(kError) << "User does not hold such public ID: " << inbox_item.sender_public_id;
    return kPublicIdNotFoundFailure;
  }

  Contact recipient_contact;
  int result(contacts_handler->ContactInfo(inbox_item.receiver_public_id, &recipient_contact));
  if (result != kSuccess ||
      recipient_contact.inbox_name.empty() ||
      !asymm::ValidateKey(recipient_contact.inbox_public_key)) {
    LOG(kError) << "Failed to get MMID for " << inbox_item.receiver_public_id << ", type: "
                << inbox_item.item_type << ", result: " << result
                << ", " << std::boolalpha << asymm::ValidateKey(recipient_contact.inbox_public_key);
    return result == kSuccess ? kContactInfoContentsFailure : result;
  }
  asymm::PublicKey recipient_public_key(recipient_contact.inbox_public_key);

  asymm::Keys mmid(passport_.SignaturePacketDetails(passport::kMmid,
                                                    true,
                                                    inbox_item.sender_public_id));
  // Encrypt the message for the recipient
  std::string encrypted_message;
  result = asymm::Encrypt(message.SerializeAsString(), recipient_public_key, &encrypted_message);
  if (result != kSuccess) {
    LOG(kError) << "Failed to encrypt message to recipient( " << inbox_item.receiver_public_id
                << "): " << result;
    return kGetPublicIdError;
  }

  pca::SignedData signed_data;
  signed_data.set_data(encrypted_message);

  std::string message_signature;
  result = asymm::Sign(signed_data.data(), mmid.private_key, &message_signature);
  if (result != kSuccess) {
    LOG(kError) << "Failed to sign message: " << result;
    return result;
  }

  signed_data.set_signature(message_signature);

  // Store encrypted MMID at recipient's MPID's name
  std::mutex mutex;
  std::condition_variable cond_var;
  result = priv::utilities::kPendingResult;

  std::string inbox_id(AppendableByAllType(recipient_contact.inbox_name));
  VoidFunctionOneBool callback([&] (const bool& response) {
                                 utils::ChunkStoreOperationCallback(response,
                                                                    &mutex,
                                                                    &cond_var,
                                                                    &result);
                               });
  if (!remote_chunk_store_->Modify(inbox_id, signed_data.SerializeAsString(), callback, mmid)) {
    LOG(kError) << "Immediate remote chunkstore failure.";
    return kRemoteChunkStoreFailure;
  }

  try {
    std::unique_lock<std::mutex> lock(mutex);
    if (!cond_var.wait_for(lock,
                           std::chrono::seconds(kSecondsInterval),
                           [&result] ()->bool {
                             return result != priv::utilities::kPendingResult;
                           })) {
      LOG(kError) << "Timed out storing packet.";
      return kPublicIdTimeout;
    }
  }
  catch(const std::exception& e) {
    LOG(kError) << "Failed to store packet: " << e.what();
    return kMessageHandlerException;
  }
  if (result != kSuccess) {
    LOG(kError) << "Failed to store packet.  Result: " << result;
    return result;
  }

  return kSuccess;
}

int MessageHandler::SendPresenceMessage(const std::string& own_public_id,
                                        const std::string& recipient_public_id,
                                        const ContactPresence& presence) {
  InboxItem inbox_item(kContactPresence);
  inbox_item.sender_public_id  = own_public_id;
  inbox_item.receiver_public_id = recipient_public_id;

  if (presence == kOnline)
    inbox_item.content.push_back("kOnline");
  else
    inbox_item.content.push_back("kOffline");

  int result(Send(inbox_item));
  if (result != kSuccess) {
    LOG(kError) << own_public_id << " failed to inform "
                << recipient_public_id << " of presence state "
                << presence << ", result: " << result;
    const ContactsHandlerPtr contacts_handler(session_.contacts_handler(own_public_id));
    if (!contacts_handler) {
      LOG(kError) << "User does not hold such public ID: " << own_public_id;
      return result;
    }

    contacts_handler->UpdatePresence(recipient_public_id, kOffline);
  }

  return result;
}

void MessageHandler::InformConfirmedContactOnline(const std::string& own_public_id,
                                                  const std::string& recipient_public_id) {
  asio_service_.post([=] {
                       return SendPresenceMessage(own_public_id, recipient_public_id, kOnline);
                     });
}

void MessageHandler::SendEveryone(const InboxItem& message) {
  std::vector<Contact> contacts;
  const ContactsHandlerPtr contacts_handler(session_.contacts_handler(message.sender_public_id));
  if (!contacts_handler) {
    LOG(kError) << "User does not hold such public ID: " << message.sender_public_id;
    return;
  }
  contacts_handler->OrderedContacts(&contacts, kAlphabetical, kConfirmed);
  auto it_map(contacts.begin());
  while (it_map != contacts.end()) {
    InboxItem local_message(message);
    local_message.receiver_public_id = (*it_map++).public_id;
    asio_service_.post([=] { return Send(local_message); });  // NOLINT (Alison)
  }
}

void MessageHandler::GetNewMessages(const bptime::seconds& interval,
                                    const boost::system::error_code& error_code) {
  if (error_code) {
    if (error_code != ba::error::operation_aborted) {
      LOG(kWarning) << "Refresh timer error: " << error_code.message();
    } else {
      LOG(kInfo) << "Timer cancel triggered: " << error_code.message();
      return;
    }
  }

  if (!get_new_messages_timer_active_) {
    LOG(kInfo) << "Timer process cancelled.";
    return;
  }

  ClearExpiredReceivedMessages();
  RetrieveMessagesForAllIds();

  get_new_messages_timer_.expires_from_now(interval);
  get_new_messages_timer_.async_wait([=] (const boost::system::error_code& error_code) {
                                       GetNewMessages(interval, error_code);
                                     });
}

void MessageHandler::ProcessRetrieved(const std::string& public_id,
                                      const std::string& retrieved_mmid_packet) {
  pca::AppendableByAll mmid_packet;
  if (!mmid_packet.ParseFromString(retrieved_mmid_packet)) {
    LOG(kError) << "Failed to parse as AppendableByAll";
    return;
  }

  for (int it(0); it < mmid_packet.appendices_size(); ++it) {
    pca::SignedData signed_data(mmid_packet.appendices(it));
    asymm::Keys mmid(passport_.SignaturePacketDetails(passport::kMmid, true, public_id));

    std::string decrypted_message;
    int n(asymm::Decrypt(signed_data.data(), mmid.private_key, &decrypted_message));
    if (n != kSuccess) {
      LOG(kError) << "Failed to decrypt message: " << n;
      continue;
    }

    Message mmid_message;
    if (!mmid_message.ParseFromString(decrypted_message)) {
      LOG(kError) << "Failed to parse decrypted message";
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
      }
    }
  }
}

void MessageHandler::ProcessFileTransfer(const InboxItem& inbox_item) {
  if (inbox_item.content.size() != 2U ||
      inbox_item.content[0].empty() ||
      inbox_item.content[1].empty()) {
    LOG(kError) << "Wrong number of arguments for message.";
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
    LOG(kError) << "Failed to parse file DM";
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

void MessageHandler::ProcessContactPresence(const InboxItem& presence_message) {
  if (presence_message.content.size() != 1U) {
    // Drop silently
    LOG(kWarning) << presence_message.sender_public_id
                  << " has sent a presence message with bad content: "
                  << presence_message.content.size();
    return;
  }

  std::string sender(presence_message.sender_public_id),
              receiver(presence_message.receiver_public_id);
  const ContactsHandlerPtr contacts_handler(session_.contacts_handler(receiver));
  if (!contacts_handler) {
    LOG(kError) << "User does not hold such public ID: " << receiver;
    return;
  }

  int result(0);
  if (presence_message.content[0] == "kOnline") {
    result = contacts_handler->UpdatePresence(sender, kOnline);
    if (result == kSuccess && start_up_done_)
      contact_presence_signal_(receiver, sender, presence_message.timestamp, kOnline);
  } else if (presence_message.content[0] == "kOffline") {
    result = contacts_handler->UpdatePresence(sender, kOffline);
    if (result == kSuccess && start_up_done_)
      contact_presence_signal_(receiver, sender, presence_message.timestamp, kOffline);

    // Send message so they know we're online when they come back
    asio_service_.post([=] {
                         return SendPresenceMessage(receiver, sender, kOnline);
                       });
  } else {
    LOG(kWarning) << presence_message.sender_public_id
                  << " has sent a presence message with wrong content.";
  }
}

void MessageHandler::ProcessContactProfilePicture(const InboxItem& profile_picture_message) {
  if (profile_picture_message.content.size() != 1U || profile_picture_message.content[0].empty()) {
    // Drop silently
    LOG(kError) << profile_picture_message.sender_public_id
                  << " has sent a profile picture message with bad content.";
    return;
  }

  std::string sender(profile_picture_message.sender_public_id),
              receiver(profile_picture_message.receiver_public_id);
  if (profile_picture_message.content[0] != kBlankProfilePicture) {
    encrypt::DataMapPtr data_map(ParseSerialisedDataMap(profile_picture_message.content[0]));
    if (!data_map) {
      LOG(kError) << "Data map didn't parse.";
      return;
    }
  }

  const ContactsHandlerPtr contacts_handler(session_.contacts_handler(receiver));
  if (!contacts_handler) {
    LOG(kError) << "User does not hold public ID: " << receiver;
    return;
  }

  int result(contacts_handler->UpdateProfilePictureDataMap(sender,
                                                           profile_picture_message.content[0]));
  if (result != kSuccess) {
    LOG(kError) << "Failed to update picture DM in session: " << result;
    return;
  }
  session_.set_changed(true);

  contact_profile_picture_signal_(receiver, sender, profile_picture_message.timestamp);
}

void MessageHandler::RetrieveMessagesForAllIds() {
  int result(-1);
  std::vector<std::string> selectables(session_.PublicIdentities());
  for (auto it(selectables.begin()); it != selectables.end(); ++it) {
//    LOG(kError) << "RetrieveMessagesForAllIds for " << (*it);
    asymm::Keys mmid(passport_.SignaturePacketDetails(passport::kMmid, true, *it));
    std::string mmid_value(remote_chunk_store_->Get(AppendableByAllType(mmid.identity), mmid));

    if (mmid_value.empty()) {
      LOG(kWarning) << "Failed to get MPID contents for " << (*it) << ": " << result;
    } else {
      ProcessRetrieved(*it, mmid_value);
      ClearExpiredReceivedMessages();
    }
  }
}

bool MessageHandler::ProtobufToInbox(const Message& message, InboxItem* inbox_item) const {
  if (!message.IsInitialized()) {
    LOG(kWarning) << "Message not initialised.";
    return false;
  }

  if (message.content_size() == 0) {
    LOG(kWarning) << "Message with no content. Type: " << message.type();
    return false;
  }

  if (message.type() > kMaxInboxItemType) {
    LOG(kWarning) << "Message type out of range.";
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

bool MessageHandler::InboxToProtobuf(const InboxItem& inbox_item, Message* message) const {
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

bool MessageHandler::MessagePreviouslyReceived(const std::string& message) {
  if (received_messages_.find(message) == received_messages_.end()) {
    received_messages_.insert(std::make_pair(message,
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

}  // namespace lifestuff

}  // namespace maidsafe
