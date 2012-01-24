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

#include "maidsafe/passport/passport.h"

#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

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

void SendMessageCallback(const int &response,
                         boost::mutex *mutex,
                         boost::condition_variable *cond_var,
                         int *result) {
  if (!mutex || !cond_var || !result)
    return;
  boost::mutex::scoped_lock lock(*mutex);
  *result = response;
  cond_var->notify_one();
}

std::string AppendableByAllType(const std::string &mmid) {
  return mmid + std::string(1, pca::kAppendableByAll);
}

}  // namespace

MessageHandler::MessageHandler(std::shared_ptr<PacketManager> packet_manager,
                               std::shared_ptr<Session> session,
                               boost::asio::io_service &asio_service)  // NOLINT (Fraser)
    : packet_manager_(packet_manager),
      session_(session),
      asio_service_(asio_service),
      get_new_messages_timer_(asio_service),
      new_message_signals_(),
      received_messages_() {
  for (int n(pca::Message::ContentType_MIN);
       n != pca::Message::ContentType_MAX;
       ++n) {
  	new_message_signals_.push_back(std::make_shared<NewMessageSignal>());
  }
}

MessageHandler::~MessageHandler() {
  StopCheckingForNewMessages();
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
  get_new_messages_timer_.cancel();
}

int MessageHandler::Send(const std::string &public_username,
                         const std::string &recipient_public_username,
                         const pca::Message &message) {
  if (!ValidateMessage(message)) {
    DLOG(ERROR) << "Invalid message. Won't send. Good day. I said: 'Good day!'";
    return -7;
  }
  Contact recipient_contact;
  int result(session_->contact_handler_map()[public_username]->ContactInfo(
                 recipient_public_username,
                 &recipient_contact));
  if (result != kSuccess || recipient_contact.mmid_name.empty()) {
    DLOG(ERROR) << "Failed to get MMID for " << recipient_public_username;
    return result;
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
  asymm::PublicKey recipient_public_key;
  result = GetValidatedMmidPublicKey(recipient_contact.mmid_name,
                                     std::get<0>(data.at(2)),
                                     packet_manager_,
                                     &recipient_public_key);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get public key for " << recipient_public_username;
    return result;
  }

  // Encrypt the message for the recipient
  std::string encrypted_message/*, encrpyted_symm_key*/;
  result = asymm::Encrypt(message.SerializeAsString(),
                          recipient_public_key,
                          &encrypted_message);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get own public ID data: " << result;
    return kGetPublicIdError;
  }

//  pca::Encrypted combined_encrypted_message;
//  combined_encrypted_message.set_asymm_encrypted_symm_key(encrpyted_symm_key);
//  combined_encrypted_message.set_symm_encrypted_data(encrypted_message);

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
  VoidFuncOneInt callback(std::bind(&SendMessageCallback, args::_1, &mutex,
                                    &cond_var, &result));

  packet_manager_->ModifyPacket(
      AppendableByAllType(recipient_contact.mmid_name),
      signed_data.SerializeAsString(),
      std::get<0>(data.at(2)),
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
    return kMessageHandlerException;
  }
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to store packet.  Result: " << result;
    return result;
  }

  return kSuccess;
}

bs2::connection MessageHandler::ConnectToSignal(
    const pca::Message::ContentType type,
    const MessageFunction &function) {
  if (type < pca::Message::ContentType_MIN ||
      type > pca::Message::ContentType_MAX) {
    DLOG(ERROR) << "No such content type, and therefore, no signal. Good day!";
    return bs2::connection();
  }

  return new_message_signals_.at(static_cast<size_t>(type))->connect(function);
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

    std::vector<std::string> mmid_values;
    result = packet_manager_->GetPacket(AppendableByAllType(std::get<1>(*it)),
                                        std::get<0>(data.at(2)),
                                        &mmid_values);

    if (result == kSuccess) {
      ProcessRetrieved(*it, mmid_values);
      ClearExpiredReceivedMessages();
    } else if (result != kGetPacketEmptyData) {
      DLOG(WARNING) << "Failed to get MPID contents for " << std::get<0>(*it)
                  << ": " << result;
    }
  }

  get_new_messages_timer_.expires_at(get_new_messages_timer_.expires_at() +
                                     interval);
  get_new_messages_timer_.async_wait(std::bind(&MessageHandler::GetNewMessages,
                                               this,
                                               interval,
                                               std::placeholders::_1));
}

void MessageHandler::ProcessRetrieved(
    const passport::SelectableIdData &data,
    const std::vector<std::string> &mmid_values) {
  BOOST_ASSERT(mmid_values.size() == 1U);
  pca::AppendableByAll mmid;
  if (!mmid.ParseFromString(mmid_values.at(0))) {
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

    pca::Message mmid_message;
    if (!mmid_message.ParseFromString(decrypted_message)) {
      DLOG(ERROR) << "Failed to parse decrypted message";
      continue;
    }

    if (ValidateMessage(mmid_message) &&
        !MessagePreviouslyReceived(decrypted_message)) {
      (*new_message_signals_.at(mmid_message.type()))(mmid_message);
    }
  }
}

bool MessageHandler::ValidateMessage(const pca::Message &message) const {
  if (!message.IsInitialized())
    return false;

  if (message.type() < pca::Message::ContentType_MIN ||
      message.type() > pca::Message::ContentType_MAX)
    return false;

  for (auto it(0); it < message.content_size(); ++it)
    if (!message.content(it).empty())
      return true;

  return false;
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

}  // namespace lifestuff

}  // namespace maidsafe
