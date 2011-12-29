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

#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/maidsafe.h"
#include "maidsafe/lifestuff/message.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/utils.h"
#include "maidsafe/lifestuff/store_components/packet_manager.h"

namespace args = std::placeholders;


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

}  // namespace

//MessageHandler::MessageHandler(std::shared_ptr<PacketManager> packet_manager,
//                               std::shared_ptr<Session> session,
//                               boost::asio::io_service &asio_service)  // NOLINT (Fraser)
//    : packet_manager_(packet_manager),
//      session_(session),
//      asio_service_(asio_service),
//      get_new_messages_timer_(asio_service),
//      new_message_signal_(new NewMessageSignal) {}
//
//MessageHandler::~MessageHandler() {
//  StopCheckingForNewMessages();
//}
//
//int MessageHandler::StartCheckingForNewMessages(bptime::seconds interval) {
//  std::vector<passport::SelectableIdData> selectables;
//  session_->passport_->SelectableIdentitiesList(&selectables);
//  if (selectables.empty()) {
//    DLOG(ERROR) << "No public username set";
//    return kNoPublicIds;
//  }
//  get_new_messages_timer_.expires_from_now(interval);
//  get_new_messages_timer_.async_wait(std::bind(&MessageHandler::GetNewMessages,
//                                               this,
//                                               interval,
//                                               std::placeholders::_1));
//  return kSuccess;
//}
//
//void MessageHandler::StopCheckingForNewMessages() {
//  get_new_messages_timer_.cancel();
//}
//
//int MessageHandler::Send(const std::string &public_username,
//                         const std::string &recipient_public_username,
//                         const Message &message) {
//  if (!ValidateMessage(message)) {
//    DLOG(ERROR) << "Invalid message. Won't send. Good day. I said good day!";
//    return -7;
//  }
//  mi_contact recipient_contact;
//  int result(session_->contacts_handler()->GetContactInfo(
//                 recipient_public_username,
//                 &recipient_contact));
//  if (result != kSuccess || recipient_contact.pub_key_.empty()) {
//    DLOG(ERROR) << "Failed to get MMID for " << recipient_public_username;
//    return result;
//  }
//
//  // Get recipient's public key
//  asymm::PublicKey recipient_public_key;
//  result = GetValidatedMmidPublicKey(recipient_contact.pub_key_,
//                                     packet_manager_,
//                                     &recipient_public_key);
//  if (result != kSuccess) {
//    DLOG(ERROR) << "Failed to get public key for " << recipient_public_username;
//    return result;
//  }
//
//
//  MMID::Message mmid_message;
//  // TODO(Fraser#5#): 2011-12-03 - Implement way to generate an ID unique
//  //                  betweeen sender and recipient
//  mmid_message.set_type(message.message_type);
//  mmid_message.set_id(message.message_id);
//  mmid_message.set_parent_id(message.parent_id);
//  mmid_message.set_sender_public_username(message.sender_public_username);
//  mmid_message.set_subject(message.subject);
//  for (size_t i(0); i != message.content.size(); ++i)
//    mmid_message.add_content(message.content.at(i));
//
//  // Get PrivateKey for this user
//  std::vector<passport::SelectableIdData> selectables;
//  session_->passport_->SelectableIdentitiesList(&selectables);
//  passport::SelectableIdData selectable_id;
//  auto it(std::find_if(selectables.begin(),
//                       selectables.end(),
//                       [public_username]
//                           (const passport::SelectableIdData &selectable) {
//                         return (std::get<0>(selectable) == public_username);
//                       }));
//
//  if (it == selectables.end()) {
//    DLOG(ERROR) << "Failed to get own MPID private key";
//    return kGetPublicIdError;
//  }
//
//  // Encrypt the message for the recipient
//  std::string encrypted_message, encrpyted_symm_key;
//  result = crypto::CombinedEncrypt(mmid_message.SerializeAsString(),
//                                   recipient_public_key,
//                                   &encrypted_message,
//                                   &encrpyted_symm_key);
//  if (result != kSuccess) {
//    DLOG(ERROR) << "Failed to get own public ID data: " << result;
//    return kGetPublicIdError;
//  } else {
//    DLOG(ERROR) << "\t\t\t\t\t\t The MMID message is "
//                << Base32Substr(mmid_message.SerializeAsString());
//  }
//
//  Encrypted combined_encrypted_message;
//  combined_encrypted_message.set_asymm_encrypted_symm_key(encrpyted_symm_key);
//  combined_encrypted_message.set_symm_encrypted_data(encrypted_message);
//
//  GenericPacket gp;
//  gp.set_data(combined_encrypted_message.SerializeAsString());
//  gp.set_type(kMmid);
//
//  std::string message_signature;
//  result = asymm::Sign(gp.data(), std::get<2>(*it), &message_signature);
//  if (result != kSuccess) {
//    DLOG(ERROR) << "Failed to sign message: " << result;
//    return result;
//  }
//
//  gp.set_signature(message_signature);
//
//  // Store encrypted MMID at recipient's MPID's name
//  boost::mutex mutex;
//  boost::condition_variable cond_var;
//  result = kPendingResult;
//  VoidFuncOneInt callback(std::bind(&SendMessageCallback, args::_1, &mutex,
//                                    &cond_var, &result));
//
//  packet_manager_->StorePacket(recipient_contact.pub_key_,
//                               gp.SerializeAsString(),
//                               callback);
//
//  try {
//    boost::mutex::scoped_lock lock(mutex);
//    if (!cond_var.timed_wait(lock,
//                             bptime::seconds(30),
//                             [&result]()->bool {
//                               return result != kPendingResult;
//                             })) {
//      DLOG(ERROR) << "Timed out storing packet.";
//      return kPublicIdTimeout;
//    }
//  }
//  catch(const std::exception &e) {
//    DLOG(ERROR) << "Failed to store packet: " << e.what();
//    return kMessageHandlerException;
//  }
//  if (result != kSuccess) {
//    DLOG(ERROR) << "Failed to store packet.  Result: " << result;
//    return result;
//  }
//
//  return kSuccess;
//}
//
//MessageHandler::NewMessageSignalPtr MessageHandler::new_message_signal() const {
//  return new_message_signal_;
//}
//
//void MessageHandler::GetNewMessages(
//    const bptime::seconds &interval,
//    const boost::system::error_code &error_code) {
//  if (error_code) {
//    if (error_code != ba::error::operation_aborted) {
//      DLOG(ERROR) << "Refresh timer error: " << error_code.message();
//    } else {
//      return;
//    }
//  }
//
//  std::vector<passport::SelectableIdData> selectables;
//  session_->passport_->SelectableIdentitiesList(&selectables);
//  for (auto it(selectables.begin()); it != selectables.end(); ++it) {
//    std::vector<std::string> mmid_values;
//    int result(packet_manager_->GetPacket(std::get<1>(*it),
//                                          &mmid_values,
//                                          std::get<0>(*it),
//                                          kMmid));
//    if (result == kSuccess) {
//      ProcessRetrieved(*it, mmid_values);
//    } else if (result != kGetPacketEmptyData) {
//      DLOG(ERROR) << "Failed to get MPID contents for " << std::get<0>(*it)
//                  << ": " << result;
//    }
//  }
//
//  get_new_messages_timer_.expires_at(get_new_messages_timer_.expires_at() +
//                                     interval);
//  get_new_messages_timer_.async_wait(std::bind(&MessageHandler::GetNewMessages,
//                                               this,
//                                               interval,
//                                               std::placeholders::_1));
//}
//
//void MessageHandler::ProcessRetrieved(
//    const passport::SelectableIdData &data,
//    const std::vector<std::string> &mmid_values) {
//  for (auto it(mmid_values.begin()); it != mmid_values.end(); ++it) {
//    asymm::PublicKey mmid_pub_key(session_->passport_->SignaturePacketValue(
//                                      passport::kMmid,
//                                      true,
//                                      std::get<0>(data)));
//    std::string serialised_pub_key;
//    asymm::EncodePublicKey(mmid_pub_key, &serialised_pub_key);
//    DLOG(ERROR) << "\t\t\t\t The MMID public key is "
//                << Base32Substr(serialised_pub_key);
//
//    asymm::PrivateKey mmid_private_key(session_->passport_->PacketPrivateKey(
//                                           passport::kMmid,
//                                           true,
//                                           std::get<0>(data)));
//    Encrypted encrypted;
//    if (!encrypted.ParseFromString(*it)) {
//      DLOG(ERROR) << "Failed to parse encrypted message";
//      continue;
//    }
//
//    std::string decrypted_message;
//    int n(crypto::CombinedDecrypt(encrypted.symm_encrypted_data(),
//                                  encrypted.asymm_encrypted_symm_key(),
//                                  mmid_private_key,
//                                  &decrypted_message));
//    if (n != kSuccess) {
//      DLOG(ERROR) << "Failed to decrypt message: " << n;
//      continue;
//    } else {
//      DLOG(ERROR) << "\t\t\t\t\t\t The MMID message is "
//                  << Base32Substr(decrypted_message);
//    }
//
//    MMID::Message mmid_message;
//    if (!mmid_message.ParseFromString(decrypted_message)) {
//      DLOG(ERROR) << "Failed to parse decrypted message";
//      continue;
//    }
//
//    std::vector<std::string> mmid_content;
//    for (int i(0); i != mmid_message.content_size(); ++i)
//      mmid_content.push_back(mmid_message.content(i));
//
//    Message msg(static_cast<MessageType>(mmid_message.type()),
//                mmid_message.id(),
//                mmid_message.has_parent_id() ? mmid_message.parent_id() : "",
//                mmid_message.sender_public_username(),
//                mmid_message.has_subject() ? mmid_message.subject() : "",
//                mmid_content);
//    (*new_message_signal_)(msg);
//  }
//}
//
//bool MessageHandler::ValidateMessage(const Message &message) const {
//  if (message.message_id.empty() ||
//      message.sender_public_username.empty() ||
//      message.content.empty() ||
//      (message.message_type != kNormal &&
//       message.message_type != kFileTransfer &&
//       message.message_type != kSharedDirectory)) {
//    return false;
//  }
//
//  for (auto it(message.content.begin()); it != message.content.end(); ++it)
//    if (!(*it).empty())
//      return true;
//
//  return false;
//}


}  // namespace lifestuff

}  // namespace maidsafe
