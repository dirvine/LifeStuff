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

#ifndef MAIDSAFE_LIFESTUFF_MESSAGE_HANDLER_H_
#define MAIDSAFE_LIFESTUFF_MESSAGE_HANDLER_H_


#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "boost/config.hpp"
#include "boost/signals2.hpp"

#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#include "maidsafe/passport/passport_config.h"

#include "maidsafe/lifestuff/data_atlas_pb.h"
#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/version.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 400
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif

namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace pcs = maidsafe::priv::chunk_store;

namespace maidsafe {

namespace lifestuff {

class Message;
class Session;
class YeOldeSignalToCallbackConverter;

class MessageHandler {
 public:
  typedef bs2::signal<void(const Message&)> NewMessageSignal;  // NOLINT (Dan)
  typedef NewMessageSignal::slot_type MessageFunction;
  typedef std::shared_ptr<NewMessageSignal> NewMessageSignalPtr;

  typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                           const std::string&,
                           ContactPresence presence)> ContactPresenceSignal;
  typedef ContactPresenceSignal::slot_type ContactPresenceFunction;
  typedef std::shared_ptr<ContactPresenceSignal> ContactPresenceSignalPtr;

  typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                           const std::string&)> ContactProfilePictureSignal;
  typedef ContactProfilePictureSignal::slot_type ContactProfilePictureFunction;
  typedef std::shared_ptr<ContactProfilePictureSignal>
          ContactProfilePictureSignalPtr;

  typedef std::map<std::string, uint64_t> ReceivedMessagesMap;

  MessageHandler(std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
                 std::shared_ptr<YeOldeSignalToCallbackConverter> converter,
                 std::shared_ptr<Session> session,
                 ba::io_service &asio_service);  // NOLINT (Fraser)
  ~MessageHandler();

  void StartUp(bptime::seconds interval);
  void ShutDown();

  // Periodically retrieves saved messages from MMID and fires
  // new_message_signal_ for each valid message retrieved.  Checking will only
  // succeed if at least one public username has been successfully created.
  int StartCheckingForNewMessages(boost::posix_time::seconds interval);
  void StopCheckingForNewMessages();

  int Send(const std::string &own_public_username,
           const std::string &recipient_public_username,
           const Message &message);

  bs2::connection ConnectToSignal(const Message::ContentType type,
                                  const MessageFunction &function);
  bs2::connection ConnectToContactPresenceSignal(
      const ContactPresenceFunction &function);
  bs2::connection ConnectToContactProfilePictureSignal(
      const ContactProfilePictureFunction &function);

 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);

  bool ValidateMessage(const Message &message) const;
  void GetNewMessages(const bptime::seconds &interval,
                      const boost::system::error_code &error_code);
  void ProcessRetrieved(const passport::SelectableIdData &data,
                        const std::string &mmid_value);
  bool MessagePreviouslyReceived(const std::string &message);
  void ClearExpiredReceivedMessages();
  void KeysAndProof(const std::string &public_username,
                    passport::PacketType pt,
                    bool confirmed,
                    pcs::RemoteChunkStore::ValidationData *validation_data);
  void ContactInformationSlot(const Message& information_message);
  void RetrieveMessagesForAllIds();
  void SendPresenceMessage(const std::string &own_public_username,
                           const std::string &recipient_public_username,
                           const ContactPresence &presence);
  void EnqueuePresenceMessages(ContactPresence presence);

  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store_;
  std::shared_ptr<YeOldeSignalToCallbackConverter> converter_;
  std::shared_ptr<Session> session_;
  ba::deadline_timer get_new_messages_timer_;
  std::vector<NewMessageSignalPtr> new_message_signals_;
  ContactPresenceSignalPtr contact_presence_signal_;
  ContactProfilePictureSignalPtr contact_profile_picture_signal_;
  ReceivedMessagesMap received_messages_;
  ba::io_service &asio_service_;  // NOLINT(Dan)
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_MESSAGE_HANDLER_H_
