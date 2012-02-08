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

#include "maidsafe/common/alternative_store.h"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"

#include "maidsafe/passport/passport_config.h"

#include "maidsafe/lifestuff/version.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 200
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif

namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace pd { class RemoteChunkStore; }

namespace lifestuff {

class Session;
class YeOldeSignalToCallbackConverter;

class MessageHandler {
 public:
  typedef bs2::signal<void(const priv::chunk_actions::Message&)> NewMessageSignal;  // NOLINT (Dan)
  typedef NewMessageSignal::slot_type MessageFunction;
  typedef std::shared_ptr<NewMessageSignal> NewMessageSignalPtr;
  typedef std::map<std::string, uint64_t> ReceivedMessagesMap;

  MessageHandler(std::shared_ptr<pd::RemoteChunkStore> remote_chunk_store,
                 std::shared_ptr<YeOldeSignalToCallbackConverter> converter,
                 std::shared_ptr<Session> session,
                 ba::io_service &asio_service);  // NOLINT (Fraser)
  ~MessageHandler();

  // Periodically retrieves saved messages from MMID and fires
  // new_message_signal_ for each valid message retrieved.  Checking will only
  // succeed if at least one public username has been successfully created.
  int StartCheckingForNewMessages(boost::posix_time::seconds interval);
  void StopCheckingForNewMessages();

  int Send(const std::string &public_username,
           const std::string &recipient_public_username,
           const priv::chunk_actions::Message &message);

  bs2::connection ConnectToSignal(const pca::Message::ContentType type,
                                  const MessageFunction &function);

 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);

  bool ValidateMessage(const priv::chunk_actions::Message &message) const;
  void GetNewMessages(const bptime::seconds &interval,
                      const boost::system::error_code &error_code);
  void ProcessRetrieved(const passport::SelectableIdData &data,
                        const std::string &mmid_value);
  bool MessagePreviouslyReceived(const std::string &message);
  void ClearExpiredReceivedMessages();
  void GetKeysAndProof(const std::string &public_username,
                       passport::PacketType pt,
                       bool confirmed,
                       AlternativeStore::ValidationData *validation_data);

  std::shared_ptr<pd::RemoteChunkStore> remote_chunk_store_;
  std::shared_ptr<YeOldeSignalToCallbackConverter> converter_;
  std::shared_ptr<Session> session_;
  ba::io_service &asio_service_;
  ba::deadline_timer get_new_messages_timer_;
  std::vector<NewMessageSignalPtr> new_message_signals_;
  ReceivedMessagesMap received_messages_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_MESSAGE_HANDLER_H_
