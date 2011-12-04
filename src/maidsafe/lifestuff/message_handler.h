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
#include <memory>
#include <string>
#include <vector>

#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/signals2.hpp"

#include "maidsafe/passport/passport_config.h"

#include "maidsafe/lifestuff/version.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 110
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif

namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;

namespace maidsafe {

namespace lifestuff {

struct Message;
class PacketManager;
class Session;


class MessageHandler {
 public:
  typedef bs2::signal<void(const Message&)> NewMessageSignal;  // NOLINT (Fraser)
  typedef std::shared_ptr<NewMessageSignal> NewMessageSignalPtr;
  MessageHandler(std::shared_ptr<PacketManager> packet_manager,
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
           const Message &message);

  NewMessageSignalPtr new_message_signal() const;

 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
  void GetNewMessages(const bptime::seconds &interval,
                      const boost::system::error_code &error_code);
  void ProcessRetrieved(const passport::SelectableIdData &data,
                        const std::vector<std::string> &mmid_values);

  std::shared_ptr<PacketManager> packet_manager_;
  std::shared_ptr<Session> session_;
  ba::io_service &asio_service_;
  ba::deadline_timer get_new_messages_timer_;
  NewMessageSignalPtr new_message_signal_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_MESSAGE_HANDLER_H_
