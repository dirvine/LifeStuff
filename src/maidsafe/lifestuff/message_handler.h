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
#include "maidsafe/lifestuff/utils.h"

namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace pcs = maidsafe::priv::chunk_store;

namespace maidsafe {

namespace lifestuff {

class Message;
class Session;

class MessageHandler {
 public:
  typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                           const std::string&,
                           const std::string&,
                           const std::string&)> ShareInvitationSignal;
  typedef std::shared_ptr<ShareInvitationSignal> ShareInvitationSignalPtr;

  typedef bs2::signal<void(const std::string&,  // NOLINT
                           const std::string&,
                           const std::string&,
                           const std::string&)> OpenShareInvitationSignal;
  typedef std::shared_ptr<OpenShareInvitationSignal> OpenShareInvitationSignalPtr;

  typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                           const std::string&)> ShareDeletionSignal;
  typedef std::shared_ptr<ShareDeletionSignal> ShareDeletionSignalPtr;

  typedef bs2::signal<void(const std::string&,  // share id
                           const std::string*,  // directory id
                           const std::string*,  // new share id
                           const asymm::Keys*)> ShareUpdateSignal;  // new key
  typedef std::shared_ptr<ShareUpdateSignal> ShareUpdateSignalPtr;

  typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                           const std::string&,
                           const std::string&,
                           int)> MemberAccessLevelSignal;
  typedef std::shared_ptr<MemberAccessLevelSignal> MemberAccessLevelSignalPtr;

  typedef bs2::signal<bool(const std::string&,  // NOLINT (Dan)
                           const std::string&)> SaveShareDataSignal;
  typedef std::shared_ptr<SaveShareDataSignal> SaveShareDataSignalPtr;

  typedef bs2::signal<bool(const std::string&,  // NOLINT
                           const std::string&)> SaveOpenShareDataSignal;
  typedef std::shared_ptr<SaveOpenShareDataSignal> SaveOpenShareDataSignalPtr;

  typedef bs2::signal<void(const InboxItem&)> NewItemSignal;  // NOLINT (Dan)
  typedef std::shared_ptr<NewItemSignal> NewItemSignalPtr;

  typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                           const std::string&,
                           ContactPresence presence)> ContactPresenceSignal;
  typedef std::shared_ptr<ContactPresenceSignal> ContactPresenceSignalPtr;

  typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                           const std::string&,
                           const std::string&)> ChatMessageSignal;
  typedef std::shared_ptr<ChatMessageSignal> ChatMessageSignalPtr;

  typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                           const std::string&,
                           const std::string&)> ContactDeletionSignal;
  typedef std::shared_ptr<ContactDeletionSignal> ContactDeletionSignalPtr;

  typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                           const std::string&,
                           const std::string&,
                           const std::string&)> FileTransferSignal;
  typedef std::shared_ptr<FileTransferSignal> FileTransferSignalPtr;

  typedef bs2::signal<void(const std::string&,  // NOLINT (Dan)
                           const std::string&)> ContactProfilePictureSignal;
  typedef std::shared_ptr<ContactProfilePictureSignal>
          ContactProfilePictureSignalPtr;

  typedef bs2::signal<bool(const std::string&,  // NOLINT (Dan)
                           std::string*)> ParseAndSaveDataMapSignal;
  typedef std::shared_ptr<ParseAndSaveDataMapSignal>
          ParseAndSaveDataMapSignalPtr;

  typedef std::map<std::string, uint64_t> ReceivedMessagesMap;

  MessageHandler(std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
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
           const InboxItem &message);
  int SendPresenceMessage(const std::string &own_public_username,
                          const std::string &recipient_public_username,
                          const ContactPresence &presence);
  void InformConfirmedContactOnline(const std::string &own_public_id,
                                    const std::string &recipient_public_id);
  void SendEveryone(const InboxItem &message);

  bs2::connection ConnectToChatSignal(const ChatFunction &function);
  bs2::connection ConnectToFileTransferSignal(
      const FileTransferFunction &function);
  bs2::connection ConnectToShareInvitationSignal(
      const ShareInvitationFunction &function);
  bs2::connection ConnectToOpenShareInvitationSignal(
      const OpenShareInvitationFunction &function);
  bs2::connection ConnectToShareDeletionSignal(
      const ShareDeletionFunction &function);
  bs2::connection ConnectToShareUpdateSignal(
      const ShareUpdateSignal::slot_type &function);
  bs2::connection ConnectToMemberAccessLevelSignal(
      const MemberAccessLevelFunction &function);
  bs2::connection ConnectToSaveShareDataSignal(
      const SaveShareDataSignal::slot_type &function);
  bs2::connection ConnectToSaveOpenShareDataSignal(
      const SaveOpenShareDataSignal::slot_type &function);
  bs2::connection ConnectToContactPresenceSignal(
      const ContactPresenceFunction &function);
  bs2::connection ConnectToContactProfilePictureSignal(
      const ContactProfilePictureFunction &function);
  bs2::connection ConnectToParseAndSaveDataMapSignal(
      const ParseAndSaveDataMapSignal::slot_type &function);
  bs2::connection ConnectToContactDeletionSignal(
      const ContactDeletionFunction &function);

 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);

  bool ProtobufToInbox(const Message &message, InboxItem *inbox_item) const;
  bool InboxToProtobuf(const InboxItem &inbox_item, Message *message) const;
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
  void ContactPresenceSlot(const InboxItem& information_message);
  void ContactProfilePictureSlot(const InboxItem& information_message);
  void OpenShareInvitationSlot(const InboxItem& inbox_item);
  void RetrieveMessagesForAllIds();
  void EnqueuePresenceMessages(ContactPresence presence);
  void SignalFileTransfer(const InboxItem &inbox_item);
  void SignalShare(const InboxItem &inbox_item);
  void ContentsDontParseAsDataMap(const std::string& serialised_dm,
                                  std::string* data_map);
  void ProcessPresenceMessages();
  void ContactDeletionSlot(const InboxItem &deletion_item);

  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store_;
  std::shared_ptr<Session> session_;
  ba::deadline_timer get_new_messages_timer_;
  ChatMessageSignalPtr chat_signal_;
  FileTransferSignalPtr file_transfer_signal_;
  ShareInvitationSignalPtr share_invitation_signal_;
  OpenShareInvitationSignalPtr open_share_invitation_signal_;
  ShareDeletionSignalPtr share_deletion_signal_;
  ShareUpdateSignalPtr share_update_signal_;
  MemberAccessLevelSignalPtr member_access_level_signal_;
  SaveShareDataSignalPtr save_share_data_signal_;
  SaveOpenShareDataSignalPtr save_open_share_data_signal_;
  ContactPresenceSignalPtr contact_presence_signal_;
  ContactProfilePictureSignalPtr contact_profile_picture_signal_;
  ContactDeletionSignalPtr contact_deletion_signal_;
  ParseAndSaveDataMapSignalPtr parse_and_save_data_map_signal_;
  ReceivedMessagesMap received_messages_;
  ba::io_service &asio_service_;  // NOLINT (Dan)
  bool start_up_done_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_MESSAGE_HANDLER_H_
