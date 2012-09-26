/*
* ============================================================================
*
* Copyright [2012] maidsafe.net limited
*
* Description:  Definition of system-wide constants/enums/structs
* Version:      1.0
* Created:      2012-03-27
* Revision:     none
* Compiler:     gcc
* Company:      maidsafe.net limited
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

#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_
#define MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_

#include <list>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "boost/filesystem/path.hpp"
#include "boost/signals2/signal.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/private/process_management/client_controller.h"
#include "maidsafe/routing/routing_api.h"
#include "maidsafe/pd/client/node.h"
#include "maidsafe/pd/vault/node.h"
#include "maidsafe/lifestuff/detail/routings_handler.h"
#endif

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace fs = boost::filesystem;
namespace bptime = boost::posix_time;
namespace pcs = maidsafe::priv::chunk_store;

namespace maidsafe {

namespace lifestuff {

class Session;
class UserCredentials;
class UserStorage;
class PublicId;
class MessageHandler;

struct Slots {
  Slots()
      : chat_slot(),
        file_slot(),
        new_contact_slot(),
        confirmed_contact_slot(),
        profile_picture_slot(),
        contact_presence_slot(),
        contact_deletion_function(),
        lifestuff_card_update_function(),
        network_health_function(),
        immediate_quit_required_function() {}
  ChatFunction chat_slot;
  FileTransferFunction file_slot;
  NewContactFunction new_contact_slot;
  ContactConfirmationFunction confirmed_contact_slot;
  ContactProfilePictureFunction profile_picture_slot;
  ContactPresenceFunction contact_presence_slot;
  ContactDeletionFunction contact_deletion_function;
  LifestuffCardUpdateFunction lifestuff_card_update_function;
  NetworkHealthFunction network_health_function;
  ImmediateQuitRequiredFunction immediate_quit_required_function;
};

class LifeStuffImpl {
 public:
  LifeStuffImpl();
  ~LifeStuffImpl();

  /// State operations
  int Initialise(const UpdateAvailableFunction& software_update_available_function,
                 const fs::path& base_directory);
  int ConnectToSignals(const bool& apply_changes,
                       const ChatFunction& chat_slot,
                       const FileTransferFunction& file_slot,
                       const NewContactFunction& new_contact_slot,
                       const ContactConfirmationFunction& confirmed_contact_slot,
                       const ContactProfilePictureFunction& profile_picture_slot,
                       const ContactPresenceFunction& contact_presence_slot,
                       const ContactDeletionFunction& contact_deletion_function,
                       const LifestuffCardUpdateFunction& lifestuff_card_update_function,
                       const NetworkHealthFunction& network_health_function,
                       const ImmediateQuitRequiredFunction& immediate_quit_required_function);
  int Finalise();

  /// Credential operations
  int CreateUser(const std::string& username,
                 const std::string& pin,
                 const std::string& password,
                 const fs::path& chunk_store,
                 bool vault_cheat = false);
  int CreatePublicId(const std::string& public_id);
  int LogIn(const std::string& username, const std::string& pin, const std::string& password);
  int LogOut();
  int CreateAndMountDrive();
  int MountDrive(bool read_only);
  int UnMountDrive();
  int StartMessagesAndIntros();
  int StopMessagesAndIntros();

  int CheckPassword(const std::string& password);
  int ChangeKeyword(const std::string& new_username, const std::string& password);
  int ChangePin(const std::string& new_pin, const std::string& password);
  int ChangePassword(const std::string& new_password, const std::string& current_password);
  int ChangePublicId(const std::string& public_id, const std::string& password);

  int LeaveLifeStuff();  // ='(

  /// Contact operations
  int AddContact(const std::string& my_public_id,
                 const std::string& contact_public_id,
                 const std::string& message);
  int ConfirmContact(const std::string& my_public_id, const std::string& contact_public_id);
  int DeclineContact(const std::string& my_public_id, const std::string& contact_public_id);
  int RemoveContact(const std::string& my_public_id,
                    const std::string& contact_public_id,
                    const std::string& removal_message,
                    const std::string& timestamp,
                    const bool& instigator);
  int ChangeProfilePicture(const std::string& my_public_id,
                           const std::string& profile_picture_contents);
  std::string GetOwnProfilePicture(const std::string& my_public_id);
  std::string GetContactProfilePicture(const std::string& my_public_id,
                                       const std::string& contact_public_id);
  int GetLifestuffCard(const std::string& my_public_id,
                       const std::string& contact_public_id,
                       SocialInfoMap& social_info);
  int SetLifestuffCard(const std::string& my_public_id, const SocialInfoMap& social_info);
  ContactMap GetContacts(const std::string& my_public_id,
                         uint16_t bitwise_status = kConfirmed | kRequestSent);
  std::vector<std::string> PublicIdsList() const;

  /// Messaging
  int SendChatMessage(const std::string& sender_public_id,
                      const std::string& receiver_public_id,
                      const std::string& message);
  int SendFile(const std::string& sender_public_id,
               const std::string& receiver_public_id,
               const fs::path& absolute_path);
  int AcceptSentFile(const std::string& identifier,
                     const fs::path& absolute_path = fs::path(),
                     std::string* file_name = nullptr);
  int RejectSentFile(const std::string& identifier);

  /// Filesystem
  int ReadHiddenFile(const fs::path& absolute_path, std::string* content) const;
  int WriteHiddenFile(const fs::path& absolute_path,
                      const std::string& content,
                      bool overwrite_existing);
  int DeleteHiddenFile(const fs::path& absolute_path);
  int SearchHiddenFiles(const fs::path& absolute_path,
                        std::vector<std::string>* results);

  int state() const;
  int logged_in_state() const;
  fs::path mount_path() const;

 private:
  int thread_count_;
  fs::path buffered_path_;
#ifdef LOCAL_TARGETS_ONLY
  fs::path simulation_path_;
#endif
  bptime::seconds interval_;
  AsioService asio_service_;
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store_;
#ifndef LOCAL_TARGETS_ONLY
  std::shared_ptr<priv::process_management::ClientController> client_controller_;
  std::shared_ptr<pd::Node> node_;
  std::shared_ptr<RoutingsHandler> routings_handler_;
  pd::vault::Node vault_node_;
#endif
  boost::signals2::signal<void(const int&)> network_health_signal_;
  Session session_;
  std::shared_ptr<UserCredentials> user_credentials_;
  std::shared_ptr<UserStorage> user_storage_;
  std::shared_ptr<PublicId> public_id_;
  std::shared_ptr<MessageHandler> message_handler_;
  Slots slots_;
  LifeStuffState state_;
  uint8_t logged_in_state_;

  void ConnectInternalElements();
  int SetValidPmidAndInitialisePublicComponents();
  int CheckStateAndReadOnlyAccess() const;
  int CheckStateAndFullAccess() const;
  int PreContactChecksFullAccess(const std::string& my_public_id);
  int PreContactChecksReadOnly(const std::string& my_public_id);
  void NetworkHealthSlot(const int& index);
#ifndef LOCAL_TARGETS_ONLY
  int CreateVaultInLocalMachine(const fs::path& chunk_store, bool vault_cheat);
  int EstablishMaidRoutingObject(
      const std::vector<std::pair<std::string, uint16_t> >& bootstrap_endpoints);  // NOLINT (Dan)
#endif
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_
