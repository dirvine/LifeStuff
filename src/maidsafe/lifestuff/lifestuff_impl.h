/***************************************************************************************************
 *  Copyright 2013 MaidSafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use.  The use of this code is governed by the licence file licence.txt found in the root of    *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit         *
 *  written permission of the board of directors of MaidSafe.net.                                  *
 **************************************************************************************************/

#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_
#define MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/detail/client_maid.h"
#include "maidsafe/lifestuff/detail/client_mpid.h"

namespace maidsafe {
namespace lifestuff {

class LifeStuffImpl {
 public:
  explicit LifeStuffImpl(const Slots& slots);
  ~LifeStuffImpl();

  void CreateUser(const Keyword& keyword, const Pin& pin, const Password& password);
  void CreatePublicId(const NonEmptyString& public_id);

  void LogIn(const Keyword& keyword, const Pin& pin, const Password& password);
  void LogOut();
  void MountDrive();
  void UnMountDrive();

 private:
  const Slots& CheckSlots(const Slots& slots);

  Slots slots_;
  Session session_;
  ClientMaid client_maid_;
  ClientMpid client_mpid_;
};

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_



//
// #ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_
// #define MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_
//
// #include <list>
// #include <map>
// #include <string>
// #include <utility>
// #include <vector>
//
// #include "boost/filesystem/path.hpp"
// #include "boost/signals2/signal.hpp"
//
// #include "maidsafe/common/asio_service.h"
// #include "maidsafe/common/log.h"
// #include "maidsafe/common/utils.h"
//
// #include "maidsafe/routing/routing_api.h"
//
// #include "maidsafe/lifestuff/lifestuff.h"
// #include "maidsafe/lifestuff/detail/contacts.h"
// #include "maidsafe/lifestuff/detail/session.h"
// #include "maidsafe/lifestuff/detail/utils.h"
//
// namespace fs = boost::filesystem;
// namespace bptime = boost::posix_time;
//
// namespace maidsafe {
// namespace lifestuff {
//
// class MessageHandler;
// class PublicId;
// class RoutingsHandler;
// class UserCredentials;
// class UserStorage;
//
// class LifeStuffImpl {
// public:
//  LifeStuffImpl(const Slots& slot_functions, const fs::path& base_directory);
//  ~LifeStuffImpl();
//
//  /// Credential operations
//  int CreateUser(const NonEmptyString& keyword,
//                 const NonEmptyString& pin,
//                 const NonEmptyString& password,
//                 const fs::path& chunk_store);
//  int CreatePublicId(const NonEmptyString& public_id);
//  int LogIn(const NonEmptyString& keyword,
//            const NonEmptyString& pin,
//            const NonEmptyString& password);
//  int LogOut(bool clear_maid_routing = true);
//  int MountDrive();
//  int UnMountDrive();
//  int StartMessagesAndIntros();
//  int StopMessagesAndIntros();
//
//  int CheckPassword(const NonEmptyString& password);
//  int ChangeKeyword(const NonEmptyString& new_keyword, const NonEmptyString& password);
//  int ChangePin(const NonEmptyString& new_pin, const NonEmptyString& password);
//  int ChangePassword(const NonEmptyString& new_password, const NonEmptyString& current_password);
//  int ChangePublicId(const NonEmptyString& public_id, const NonEmptyString& password);
//
//  int LeaveLifeStuff();  // ='(
//
//  /// Contact operations
//  int AddContact(const NonEmptyString& my_public_id,
//                 const NonEmptyString& contact_public_id,
//                 const std::string& message);
//  int ConfirmContact(const NonEmptyString& my_public_id, const NonEmptyString& contact_public_id);
//  int DeclineContact(const NonEmptyString& my_public_id, const NonEmptyString& contact_public_id);
//  int RemoveContact(const NonEmptyString& my_public_id,
//                    const NonEmptyString& contact_public_id,
//                    const std::string& removal_message,
//                    const bool& instigator);
//  int ChangeProfilePicture(const NonEmptyString& my_public_id,
//                           const NonEmptyString& profile_picture_contents);
//  NonEmptyString GetOwnProfilePicture(const NonEmptyString& my_public_id);
//  NonEmptyString GetContactProfilePicture(const NonEmptyString& my_public_id,
//                                       const NonEmptyString& contact_public_id);
//  int GetLifestuffCard(const NonEmptyString& my_public_id,
//                       const std::string& contact_public_id,
//                       SocialInfoMap& social_info);
//  int SetLifestuffCard(const NonEmptyString& my_public_id, const SocialInfoMap& social_info);
//  ContactMap GetContacts(const NonEmptyString& my_public_id,
//                         uint16_t bitwise_status = kConfirmed | kRequestSent);
//  std::vector<NonEmptyString> PublicIdsList() const;
//
//  /// Messaging
//  int SendChatMessage(const NonEmptyString& sender_public_id,
//                      const NonEmptyString& receiver_public_id,
//                      const NonEmptyString& message);
//  int SendFile(const NonEmptyString& sender_public_id,
//               const NonEmptyString& receiver_public_id,
//               const fs::path& absolute_path);
//  int AcceptSentFile(const NonEmptyString& identifier,
//                     const fs::path& absolute_path = fs::path(),
//                     std::string* file_name = nullptr);
//  int RejectSentFile(const NonEmptyString& identifier);
//
//  /// Filesystem
//  int ReadHiddenFile(const fs::path& absolute_path, std::string* content) const;
//  int WriteHiddenFile(const fs::path& absolute_path,
//                      const NonEmptyString& content,
//                      bool overwrite_existing);
//  int DeleteHiddenFile(const fs::path& absolute_path);
//  int SearchHiddenFiles(const fs::path& absolute_path,
//                        std::vector<std::string>* results);
//
//  int state() const;
//  int logged_in_state() const;
//  fs::path mount_path() const;
//
// private:
//  struct LoggedInComponents;
//  int thread_count_;
//  fs::path buffered_path_;
//  bptime::seconds interval_;
//  AsioService asio_service_;
//  boost::signals2::signal<void(const int&)> network_health_signal_;
//  Session session_;
//  std::shared_ptr<priv::chunk_store::RemoteChunkStore> remote_chunk_store_;
//  std::shared_ptr<priv::lifestuff_manager::ClientController> client_controller_;
//  std::shared_ptr<pd::Node> client_node_;
//  std::shared_ptr<RoutingsHandler> routings_handler_;
//  std::shared_ptr<UserCredentials> user_credentials_;
//  std::shared_ptr<LoggedInComponents> logged_in_components_;
//  Slots slots_;
//  LifeStuffState state_;
//  uint8_t logged_in_state_;
//  boost::signals2::signal<void()> immediate_quit_required_signal_;
//  std::mutex single_threaded_class_mutex_;
//
//  int AttemptCleanQuit();
//  void ConnectToSignals();
//  int MakeAnonymousComponents();
//  void ConnectInternalElements();
//  int SetValidPmidAndInitialisePublicComponents();
//  int CheckStateAndFullAccess() const;
//  int PreContactChecksFullAccess(const NonEmptyString& my_public_id);
//  void NetworkHealthSlot(const int& index);
//  int CreateVaultInLocalMachine(const fs::path& chunk_store);
//  bool HandleRoutingsHandlerMessage(const NonEmptyString& message, std::string& response);
//  bool HandleLogoutProceedingsMessage(const NonEmptyString& message, std::string& response);
// };
//
// }  // namespace lifestuff
//
// }  // namespace maidsafe
//
// #endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_
