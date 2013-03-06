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

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/routing/routing_api.h"

#include "maidsafe/nfs/nfs.h"
#include "maidsafe/nfs/pmid_registration.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/detail/user_credentials.h"
#include "maidsafe/lifestuff_manager/client_controller.h"
#include "maidsafe/lifestuff/detail/routings_handler.h"

namespace maidsafe {
namespace lifestuff {

class LifeStuffImpl {
 public:
  typedef maidsafe::routing::Routing Routing;
  typedef std::unique_ptr<Routing> RoutingPtr;
  typedef std::pair<std::string, uint16_t> EndPoint;
  typedef boost::asio::ip::udp::endpoint UdpEndPoint;
  typedef maidsafe::nfs::PmidRegistration PmidRegistration;
  typedef maidsafe::nfs::ClientMaidNfs ClientNfs;
  typedef std::unique_ptr<ClientNfs> ClientNfsPtr;
  typedef std::unique_ptr<UserCredentials> UserCredentialsPtr;
  typedef maidsafe::lifestuff_manager::ClientController ClientController;
  typedef passport::Passport Passport;
  typedef passport::Anmid Anmid;
  typedef passport::Ansmid Ansmid;
  typedef passport::Antmid Antmid;
  typedef passport::Anmaid Anmaid;
  typedef passport::Maid Maid;
  typedef passport::Pmid Pmid;
  typedef passport::Mid Mid;
  typedef passport::Tmid Tmid;
  
  LifeStuffImpl(const Slots& slots);
  ~LifeStuffImpl();

  void CreateUser(const Keyword& keyword, const Pin& pin, const Password& password);
  void CreatePublicId(const NonEmptyString& public_id);

  void LogIn(const Keyword& keyword, const Pin& pin, const Password& password);
  void LogOut();
  void MountDrive();
  void UnMountDrive();

 private:
  const Slots& CheckSlots(const Slots& slots);

  void CheckInputs(const Keyword& keyword, const Pin& pin, const Password& password);
  void CheckKeywordValidity(const Keyword& keyword);
  void CheckPinValidity(const Pin& pin);
  void CheckPasswordValidity(const Password& password);
  bool AcceptableWordSize(const Identity& word);
  bool AcceptableWordPattern(const Identity& word);

  void Join(const Maid& maid);
  void PutFreeFobs();
  void HandlePutFreeFobsFailure();
  void PutPaidFobs();
  void HandlePutPaidFobsFailure();
  template <typename Fob> void PutFob(const Fob& fob);
  void HandlePutFobFailure();

  std::vector<UdpEndPoint> UdpEndpoints(const std::vector<EndPoint>& bootstrap_endpoints);
  routing::Functors InitialiseRoutingFunctors();
  void OnMessageReceived(const std::string& message,  const routing::ReplyFunctor& reply_functor);
  void DoOnMessageReceived(const std::string& message, const routing::ReplyFunctor& reply_functor);
  void OnNetworkStatusChange(const int& network_health);
  void DoOnNetworkStatusChange(const int& network_health);
  void OnPublicKeyRequested(const NodeId &node_id, const routing::GivePublicKeyFunctor &give_key);
  void DoOnPublicKeyRequested(const NodeId &node_id, const routing::GivePublicKeyFunctor &give_key);
  void OnCloseNodeReplaced(const std::vector<routing::NodeInfo>& new_close_nodes);
  bool OnGetFromCache(std::string& message);
  void OnStoreInCache(const std::string& message);
  void DoOnStoreInCache(const std::string& message);
  void OnNewBootstrapEndpoint(const boost::asio::ip::udp::endpoint& endpoint);
  void DoOnNewBootstrapEndpoint(const boost::asio::ip::udp::endpoint& endpoint);

  Slots slots_;
  Passport passport_;
  RoutingPtr routing_;
  ClientNfsPtr client_nfs_;
  UserCredentialsPtr user_credentials_;
  ClientController client_controller_;
  int network_health_;
  AsioService asio_service_;
};

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_



//
//#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_
//#define MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_
//
//#include <list>
//#include <map>
//#include <string>
//#include <utility>
//#include <vector>
//
//#include "boost/filesystem/path.hpp"
//#include "boost/signals2/signal.hpp"
//
//#include "maidsafe/common/asio_service.h"
//#include "maidsafe/common/log.h"
//#include "maidsafe/common/utils.h"
//
//#include "maidsafe/routing/routing_api.h"
//
//#include "maidsafe/lifestuff/lifestuff.h"
//#include "maidsafe/lifestuff/detail/contacts.h"
//#include "maidsafe/lifestuff/detail/session.h"
//#include "maidsafe/lifestuff/detail/utils.h"
//
//namespace fs = boost::filesystem;
//namespace bptime = boost::posix_time;
//
//namespace maidsafe {
//namespace lifestuff {
//
//class MessageHandler;
//class PublicId;
//class RoutingsHandler;
//class UserCredentials;
//class UserStorage;
//
//class LifeStuffImpl {
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
//};
//
//}  // namespace lifestuff
//
//}  // namespace maidsafe
//
//#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_
