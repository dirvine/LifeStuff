/***************************************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use.  The use of this code is governed by the licence file licence.txt found in the root of    *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit         *
 *  written permission of the board of directors of MaidSafe.net.                                  *
 **************************************************************************************************/

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MAID_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MAID_H_

#include <string>
#include <vector>
#include <utility>

#include "maidsafe/routing/routing_api.h"

#include "maidsafe/nfs/nfs.h"
#include "maidsafe/nfs/pmid_registration.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/detail/user_credentials.h"
#include "maidsafe/lifestuff_manager/client_controller.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/user_storage.h"
#include "maidsafe/lifestuff/detail/routings_handler.h"

namespace maidsafe {
namespace lifestuff {

class ClientMaid {
 public:
  typedef routing::Routing Routing;
  typedef std::unique_ptr<Routing> RoutingPtr;
  typedef std::pair<std::string, uint16_t> EndPoint;
  typedef boost::asio::ip::udp::endpoint UdpEndPoint;
  typedef nfs::PmidRegistration PmidRegistration;
  typedef nfs::ClientMaidNfs ClientNfs;
  typedef std::unique_ptr<ClientNfs> ClientNfsPtr;
  typedef std::unique_ptr<UserCredentials> UserCredentialsPtr;
  typedef lifestuff_manager::ClientController ClientController;
  typedef passport::Passport Passport;
  typedef passport::Anmid Anmid;
  typedef passport::Ansmid Ansmid;
  typedef passport::Antmid Antmid;
  typedef passport::Anmaid Anmaid;
  typedef passport::Maid Maid;
  typedef passport::Pmid Pmid;
  typedef passport::Mid Mid;
  typedef passport::Tmid Tmid;

  explicit ClientMaid(UpdateAvailableFunction update_available_slot);
  ~ClientMaid() {}

  void CreateUser(const Keyword& keyword, const Pin& pin, const Password& password);
  void LogIn(const Keyword& keyword, const Pin& pin, const Password& password);
  void LogOut();
  void MountDrive();
  void UnMountDrive();

 private:
  void CheckInputs(const Keyword& keyword, const Pin& pin, const Password& password);
  void CheckKeywordValidity(const Keyword& keyword);
  void CheckPinValidity(const Pin& pin);
  void CheckPasswordValidity(const Password& password);
  bool AcceptableWordSize(const Identity& word);
  bool AcceptableWordPattern(const Identity& word);

  void GetSession(const Keyword& keyword, const Pin& pin, const Password& password);
  void PutSession(const Keyword& keyword, const Pin& pin, const Password& password);

  void Join(const Maid& maid);
  void PutFreeFobs();
  void HandlePutFreeFobsFailure();
  void PutPaidFobs();
  void HandlePutPaidFobsFailure();
  template <typename Fob> void PutFob(const Fob& fob);
  void HandlePutFobFailure();

  void RegisterPmid(const Maid& maid, const Pmid& pmid);
  void UnregisterPmid(const Maid& maid, const Pmid& pmid);

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

  ClientController client_controller_;
  Session session_;
  UserStorage user_storage_;
  RoutingPtr routing_;
  ClientNfsPtr client_nfs_;
  UserCredentialsPtr user_credentials_;
  int network_health_;
  AsioService asio_service_;
};
}  // lifestuff
}  // maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MAID_H_
