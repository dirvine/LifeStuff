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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_ROUTING_HANDLER_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_ROUTING_HANDLER_H_

#include <functional>
#include <string>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <utility>

#include "maidsafe/routing/routing_api.h"

namespace maidsafe {
namespace lifestuff {

typedef routing::GivePublicKeyFunctor GivePublicKeyFunctor;
typedef std::function<void(const NodeId&, const GivePublicKeyFunctor&)> PublicKeyRequestFunction;

class RoutingHandler {
 public:
  typedef routing::Routing Routing;
  typedef routing::Functors Functors;
  typedef routing::ReplyFunctor ReplyFunctor;
  typedef std::pair<std::string, uint16_t> EndPoint;
  typedef boost::asio::ip::udp::endpoint UdpEndPoint;
  typedef std::vector<EndPoint> EndPointVector;
  typedef std::vector<UdpEndPoint> UdpEndPointVector;
  typedef passport::Maid Maid;

  RoutingHandler(const Maid& maid, PublicKeyRequestFunction public_key_request);
  ~RoutingHandler();

  void Join(const EndPointVector& endpoints);

  Routing& routing();

 private:
  RoutingHandler(const RoutingHandler&);
  RoutingHandler& operator=(const RoutingHandler&);

  Functors InitialiseFunctors();

  void OnMessageReceived(const std::string& message,  const ReplyFunctor& reply_functor);
  void DoOnMessageReceived(const std::string& message, const ReplyFunctor& reply_functor);
  void OnNetworkStatusChange(const int& network_health);
  void DoOnNetworkStatusChange(const int& network_health);
  void OnPublicKeyRequested(const NodeId &node_id, const GivePublicKeyFunctor &give_key);
  void DoOnPublicKeyRequested(const NodeId &node_id, const GivePublicKeyFunctor &give_key);
  void OnNewBootstrapEndpoint(const UdpEndPoint& endpoint);
  void DoOnNewBootstrapEndpoint(const UdpEndPoint& endpoint);

  UdpEndPointVector UdpEndpoints(const EndPointVector& bootstrap_endpoints);

  Routing routing_;
  PublicKeyRequestFunction public_key_request_;
  int network_health_;
  std::mutex mutex_;
  std::condition_variable condition_variable_;
  AsioService asio_service_;
};

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_ROUTING_HANDLER_H_
