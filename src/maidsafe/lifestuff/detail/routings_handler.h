///***************************************************************************************************
// *  Copyright 2012 maidsafe.net limited                                                            *
// *                                                                                                 *
// *  The following source code is property of maidsafe.net limited and is not meant for external    *
// *  use. The use of this code is governed by the license file LICENSE.TXT found in the root of     *
// *  this directory and also on www.maidsafe.net.                                                   *
// *                                                                                                 *
// *  You are not free to copy, amend or otherwise use this source code without the explicit written *
// *  permission of the board of directors of maidsafe.net.                                          *
// **************************************************************************************************/
///**
// * @file  routings_handler.h
// * @brief Provides a class for processing messages using Routing.
// * @date  2012-09-03
// */
//
//#ifndef MAIDSAFE_LIFESTUFF_DETAIL_ROUTINGS_HANDLER_H_
//#define MAIDSAFE_LIFESTUFF_DETAIL_ROUTINGS_HANDLER_H_
//
//#include <condition_variable>
//#include <functional>
//#include <map>
//#include <memory>
//#include <mutex>
//#include <string>
//#include <utility>
//#include <vector>
//
//#include "maidsafe/common/rsa.h"
//
//#include "maidsafe/routing/routing_api.h"
//
//#include "maidsafe/lifestuff/lifestuff.h"
//
//namespace maidsafe {
//namespace lifestuff {
//
//class Session;
//
//class RoutingsHandler {
// public:
//  explicit RoutingsHandler(priv::chunk_store::RemoteChunkStore& chunk_store,
//                           Session& session,
//                           const ValidatedMessageFunction& validated_message_signal);
//
//  ~RoutingsHandler();
//
//  bool AddRoutingObject(const Fob& owner_fob,
//                        const std::vector<std::pair<std::string, uint16_t> >& bootstrap_endpoints,  // NOLINT (Dan)
//                        const NonEmptyString& search_id,
//                        const routing::RequestPublicKeyFunctor& public_key_functor);
//  bool DeleteRoutingObject(const Identity& identity);
//
//  bool Send(const Identity& source_id,
//            const Identity& destination_id,
//            const asymm::PublicKey& destination_public_key,
//            const NonEmptyString& message,
//            std::string* reply_message);
//
//  void set_remote_chunk_store(priv::chunk_store::RemoteChunkStore& chunk_store);
//
// private:
//  struct RoutingDetails {
//    RoutingDetails();
//    RoutingDetails(const Fob& owner_fob, const NonEmptyString& search_id);
//    routing::Routing routing_object;
//    int newtwork_health;
//    Fob fob;
//    std::mutex mutex;
//    std::condition_variable condition_variable;
//    NonEmptyString search_id;
//    bool action_health;
//  };
//
//  priv::chunk_store::RemoteChunkStore* chunk_store_;
//  std::map<Identity, std::shared_ptr<RoutingDetails> > routing_objects_;
//  std::mutex routing_objects_mutex_;
//  Session& session_;
//  ValidatedMessageFunction validated_message_signal_;
//  std::mutex cs_mutex_;
//  volatile bool stopped_;
//
//  RoutingsHandler(const RoutingsHandler&);
//  RoutingsHandler& operator=(const RoutingsHandler&);
//
//  void OnRequestReceived(const Identity& owner_id,
//                         const NonEmptyString& wrapped_message,
//                         const NodeId& group_claim,
//                         const routing::ReplyFunctor& reply_functor);
//
//  void DoOnRequestReceived(const Identity& owner_id,
//                           const NonEmptyString& wrapped_message,
//                           const NodeId& group_claim,
//                           const routing::ReplyFunctor& reply_functor);
//
//  void OnPublicKeyRequested(const NodeId& node_id,
//                            const routing::GivePublicKeyFunctor& give_key);
//
//  NonEmptyString WrapMessage(const NonEmptyString& message,
//                             const asymm::PublicKey& receiver_public_key,
//                             const asymm::PrivateKey& sender_private_key);
//
//  NonEmptyString UnwrapMessage(const NonEmptyString& wrapped_message,
//                               const asymm::PublicKey& sender_public_key,
//                               const asymm::PrivateKey& receiver_private_key);
//};
//
//}  // namespace lifestuff
//}  // namespace maidsafe
//
//#endif  // MAIDSAFE_LIFESTUFF_DETAIL_ROUTINGS_HANDLER_H_
