/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of maidsafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the license file LICENSE.TXT found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of maidsafe.net.                                          *
 **************************************************************************************************/
/**
 * @file  routing_message_handler.cc
 * @brief Provides a class for processing messages using Routing.
 * @date  2012-06-02
 */

//#include "maidsafe/lifestuff/detail/routings_handler.h"
//
//#include <chrono>
//#include <utility>
//#include <vector>
//
//#include "maidsafe/common/log.h"
//#include "maidsafe/common/node_id.h"
//#include "maidsafe/common/utils.h"
//
//#include "maidsafe/private/chunk_actions/chunk_pb.h"
//#include "maidsafe/private/chunk_actions/chunk_id.h"
//
//#include "maidsafe/routing/api_config.h"
//#include "maidsafe/routing/return_codes.h"
//
//#include "maidsafe/lifestuff/return_codes.h"
//#include "maidsafe/lifestuff/detail/session.h"
//#include "maidsafe/lifestuff/detail/utils.h"
//
//namespace pca = maidsafe::priv::chunk_actions;
//
//namespace maidsafe {
//
//namespace lifestuff {
//
//const int kMinAcceptableClientHealth(75);
//
//RoutingsHandler::RoutingDetails::RoutingDetails()
//    : routing_object(Fob(), true),
//      newtwork_health(-1),
//      fob(),
//      mutex(),
//      condition_variable(),
//      search_id(),
//      action_health(true) {}
//
//RoutingsHandler::RoutingDetails::RoutingDetails(const Fob& owner_credentials,
//                                                const NonEmptyString& search_id)
//    : routing_object(owner_credentials, true),
//      newtwork_health(-1),
//      fob(owner_credentials),
//      mutex(),
//      condition_variable(),
//      search_id(search_id),
//      action_health(true) {}
//
//RoutingsHandler::RoutingsHandler(priv::chunk_store::RemoteChunkStore& chunk_store,
//                                 Session& session,
//                                 const ValidatedMessageFunction& validated_message_signal,
//                                 boost::asio::io_service& service)
//    : chunk_store_(&chunk_store),
//      routing_objects_(),
//      routing_objects_mutex_(),
//      session_(session),
//      validated_message_signal_(validated_message_signal),
//      cs_mutex_(),
//      stopped_(false),
//      asio_service_(service) {}
//
//RoutingsHandler::~RoutingsHandler() {
//  stopped_ = true;
//  std::lock_guard<std::mutex> lock(routing_objects_mutex_);
//  for (auto& element : routing_objects_)
//    element.second->routing_object.DisconnectFunctors();
//  routing_objects_.clear();
//  LOG(kInfo) << "Cleared objects\n\n\n\n";
//}
//
//void RoutingsHandler::set_remote_chunk_store(priv::chunk_store::RemoteChunkStore& chunk_store) {
//  std::lock_guard<std::mutex> lock(cs_mutex_);
//  chunk_store_ = &chunk_store;
//}
//
//bool RoutingsHandler::AddRoutingObject(
//    const Fob& owner_credentials,
//    const std::vector<std::pair<std::string, uint16_t> >& bootstrap_endpoints,  // NOLINT (Dan)
//    const NonEmptyString& search_id,
//    const routing::RequestPublicKeyFunctor& public_key_functor) {
//  std::shared_ptr<RoutingDetails> routing_details(
//        std::make_shared<RoutingDetails>(owner_credentials, search_id));
//
//  // Bootstrap endpoints to udp endpoints
//  std::vector<boost::asio::ip::udp::endpoint> peer_endpoints;
//  for (auto& element : bootstrap_endpoints) {
//    boost::asio::ip::udp::endpoint ep;
//    ep.address(boost::asio::ip::address::from_string(element.first));
//    ep.port(element.second);
//    peer_endpoints.push_back(ep);
//  }
//
//  // Functors
//  routing::Functors functors;
//  Identity id(routing_details->fob.identity);
//  functors.message_received = [this, id] (const std::string& wrapped_message,
//                                          const NodeId& group_claim,
//                                          const bool& /*cache_lookup*/,
//                                          const routing::ReplyFunctor& reply_functor) {
//                                OnRequestReceived(id,
//                                                  NonEmptyString(wrapped_message),
//                                                  group_claim,
//                                                  reply_functor);
//                              };
//
//  if (public_key_functor)
//    functors.request_public_key = public_key_functor;
//  else
//    functors.request_public_key = [this] (const NodeId& node_id,
//                                          const routing::GivePublicKeyFunctor& give_key) {
//                                    OnPublicKeyRequested(node_id, give_key);
//                                  };
//  // Network health
//  std::weak_ptr<RoutingDetails> routing_details_weak_ptr(routing_details);
//  functors.network_status = [routing_details_weak_ptr] (const int& network_health) {
//                              if (auto spt = routing_details_weak_ptr.lock()) {
//                                if (spt->action_health) {
//                                  std::lock_guard<std::mutex> health_lock(spt->mutex);
//                                  spt->newtwork_health = network_health;
//                                }
//                              }
//                            };
//
//  routing_details->routing_object.Join(functors, peer_endpoints);
//  {
//    std::unique_lock<std::mutex> health_lock(routing_details->mutex);
//    routing_details->condition_variable.wait_for(health_lock,
//                                                 std::chrono::seconds(5),
//                                                 [&] ()->bool {
//                                                   // TODO(Team): Remove this blatantly arbitrary
//                                                   //             network level
//                                                   return routing_details->newtwork_health != -1 &&
//                                                          routing_details->newtwork_health >=
//                                                              kMinAcceptableClientHealth;
//                                                 });
//    if (routing_details->newtwork_health == routing::kNotJoined ||
//        routing_details->newtwork_health < kMinAcceptableClientHealth) {
//      LOG(kError) << "Failed to join this routing object.";
//      return false;
//    }
//  }
//  routing_details->action_health = false;
//
//  auto result(routing_objects_.insert(std::make_pair(owner_credentials.identity, routing_details)));
//  if (!result.second) {
//    LOG(kError) << "Failed to insert MAID to map.";
//    return false;
//  }
//
//  return true;
//}
//
//bool RoutingsHandler::DeleteRoutingObject(const Identity& identity) {
//  std::lock_guard<std::mutex> lock(routing_objects_mutex_);
//  size_t erased_count(routing_objects_.erase(identity));
//  LOG(kInfo) << "RoutingsHandler::DeleteRoutingObject erased: " << erased_count
//             << ", out of: " << (routing_objects_.size() + erased_count);
//  return erased_count == size_t(1);
//}
//
//
//bool RoutingsHandler::Send(const Identity& source_id,
//                           const Identity& destination_id,
//                           const asymm::PublicKey& destination_public_key,
//                           const NonEmptyString& message,
//                           std::string* reply_message) {
//  std::shared_ptr<RoutingDetails> routing_details;
//  {
//    std::lock_guard<std::mutex> lock(routing_objects_mutex_);
//    auto it(routing_objects_.find(source_id));
//    if (it == routing_objects_.end()) {
//      LOG(kError) << "No such ID to send message: " << DebugId(NodeId(source_id));
//      return false;
//    }
//    routing_details = it->second;
//    assert(routing_details);
//  }
//
//  NonEmptyString wrapped_message(WrapMessage(message,
//                                             destination_public_key,
//                                             routing_details->fob.keys.private_key));
//
//  routing::ResponseFunctor response_functor;
//  std::mutex message_mutex;
//  std::condition_variable condition_variable;
//  std::string message_from_routing;
//  bool message_received(false);
//  if (reply_message) {
//      response_functor = [&] (const std::vector<std::string>& messages) {
//                           {
//                             std::lock_guard<std::mutex> message_lock(message_mutex);
//                             if (!messages.empty()) {
//                               message_from_routing = messages.front();
//                             } else {
//                               LOG(kInfo) << "Message count: " << messages.size();
//                             }
//                             message_received = true;
//                           }
//                           condition_variable.notify_one();
//                         };
//  }
//
//  NodeId group_claim_as_own_id;
//  if (source_id == destination_id)
//    group_claim_as_own_id = NodeId(destination_id.string());
//
//  LOG(kInfo) << "sender: " << DebugId(group_claim_as_own_id)
//             << ", receiver: " << DebugId(NodeId(destination_id));
//  routing_details->routing_object.Send(NodeId(destination_id.string()),
//                                       group_claim_as_own_id,
//                                       wrapped_message.string(),
//                                       response_functor,
//                                       boost::posix_time::seconds(10),
//                                       routing::DestinationType::kDirect,
//                                       false);
//
//  if (reply_message) {
//    std::unique_lock<std::mutex> message_lock(message_mutex);
//    if (!condition_variable.wait_for(message_lock,
//                                     std::chrono::seconds(10),
//                                     [&] () { return message_received; })) {
//      LOG(kError) << "Timed out waiting for response from " << DebugId(NodeId(destination_id));
//      return false;
//    }
//    if (message_from_routing.empty()) {
//      LOG(kError) << "Message from " << DebugId(NodeId(destination_id)) << " is empty. "
//                  << "Probably timed out in routing.";
//      return false;
//    }
//
//    NonEmptyString unwrapped_message(UnwrapMessage(NonEmptyString(message_from_routing),
//                                                   destination_public_key,
//                                                   routing_details->fob.keys.private_key));
//
//    *reply_message = unwrapped_message.string();
//  }
//
//  return true;
//}
//
//bool FindPublicKeyForSenderId(const ContactsHandlerPtr& contacts_handler,
//                              const Identity& sender_id,
//                              asymm::PublicKey& sender_public_key) {
//  std::vector<Contact> contacts;
//  contacts_handler->OrderedContacts(&contacts, kAlphabetical, kConfirmed | kRequestSent);
//  if (contacts.empty()) {
//    LOG(kError) << "Quick exit. No contacts.";
//    return false;
//  }
//
//  for (auto& contact : contacts) {
//    if (contact.mpid_name == sender_id) {
//      sender_public_key = contact.mpid_public_key;
//      return true;
//    } else if (contact.inbox_name == sender_id) {
//      sender_public_key = contact.inbox_public_key;
//      return true;
//    }
//  }
//
//  return false;
//}
//
//void RoutingsHandler::OnRequestReceived(const Identity& receiver_id,
//                                        const NonEmptyString& wrapped_message,
//                                        const NodeId& sender_id,
//                                        const routing::ReplyFunctor& reply_functor) {
//  asio_service_.post([this, receiver_id, wrapped_message, sender_id, reply_functor] () {
//                       DoOnRequestReceived(receiver_id, wrapped_message, sender_id, reply_functor);
//                     });
//}
//
//void RoutingsHandler::DoOnRequestReceived(const Identity& receiver_id,
//                                          const NonEmptyString& wrapped_message,
//                                          const NodeId& sender_id,
//                                          const routing::ReplyFunctor& reply_functor) {
//  LOG(kInfo) << "receiver: " << DebugId(NodeId(receiver_id)) << ", sender: " << DebugId(sender_id);
//  if (stopped_) {
//    LOG(kWarning) << "Stopped. Dropping.";
//    return;
//  }
//
//  if (sender_id == NodeId()) {
//    LOG(kWarning) << "Void sender. Dropping.";
//    return;
//  }
//
//  std::shared_ptr<RoutingDetails> routing_details;
//  {
//    std::lock_guard<std::mutex> lock(routing_objects_mutex_);
//    auto it(routing_objects_.find(receiver_id));
//    if (it == routing_objects_.end()) {
//      LOG(kError) << "Failed to find ID locally. Silently drop. Should I even be writing this?";
//      return;
//    }
//    routing_details = it->second;
//  }
//
//  asymm::PublicKey sender_public_key;
//  asymm::PrivateKey receiver_private_key;
//  if (sender_id.string() == receiver_id.string()) {
//    sender_public_key = routing_details->fob.keys.public_key;
//    receiver_private_key = routing_details->fob.keys.private_key;
//  } else {
//    // Well, this is not gonna be easy
//    if (!FindPublicKeyForSenderId(session_.contacts_handler(routing_details->search_id),
//                                  Identity(sender_id.string()),
//                                  sender_public_key)) {
//      LOG(kError) << "Failed to find sender's pub key. Silent drop. Should I even be writing this?";
//      return;
//    }
//
//    receiver_private_key =
//        session_.passport().SignaturePacketDetails(passport::kMmid,
//                                                   true,
//                                                   routing_details->search_id).keys.private_key;
//  }
//
//  NonEmptyString unwrapped_message(UnwrapMessage(wrapped_message,
//                                                 sender_public_key,
//                                                 routing_details->fob.keys.private_key));
//
//  // Signal and assess response
//  std::string response;
//  if (validated_message_signal_(unwrapped_message, response)) {
//    NonEmptyString wrapped_message(WrapMessage(NonEmptyString(response),
//                                               sender_public_key,
//                                               receiver_private_key));
//    LOG(kInfo) << "About to invoke reply functor, response: " << response;
//    reply_functor(wrapped_message.string());
//  }
//}
//
//void RoutingsHandler::OnPublicKeyRequested(const NodeId& node_id,
//                                           const routing::GivePublicKeyFunctor& give_key) {
//  if (stopped_) {
//    LOG(kWarning) << "Stopped. Dropping.";
//    return;
//  }
//
//  std::string network_value;
//  {
//    std::lock_guard<std::mutex> lock(cs_mutex_);
//    network_value = chunk_store_->Get(SignaturePacketName(Identity(node_id.string())), Fob());
//  }
//
//  pca::SignedData signed_data;
//  if (!signed_data.ParseFromString(network_value)) {
//    LOG(kError) << "Failed to parse retrieved info as SignedData: " << DebugId(node_id);
//    return;
//  }
//
//  if (node_id.string() !=
//      crypto::Hash<crypto::SHA512>(signed_data.data() + signed_data.signature()).string()) {
//    LOG(kError) << "Failed to verify validity of info retrieved: " << DebugId(node_id);
//    return;
//  }
//
//
//  asymm::PublicKey public_key;
//  try {
//    public_key = asymm::DecodeKey(asymm::EncodedPublicKey(signed_data.data()));
//  }
//  catch(const std::exception& exception) {
//    LOG(kError) << "Did not find valid public key. Won't execute callback: " << exception.what();
//    return;
//  }
//
//  give_key(public_key);
//}
//
//NonEmptyString RoutingsHandler::WrapMessage(const NonEmptyString& message,
//                                         const asymm::PublicKey& receiver_public_key,
//                                         const asymm::PrivateKey& sender_private_key) {
//  return MessagePointToPoint(message, receiver_public_key, sender_private_key);
//}
//
//NonEmptyString RoutingsHandler::UnwrapMessage(const NonEmptyString& wrapped_message,
//                                              const asymm::PublicKey& sender_public_key,
//                                              const asymm::PrivateKey& receiver_private_key) {
//  std::string message;
//  if (PointToPointMessageValid(wrapped_message, sender_public_key, receiver_private_key, message))
//      return NonEmptyString(message);
//
//  return NonEmptyString();
//}
//
//}  // namespace lifestuff
//
//}  // namespace maidsafe
