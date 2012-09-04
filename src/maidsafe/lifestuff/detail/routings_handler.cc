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

#include "maidsafe/lifestuff/detail/routings_handler.h"

#include <chrono>
#include <utility>
#include <vector>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#include "maidsafe/routing/node_id.h"
#include "maidsafe/routing/return_codes.h"

#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

const int kMinAcceptableClientHealth(75);

RoutingsHandler::RoutingDetails::RoutingDetails()
    : routing_object(),
      newtwork_health(-1),
      keys(),
      mutex(std::make_shared<std::mutex>()),
      condition_variable(std::make_shared<std::condition_variable>()),
      search_id() {}

RoutingsHandler::RoutingDetails::RoutingDetails(const asymm::Keys& owner_credentials,
                                                const std::string& search_id)
    : routing_object(std::make_shared<routing::Routing>(owner_credentials, true)),
      newtwork_health(-1),
      keys(owner_credentials),
      mutex(std::make_shared<std::mutex>()),
      condition_variable(std::make_shared<std::condition_variable>()),
      search_id(search_id) {}

RoutingsHandler::RoutingsHandler(priv::chunk_store::RemoteChunkStore& chunk_store,
                                 Session& session,
                                 const ValidatedMessageSignal& validated_message_signal)
    : chunk_store_(chunk_store),
      routing_objects_(),
      routing_objects_mutex_(),
      session_(session),
      validated_message_signal_(validated_message_signal) {}

RoutingsHandler::~RoutingsHandler() {}

bool RoutingsHandler::AddRoutingObject(
    const asymm::Keys& owner_credentials,
    const std::vector<std::pair<std::string, uint16_t>>& bootstrap_endpoints,  // NOLINT (Dan)
    const std::string& search_id) {
  RoutingDetails routing_details(owner_credentials, search_id);

  // Bootstrap endpoints to udp endpoints
  std::vector<boost::asio::ip::udp::endpoint> peer_endpoints;
  for (auto& element : bootstrap_endpoints) {
    boost::asio::ip::udp::endpoint ep;
    ep.address(boost::asio::ip::address::from_string(element.first));
    ep.port(element.second);
    peer_endpoints.push_back(ep);
  }

  // Functors
  routing::Functors functors;
  functors.message_received = [&, routing_details] (const std::string& wrapped_message,
                                                    const routing::NodeId& group_claim,
                                                    const routing::ReplyFunctor& reply_functor) {
                                OnRequestReceived(routing_details.keys.identity,
                                                  wrapped_message,
                                                  group_claim,
                                                  reply_functor);
                              };

  functors.request_public_key = [this] (const routing::NodeId& node_id,
                                        const routing::GivePublicKeyFunctor& give_key) {
                                  OnPublicKeyRequested(node_id, give_key);
                                };
  // Network health
  functors.network_status = [&] (const int& network_health) {
                              std::unique_lock<std::mutex> health_loch(*routing_details.mutex);
                              routing_details.newtwork_health = network_health;
                            };

  routing_details.routing_object->Join(functors, peer_endpoints);
  {
    std::unique_lock<std::mutex> health_loch(*routing_details.mutex);
    routing_details.condition_variable->wait_for(health_loch,
                                                 std::chrono::seconds(5),
                                                 [&] ()->bool {
                                                   // TODO(Team): Remove this blatantly arbitrary
                                                   //             network level
                                                   return routing_details.newtwork_health != -1 &&
                                                          routing_details.newtwork_health >=
                                                              kMinAcceptableClientHealth;
                                                 });
    if (routing_details.newtwork_health == routing::kNotJoined ||
        routing_details.newtwork_health < kMinAcceptableClientHealth) {
      LOG(kError) << "Failed to join this routing object.";
      return false;
    }
  }

  auto result(routing_objects_.insert(std::make_pair(owner_credentials.identity, routing_details)));
  if (!result.second) {
    LOG(kError) << "Failed to insert MAID to map.";
    return false;
  }

  return true;
}

bool RoutingsHandler::Send(const std::string& source_id,
                           const std::string& destination_id,
                           const asymm::PublicKey& destination_public_key,
                           const std::string& message,
                           std::string* reply_message) {
  RoutingDetails routing_details;
  {
    std::unique_lock<std::mutex> loch(routing_objects_mutex_);
    auto it(routing_objects_.find(source_id));
    if (it == routing_objects_.end()) {
      LOG(kError) << "No such ID to send message: " << Base64Substr(source_id);
      return false;
    }
    routing_details = it->second;
  }

  std::string wrapped_message(WrapMessage(message,
                                          destination_public_key,
                                          routing_details.keys.private_key));
  if (wrapped_message.empty()) {
    LOG(kError) << "Failed to wrap message: " <<  Base64Substr(source_id);
    return false;
  }

  routing::ResponseFunctor response_functor;
  std::mutex message_mutex;
  std::condition_variable condition_variable;
  std::string message_from_routing;
  bool message_received(false);
  if (reply_message) {
      response_functor = [&] (const std::vector<std::string>& messages) {
                           std::unique_lock<std::mutex> message_loch(message_mutex);
                           if (!messages.empty())
                             message_from_routing = messages.front();
                           message_received = true;
                           condition_variable.notify_one();
                         };
  }

  routing_details.routing_object->Send(routing::NodeId(destination_id),
                                       routing::NodeId(),
                                       wrapped_message,
                                       response_functor,
                                       boost::posix_time::seconds(10),
                                       true,
                                       false);

  if (reply_message) {
    std::unique_lock<std::mutex> message_loch(message_mutex);
    if (!condition_variable.wait_for(message_loch,
                                     std::chrono::seconds(10),
                                     [&] ()->bool { return message_received; })) {
      LOG(kError) << "Timed out waiting for response from " << Base64Substr(destination_id);
      return false;
    }
    if (message_from_routing.empty()) {
      LOG(kError) << "Message from " << Base64Substr(destination_id) << " is empty. "
                  << "Probably timed out in routing.";
      return false;
    }

    std::string unwrapped_message;
    if (!UnwrapMessage(message_from_routing,
                       destination_public_key,
                       routing_details.keys.private_key,
                       unwrapped_message)) {
      LOG(kError) << "Message from " << Base64Substr(destination_id) << " is not decryptable. "
                  << "Probably corrupted.";
      return false;
    }

    *reply_message = unwrapped_message;
  }

  return true;
}

bool FindPublicKeyForSenderId(const ContactsHandlerPtr& contacts_handler,
                              const std::string& sender_id,
                              asymm::PublicKey& sender_public_key) {
  std::vector<Contact> contacts;
  contacts_handler->OrderedContacts(&contacts, kAlphabetical, kConfirmed | kRequestSent);
  if (contacts.empty()) {
    LOG(kError) << "Quick exit. No contacts.";
    return false;
  }

  for (auto& contact : contacts) {
    if (contact.mpid_name == sender_id) {
      sender_public_key = contact.mpid_public_key;
      return true;
    } else if (contact.inbox_name == sender_id) {
      sender_public_key = contact.inbox_public_key;
      return true;
    }
  }

  return false;
}

void RoutingsHandler::OnRequestReceived(const std::string& receiver_id,
                                        const std::string& wrapped_message,
                                        const routing::NodeId& sender_id,
                                        const routing::ReplyFunctor& reply_functor) {
  RoutingDetails routing_details;
  {
    std::unique_lock<std::mutex> loch(routing_objects_mutex_);
    auto it(routing_objects_.find(receiver_id));
    if (it == routing_objects_.end()) {
      LOG(kError) << "Failed to find ID locally. Silently drop. Should I even be writing this?";
      return;
    }
    routing_details = it->second;
  }

  asymm::PublicKey sender_public_key;
  if (sender_id.String() == receiver_id) {
    sender_public_key = routing_details.keys.public_key;
  } else {
    // Well, this is not gonna be easy
    if (!FindPublicKeyForSenderId(session_.contacts_handler(routing_details.search_id),
                                  sender_id.String(),
                                  sender_public_key)) {
      LOG(kError) << "Failed to find sender's pub key. Silent drop. Should I even be writing this?";
      return;
    }
  }

  std::string unwrapped_message;
  if (!UnwrapMessage(wrapped_message,
                     sender_public_key,
                     routing_details.keys.private_key,
                     unwrapped_message)) {
    LOG(kError) << "Failed to unwrap. Silently drop. Should I even be writing this?";
    return;
  }

  // Signal and assess response
  std::string response;
  if (validated_message_signal_(unwrapped_message, response))
    reply_functor(response);
}

void RoutingsHandler::OnPublicKeyRequested(const routing::NodeId& node_id,
                                           const routing::GivePublicKeyFunctor& give_key) {
  std::string network_name(node_id.String() + std::string(1, pca::kSignaturePacket));
  std::string network_value(chunk_store_.Get(network_name));

  asymm::PublicKey public_key;
  pca::SignedData signed_data;
  if (!signed_data.ParseFromString(network_value)) {
    LOG(kError) << "Failed to parse retrieved info as SignedData";
    give_key(public_key);
    return;
  }

  if (node_id.String() !=
      crypto::Hash<crypto::SHA512>(signed_data.data() + signed_data.signature())) {
    LOG(kError) << "Failed to verify validity of info retrieved.";
    give_key(public_key);
    return;
  }

  asymm::DecodePublicKey(signed_data.data(), &public_key);
  if (!asymm::ValidateKey(public_key)) {
    LOG(kError) << "Failed to decode key.";
    give_key(public_key);
    return;
  }

  give_key(public_key);
}

std::string RoutingsHandler::WrapMessage(const std::string& message,
                                         const asymm::PublicKey& receiver_public_key,
                                         const asymm::PrivateKey& sender_private_key) {
  std::string return_message;
  if (!MessagePointToPoint(message,
                           receiver_public_key,
                           sender_private_key,
                           return_message))
    LOG(kError) << "Failed to wrap message.";
  return return_message;
}

bool RoutingsHandler::UnwrapMessage(const std::string& wrapped_message,
                                    const asymm::PublicKey& sender_public_key,
                                    const asymm::PrivateKey& receiver_private_key,
                                    std::string& final_message) {
  return PointToPointMessageValid(wrapped_message,
                                  sender_public_key,
                                  receiver_private_key,
                                  final_message);
}

}  // namespace lifestuff

}  // namespace maidsafe
