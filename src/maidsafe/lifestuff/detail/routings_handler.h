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
 * @file  routings_handler.h
 * @brief Provides a class for processing messages using Routing.
 * @date  2012-09-03
 */

#ifndef MAIDSAFE_LIFESTUFF_ROUTINGS_HANDLER_H_
#define MAIDSAFE_LIFESTUFF_ROUTINGS_HANDLER_H_

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "maidsafe/common/rsa.h"

#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#include "maidsafe/routing/routing_api.h"

#include "maidsafe/lifestuff/lifestuff.h"

namespace maidsafe {

namespace lifestuff {

class Session;

class RoutingsHandler {
 public:
  explicit RoutingsHandler(priv::chunk_store::RemoteChunkStore& chunk_store,
                           Session& session,
                           const ValidatedMessageSignal& validated_message_signal);

  ~RoutingsHandler();

  bool AddRoutingObject(const asymm::Keys& owner_credentials,
                        const std::vector<std::pair<std::string, uint16_t>>& bootstrap_endpoints,
                        const std::string& search_id);

  bool Send(const std::string& source_id,
            const std::string& destination_id,
            const asymm::PublicKey& destination_public_key,
            const std::string& message,
            std::string* reply_message);

 private:
  struct RoutingDetails {
    RoutingDetails();
    RoutingDetails(const asymm::Keys& owner_credentials, const std::string& search_id);
    std::shared_ptr<routing::Routing> routing_object;
    int newtwork_health;
    asymm::Keys keys;
    std::shared_ptr<std::mutex> mutex;
    std::shared_ptr<std::condition_variable> condition_variable;
    std::string search_id;
  };

  priv::chunk_store::RemoteChunkStore& chunk_store_;
  std::map<std::string, RoutingDetails> routing_objects_;
  std::mutex routing_objects_mutex_;
  Session& session_;
  ValidatedMessageSignal validated_message_signal_;


  RoutingsHandler(const RoutingsHandler&);
  RoutingsHandler& operator=(const RoutingsHandler&);

  void OnRequestReceived(const std::string& owner_id,
                         const std::string& wrapped_message,
                         const routing::NodeId& group_claim,
                         const routing::ReplyFunctor& reply_functor);

  void OnPublicKeyRequested(const routing::NodeId& node_id,
                            const routing::GivePublicKeyFunctor& give_key);

  std::string WrapMessage(const std::string &message,
                          const asymm::PublicKey &receiver_public_key,
                          const asymm::PrivateKey &sender_private_key);

  bool UnwrapMessage(const std::string& wrapped_message,
                     const asymm::PublicKey& sender_public_key,
                     const asymm::PrivateKey& receiver_private_key,
                     std::string& final_message);
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_ROUTINGS_HANDLER_H_
