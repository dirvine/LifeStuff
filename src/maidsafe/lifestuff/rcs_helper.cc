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

#include "maidsafe/lifestuff/rcs_helper.h"

#include <string>
#include <utility>
#include <vector>

#include "boost/asio/ip/udp.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_id.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#include "maidsafe/pd/client/node.h"
#include "maidsafe/pd/client/utils.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/return_codes.h"

namespace pca = maidsafe::priv::chunk_actions;
namespace bai = boost::asio::ip;

namespace maidsafe {

namespace lifestuff {

std::shared_ptr<priv::chunk_store::RemoteChunkStore> BuildChunkStore(
    const fs::path& base_dir,
    const std::vector<std::pair<std::string, uint16_t> >& endopints,  // NOLINT (Dan)
    std::shared_ptr<pd::Node>& node,
    const std::function<void(const int&)>& network_health_function) {
  node = SetupNode(base_dir, endopints, network_health_function);
  if (!node) {
    LOG(kError) << "Failed to start client node";
    return std::shared_ptr<pcs::RemoteChunkStore>();
  }

  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store(
      std::make_shared<pcs::RemoteChunkStore>(node->chunk_store(),
                                              node->chunk_manager(),
                                              node->chunk_action_authority()));
  return remote_chunk_store;
}

std::shared_ptr<pd::Node> SetupNode(
    const fs::path& base_dir,
    const std::vector<std::pair<std::string, uint16_t> >& endopints,  // NOLINT (Dan)
    const std::function<void(const int&)>& network_health_function) {
  auto node = std::make_shared<pd::Node>();
  node->set_on_network_status(network_health_function);

  std::vector<boost::asio::ip::udp::endpoint> peer_endpoints;
  for (auto& element : endopints) {
    boost::asio::ip::udp::endpoint endpoint;
    endpoint.address(boost::asio::ip::address::from_string(element.first));
    endpoint.port(element.second);
    peer_endpoints.push_back(endpoint);
  }

  int result(node->Start(base_dir / "buffered_chunk_store", peer_endpoints));
  if (result != kSuccess) {
    LOG(kError) << "Failed to start PD client node.  Result: " << result;
    return std::shared_ptr<pd::Node>();
  }

  LOG(kInfo) << "Started PD client node.";
  return node;
}

}  // namespace lifestuff

}  // namespace maidsafe
