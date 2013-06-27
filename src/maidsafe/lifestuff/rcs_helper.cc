/* Copyright 2011 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

//#include "maidsafe/lifestuff/rcs_helper.h"
//
//#include <string>
//#include <utility>
//#include <vector>
//
//#include "boost/asio/ip/udp.hpp"
//
//#include "maidsafe/common/log.h"
//#include "maidsafe/common/utils.h"
//
//#include "maidsafe/private/chunk_actions/chunk_pb.h"
//#include "maidsafe/private/chunk_actions/chunk_id.h"
//#include "maidsafe/private/chunk_store/remote_chunk_store.h"
//
//#include "maidsafe/pd/client/node.h"
//#include "maidsafe/pd/client/utils.h"
//
//#include "maidsafe/lifestuff/lifestuff.h"
//#include "maidsafe/lifestuff/return_codes.h"
//
//namespace pca = maidsafe::priv::chunk_actions;
//namespace bai = boost::asio::ip;
//
//namespace maidsafe {
//
//namespace lifestuff {
//
//std::shared_ptr<priv::chunk_store::RemoteChunkStore> BuildChunkStore(
//    const fs::path& base_dir,
//    const std::vector<std::pair<std::string, uint16_t> >& endopints,  // NOLINT (Dan)
//    std::shared_ptr<pd::Node>& node,
//    const std::function<void(const int&)>& network_health_function) {
//  node = SetupNode(base_dir, endopints, network_health_function);
//
//  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store(
//      std::make_shared<pcs::RemoteChunkStore>(node->chunk_store(),
//                                              node->chunk_manager(),
//                                              node->chunk_action_authority()));
//  return remote_chunk_store;
//}
//
//std::shared_ptr<pd::Node> SetupNode(
//    const fs::path& base_dir,
//    const std::vector<std::pair<std::string, uint16_t> >& endopints,  // NOLINT (Dan)
//    const std::function<void(const int&)>& network_health_function) {
//  auto node = std::make_shared<pd::Node>();
//  node->set_on_network_status(network_health_function);
//
//  std::vector<boost::asio::ip::udp::endpoint> peer_endpoints;
//  for (auto& element : endopints) {
//    boost::asio::ip::udp::endpoint endpoint;
//    endpoint.address(boost::asio::ip::address::from_string(element.first));
//    endpoint.port(element.second);
//    peer_endpoints.push_back(endpoint);
//  }
//
//  int result(node->Start(base_dir / "buffered_chunk_store", peer_endpoints));
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to start PD client node.  Result: " << result;
//    throw std::runtime_error("failed to start node");
//  }
//
//  LOG(kInfo) << "Started PD client node.";
//  return node;
//}
//
//}  // namespace lifestuff
//
//}  // namespace maidsafe
