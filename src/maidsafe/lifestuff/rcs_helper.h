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

#ifndef MAIDSAFE_LIFESTUFF_RCS_HELPER_H_
#define MAIDSAFE_LIFESTUFF_RCS_HELPER_H_

#include <memory>
#include <string>
#include <vector>
#include <utility>

#include "boost/asio.hpp"
#include "boost/filesystem/path.hpp"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv { namespace chunk_store { class RemoteChunkStore; } }

namespace pcs = maidsafe::priv::chunk_store;

#ifndef LOCAL_TARGETS_ONLY
namespace dht { class Contact; }
namespace pd { class Node; }
#endif

namespace lifestuff {

#ifdef LOCAL_TARGETS_ONLY
std::shared_ptr<pcs::RemoteChunkStore> BuildChunkStore(const fs::path& buffered_chunk_store_path,
                                                       const fs::path& local_chunk_manager_path,
                                                       boost::asio::io_service& asio_service);
#else
std::shared_ptr<pcs::RemoteChunkStore> BuildChunkStore(
    const fs::path& base_dir,
    const std::vector<std::pair<std::string, uint16_t>>& endpoints,  // NOLINT (Dan)
    std::shared_ptr<pd::Node>& node,
    const std::function<void(const int&)> network_health_function);

std::shared_ptr<pd::Node> SetupNode(
    const fs::path& base_dir,
    const std::vector<std::pair<std::string, uint16_t>>& endpoints,  // NOLINT (Dan)
    const std::function<void(const int&)> network_health_function);
#endif

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_RCS_HELPER_H_
