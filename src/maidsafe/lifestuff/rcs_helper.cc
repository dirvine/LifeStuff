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

#include <fstream>  // NOLINT (Fraser)
#include <iostream>  // NOLINT (Fraser)
#include <istream>  // NOLINT (Fraser)
#include <ostream>  // NOLINT (Fraser)
#include <string>
#include <vector>

#include "boost/archive/text_iarchive.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/pd/client/node.h"
#include "maidsafe/pd/client/utils.h"
#endif

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/return_codes.h"

namespace pca = maidsafe::priv::chunk_actions;
namespace bai = boost::asio::ip;

namespace maidsafe {

namespace lifestuff {

#ifdef LOCAL_TARGETS_ONLY
std::shared_ptr<pcs::RemoteChunkStore> BuildChunkStore(const fs::path& buffered_chunk_store_path,
                                                       const fs::path& local_chunk_manager_path,
                                                       boost::asio::io_service& asio_service) {
  boost::system::error_code error_code;
  fs::create_directories(local_chunk_manager_path / "lock", error_code);
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store(
      pcs::CreateLocalChunkStore(buffered_chunk_store_path,
                                 local_chunk_manager_path,
                                 local_chunk_manager_path / "lock",
                                 asio_service));
  return remote_chunk_store;
}
#else
std::shared_ptr<pcs::RemoteChunkStore> BuildChunkStore(const fs::path& base_dir,
                                                       std::shared_ptr<pd::Node>& node) {
  node = SetupNode(base_dir);
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store(
      new pcs::RemoteChunkStore(node->chunk_store(),
                                node->chunk_manager(),
                                node->chunk_action_authority()));
  remote_chunk_store->SetMaxActiveOps(32);
  return remote_chunk_store;
}

std::shared_ptr<pd::Node> SetupNode(const fs::path& base_dir) {
  auto node = std::make_shared<pd::Node>();

  int result(node->Start(base_dir / "buffered_chunk_store"));
  if (result != kSuccess) {
    LOG(kError) << "Failed to start PD node.  Result: " << result;
    return nullptr;
  }

  LOG(kInfo) << "Started PD node.";
  return node;
}
#endif

}  // namespace lifestuff

}  // namespace maidsafe
