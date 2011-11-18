/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Nov 13, 2008
 *      Author: Team
 */

#include "maidsafe/lifestuff/store_components/local_store_manager.h"

#include "boost/filesystem.hpp"

#include "maidsafe/common/buffered_chunk_store.h"

#include "maidsafe/lifestuff/log.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

LocalStoreManager::LocalStoreManager(std::shared_ptr<Session> session,
                                     const std::string &db_directory)
    : FakeStoreManager(session),
      local_store_manager_dir_(!db_directory.empty() ? db_directory :
                               temp_directory_path_ / "LocalUserCredentials") {}

LocalStoreManager::~LocalStoreManager() {}

void LocalStoreManager::Init(VoidFuncOneInt callback) {
  fs::path buffered_chunk_store_dir(local_store_manager_dir_ / "StoreChunks");
  ReturnCode result = FakeStoreManager::Init(buffered_chunk_store_dir);
  if (result != kSuccess)
    return ExecReturnCodeCallback(callback, result);

  std::shared_ptr<BufferedChunkStore> buffered_chunk_store(new
      BufferedChunkStore(chunk_validation_, asio_service_));
  if (!buffered_chunk_store->Init(buffered_chunk_store_dir.string())) {
    DLOG(ERROR) << "Failed to initialise client_chunk_store_";
    return ExecReturnCodeCallback(callback, kStoreManagerInitError);
  }
  client_chunk_store_ = buffered_chunk_store;
  ExecReturnCodeCallback(callback, kSuccess);
}

}  // namespace lifestuff

}  // namespace maidsafe
