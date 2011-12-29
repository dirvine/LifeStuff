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
#include "maidsafe/private/chunk_actions/chunk_action_authority.h"

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

  boost::system::error_code error_code;
  if (!fs::exists(buffered_chunk_store_dir, error_code)) {
    fs::create_directories(buffered_chunk_store_dir, error_code);
    if (error_code) {
      DLOG(ERROR) << "Failed to create " << buffered_chunk_store_dir
                  << ": " << error_code.message();
      return;
    }
  }

  std::shared_ptr<FileChunkStore> cstore(new FileChunkStore);
  cstore->Init(buffered_chunk_store_dir);
  client_chunk_store_.reset(new ThreadsafeChunkStore(cstore));
  chunk_action_authority_.reset(
      new priv::ChunkActionAuthority(client_chunk_store_));
  ExecReturnCodeCallback(callback, kSuccess);
}

}  // namespace lifestuff

}  // namespace maidsafe
