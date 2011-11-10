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
      local_sm_dir_(db_directory) {
  if (local_sm_dir_.empty()) {
    boost::system::error_code error_code;
    fs::path temp_dir(fs::temp_directory_path(error_code));
    if (error_code) {
      DLOG(ERROR) << "Failed to get temporary directory";
    }
    local_sm_dir_ = (temp_dir / "LocalUserCredentials").string();
  }
}

LocalStoreManager::~LocalStoreManager() {}

void LocalStoreManager::Init(VoidFuncOneInt callback) {
  boost::system::error_code ec;
  if (!fs::exists(local_sm_dir_ + "/StoreChunks", ec)) {
    fs::create_directories(local_sm_dir_ + "/StoreChunks", ec);
    if (ec) {
      DLOG(INFO) << "Init - Failed to create directory";
      ExecReturnCodeCallback(callback, kStoreManagerInitError);
    }
  }

  if (!client_chunkstore_->Init(local_sm_dir_ + "/StoreChunks"))
    ExecReturnCodeCallback(callback, kStoreManagerInitError);

  ExecReturnCodeCallback(callback, kSuccess);
}

}  // namespace lifestuff

}  // namespace maidsafe
