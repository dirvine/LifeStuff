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

#include "maidsafe/lifestuff/store_components/aws_store_manager.h"

#include "maidsafe/common/buffered_chunk_store.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/store_components/aws_remote_chunk_store.h"

namespace maidsafe {

namespace lifestuff {

AWSStoreManager::AWSStoreManager(std::shared_ptr<Session> session)
    : FakeStoreManager(session) {}

AWSStoreManager::~AWSStoreManager() {}

void AWSStoreManager::Init(VoidFuncOneInt callback) {
  fs::path buffered_chunk_store_dir(temp_directory_path_ / "StoreChunks");
  ReturnCode result = FakeStoreManager::Init(buffered_chunk_store_dir);
  if (result != kSuccess)
    return ExecReturnCodeCallback(callback, result);

  std::shared_ptr<BufferedChunkStore> buffered_chunk_store(
      new BufferedChunkStore(chunk_validation_, asio_service_));
  if (!buffered_chunk_store->Init(buffered_chunk_store_dir.string())) {
    DLOG(ERROR) << "Failed to initialise buffered_chunk_store";
    return ExecReturnCodeCallback(callback, kStoreManagerInitError);
  }

  client_chunk_store_ = std::shared_ptr<AWSRemoteChunkStore>(
      new AWSRemoteChunkStore(buffered_chunk_store,
          std::shared_ptr<pd::ChunkManager>(
              new AWSChunkManager(buffered_chunk_store))));
  ExecReturnCodeCallback(callback, kSuccess);
}

}  // namespace lifestuff

}  // namespace maidsafe
