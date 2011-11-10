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

namespace maidsafe {

namespace lifestuff {

AWSStoreManager::AWSStoreManager(std::shared_ptr<Session> session)
    : FakeStoreManager(session) {}

AWSStoreManager::~AWSStoreManager() {}

void AWSStoreManager::Init(VoidFuncOneInt callback) {
                        //  if (!client_chunkstore_->Init(local_sm_dir_ + "/StoreChunks"))
                        //    ExecReturnCodeCallback(callback, kStoreManagerInitError);

  ExecReturnCodeCallback(callback, kSuccess);
}

}  // namespace lifestuff

}  // namespace maidsafe
