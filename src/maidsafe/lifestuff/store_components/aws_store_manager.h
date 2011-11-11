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


#ifndef MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_AWS_STORE_MANAGER_H_
#define MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_AWS_STORE_MANAGER_H_

#include <memory>

#include "maidsafe/lifestuff/store_components/fake_store_manager.h"

namespace maidsafe {

class BufferedChunkStore;

namespace pd { class ChunkManager; }

namespace lifestuff {

class Session;

class AWSStoreManager : public FakeStoreManager {
 public:
  explicit AWSStoreManager(std::shared_ptr<Session> session);
  ~AWSStoreManager();
  void Init(VoidFuncOneInt callback);
 private:
  AWSStoreManager &operator=(const AWSStoreManager&);
  AWSStoreManager(const AWSStoreManager&);
  std::shared_ptr<BufferedChunkStore> buffered_chunk_store_;
  std::shared_ptr<pd::ChunkManager> chunk_manager_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_AWS_STORE_MANAGER_H_
