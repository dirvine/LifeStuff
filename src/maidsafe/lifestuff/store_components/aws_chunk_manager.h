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


#ifndef MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_AWS_CHUNK_MANAGER_H_
#define MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_AWS_CHUNK_MANAGER_H_

#include <memory>
#include <string>

#include "maidsafe/pd/client/chunk_manager.h"

namespace maidsafe {

class ChunkStore;

namespace lifestuff {

class AWSChunkManager : public pd::ChunkManager {
 public:
  explicit AWSChunkManager(std::shared_ptr<ChunkStore> chunk_store);

  void GetChunk(const std::string &name);
  void StoreChunk(const std::string &name);
  void DeleteChunk(const std::string &name);

 private:
  AWSChunkManager(const AWSChunkManager&);
  AWSChunkManager& operator=(const AWSChunkManager&);
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_AWS_CHUNK_MANAGER_H_
