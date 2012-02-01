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


#ifndef MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_LOCAL_CHUNK_MANAGER_H_
#define MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_LOCAL_CHUNK_MANAGER_H_

#include <memory>
#include <string>

#include "maidsafe/pd/client/chunk_manager.h"

namespace maidsafe {

class ChunkStore;
namespace priv { class ChunkActionAuthority; }

namespace lifestuff {

class LocalChunkManager : public pd::ChunkManager {
 public:
  LocalChunkManager(std::shared_ptr<ChunkStore> normal_local_chunk_store,
                    const fs::path &simulation_directory);
  ~LocalChunkManager();

  void GetChunk(const std::string &name,
                const rsa::Identity &owner_key_id,
                const rsa::PublicKey &owner_public_key,
                const std::string &ownership_proof);
  void StoreChunk(const std::string &name,
                  const rsa::Identity &owner_key_id,
                  const rsa::PublicKey &owner_public_key);
  void DeleteChunk(const std::string &name,
                   const rsa::Identity &owner_key_id,
                   const rsa::PublicKey &owner_public_key,
                   const std::string &ownership_proof);
//  void ModifyChunk(const std::string &name);

 private:
  LocalChunkManager(const LocalChunkManager&);
  LocalChunkManager& operator=(const LocalChunkManager&);

  std::shared_ptr<ChunkStore> simulation_chunk_store_;
  std::shared_ptr<priv::ChunkActionAuthority> simulation_chunk_action_authority_;  // NOLINT(Dan)
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_LOCAL_CHUNK_MANAGER_H_
