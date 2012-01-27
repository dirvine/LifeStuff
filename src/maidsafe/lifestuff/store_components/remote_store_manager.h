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

#ifndef MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_REMOTE_STORE_MANAGER_H_
#define MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_REMOTE_STORE_MANAGER_H_

#include <list>
#include <memory>
#include <string>
#include <vector>

#include "boost/asio/io_service.hpp"
#include "boost/filesystem/path.hpp"
#include "boost/thread/thread.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/common/rsa.h"
#include "maidsafe/pd/client/client_container.h"

#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/version.h"
#include "maidsafe/lifestuff/store_components/packet_manager.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 111
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif


namespace maidsafe {

namespace priv { class ChunkActionAuthority; }
namespace pd { class RemoteChunkStore; }

namespace lifestuff {

class Session;

class RemoteStoreManager : public PacketManager {
 public:
  RemoteStoreManager(std::shared_ptr<Session> session,
                     const std::string &db_directory = "");
  ~RemoteStoreManager();
  void Init(VoidFuncOneInt callback);
  int Close(bool cancel_pending_ops);

  bool KeyUnique(const std::string &key, const std::string &signing_key_id);
  void KeyUnique(const std::string &key,
                 const std::string &signing_key_id,
                 const VoidFuncOneInt &callback);
  int GetPacket(const std::string &packet_name,
                const std::string &signing_key_id,
                std::string *value);
  void GetPacket(const std::string &packet_name,
                 const std::string &signing_key_id,
                 const GetPacketFunctor &callback);
  void StorePacket(const std::string &packet_name,
                   const std::string &value,
                   const std::string &signing_key_id,
                   const VoidFuncOneInt &callback);
  void DeletePacket(const std::string &packet_name,
                    const std::string &signing_key_id,
                    const VoidFuncOneInt &callback);
  void ModifyPacket(const std::string &packet_name,
                    const std::string &value,
                    const std::string &signing_key_id,
                    const VoidFuncOneInt &callback);
  std::shared_ptr<ChunkStore> chunk_store() const;

  void FindAndExecCallback(const std::string &chunk_name,
                           const int &op_type,
                           const int &return_code);

 private:
  struct SignalToCallback;

//  ReturnCode Init(const boost::filesystem::path &buffered_chunk_store_dir);
  void ExecReturnCodeCallback(VoidFuncOneInt callback, ReturnCode return_code);
  void ExecReturnGetPacketCallback(GetPacketFunctor callback,
                                   std::string result,
                                   ReturnCode return_code);
  AlternativeStore::ValidationData GetValidationData(
      const std::string &packet_name,
      bool create_proof) const;

  // TODO(Fraser#5#): 2012-01-27 - Remove once RCS implements Update
  void TempExecStoreAfterDelete(
      const std::string &packet_name,
      const std::string &value,
      AlternativeStore::ValidationData validation_data,
      const VoidFuncOneInt &callback);

  pd::ClientContainer client_container_;
  std::shared_ptr<pd::RemoteChunkStore> client_chunk_store_;
  std::shared_ptr<Session> session_;
  std::shared_ptr<std::list<SignalToCallback>> sig_to_cb_list_;
  boost::mutex signal_to_cb_mutex_;

  RemoteStoreManager &operator=(const RemoteStoreManager&);
  RemoteStoreManager(const RemoteStoreManager&);
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_REMOTE_STORE_MANAGER_H_
