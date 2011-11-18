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

#ifndef MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_FAKE_STORE_MANAGER_H_
#define MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_FAKE_STORE_MANAGER_H_

#include <memory>
#include <string>
#include <vector>

#include "boost/asio/io_service.hpp"
#include "boost/filesystem/path.hpp"
#include "boost/thread/thread.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/lifestuff/store_components/packet_manager.h"
#include "maidsafe/lifestuff/version.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 110
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif


namespace maidsafe {

class ChunkStore;
class ChunkValidation;

namespace lifestuff {

class DataHandler;
class GenericPacket;
class Session;

class FakeStoreManager : public PacketManager {
 public:
  explicit FakeStoreManager(std::shared_ptr<Session> session);
  virtual ~FakeStoreManager();
  int Close(bool cancel_pending_ops);
  bool KeyUnique(const std::string &key);
  void KeyUnique(const std::string &key,
                 const VoidFuncOneInt &cb);
  int GetPacket(const std::string &packet_name,
                std::vector<std::string> *results);
  void GetPacket(const std::string &packet_name,
                 const GetPacketFunctor &lpf);
  void StorePacket(const std::string &packet_name,
                   const std::string &value,
                   const VoidFuncOneInt &cb);
  void DeletePacket(const std::string &packet_name,
                    const std::string &value,
                    const VoidFuncOneInt &cb);
  void UpdatePacket(const std::string &packet_name,
                    const std::string &old_value,
                    const std::string &new_value,
                    const VoidFuncOneInt &cb);

 protected:
  ReturnCode Init(const boost::filesystem::path &buffered_chunk_store_dir);
  void ExecReturnCodeCallback(VoidFuncOneInt callback, ReturnCode return_code);
  void ExecReturnLoadPacketCallback(GetPacketFunctor callback,
                                    std::vector<std::string> results,
                                    ReturnCode return_code);
  bool ValidateGenericPacket(std::string ser_gp, std::string public_key);
  void CreateSerialisedSignedValue(const GenericPacket &data,
                                   std::string *ser_gp);

  boost::asio::io_service asio_service_;
  std::shared_ptr<boost::asio::io_service::work> work_;
  boost::thread_group thread_group_;
  std::shared_ptr<ChunkValidation> chunk_validation_;
  std::shared_ptr<ChunkStore> client_chunk_store_;
  std::shared_ptr<Session> session_;
  boost::filesystem::path temp_directory_path_;

 private:
  FakeStoreManager &operator=(const FakeStoreManager&);
  FakeStoreManager(const FakeStoreManager&);
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_FAKE_STORE_MANAGER_H_
