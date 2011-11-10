/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Manages data storage to local database (for testing)
* Version:      1.0
* Created:      2009-01-29-00.06.15
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
* Company:      maidsafe.net limited
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

#ifndef MAIDSAFE_LIFESTUFF_LOCAL_STORE_MANAGER_H_
#define MAIDSAFE_LIFESTUFF_LOCAL_STORE_MANAGER_H_

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "boost/asio/io_service.hpp"
#include "boost/thread.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/lifestuff/store_components/packet_manager.h"

namespace maidsafe {

class BufferedChunkStore;
class ChunkValidation;

namespace lifestuff {

class DataHandler;
class GenericPacket;
class Session;

class LocalStoreManager : public PacketManager {
 public:
  LocalStoreManager(std::shared_ptr<Session> session,
                    const std::string &db_directory = "");
  ~LocalStoreManager();
  void Init(VoidFuncOneInt callback);
  int Close(bool cancel_pending_ops);

  // Packets
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

 private:
  LocalStoreManager &operator=(const LocalStoreManager&);
  LocalStoreManager(const LocalStoreManager&);

  bool ValidateGenericPacket(std::string ser_gp, std::string public_key);
  void CreateSerialisedSignedValue(const GenericPacket &data,
                                   std::string *ser_gp);

  std::string local_sm_dir_;
  boost::asio::io_service service_;
  std::shared_ptr<boost::asio::io_service::work> work_;
  boost::thread_group thread_group_;
  std::shared_ptr<ChunkValidation> chunk_validation_;
  std::shared_ptr<BufferedChunkStore> client_chunkstore_;
  std::shared_ptr<Session> session_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LOCAL_STORE_MANAGER_H_
