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

#ifndef MAIDSAFE_LIFESTUFF_LOCALSTOREMANAGER_H_
#define MAIDSAFE_LIFESTUFF_LOCALSTOREMANAGER_H_

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "boost/filesystem.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/lifestuff/packet_manager.h"


namespace fs3 = boost::filesystem3;

namespace maidsafe {

class BufferedChunkStore;
class ChunkValidation;

namespace lifestuff {

class Session;

class LocalStoreManager : public PacketManager {
 public:
  explicit LocalStoreManager(const fs3::path &db_directory,
                             std::shared_ptr<Session> ss);
  virtual ~LocalStoreManager();
  virtual void Init(VoidFuncOneInt callback, const boost::uint16_t &port);
  virtual int Close(bool cancel_pending_ops);
  virtual void CleanUpTransport() {}
  virtual void StopRvPing() {}
  virtual bool NotDoneWithUploading();
  virtual bool KeyUnique(const std::string &key, bool check_local);
  virtual void KeyUnique(const std::string &key,
                         bool check_local,
                         const VoidFuncOneInt &cb);

  // Packets
  virtual int GetPacket(const std::string &packet_name,
                        std::vector<std::string> *results);
  virtual void GetPacket(const std::string &packet_name,
                         const GetPacketFunctor &lpf);
  virtual void StorePacket(const std::string &packet_name,
                           const std::string &value,
                           passport::PacketType system_packet_type,
                           DirType dir_type,
                           const std::string &msid,
                           const VoidFuncOneInt &cb);
  // Deletes all values for the specified key
  virtual void DeletePacket(const std::string &packet_name,
                            const std::vector<std::string> values,
                            passport::PacketType system_packet_type,
                            DirType dir_type,
                            const std::string &msid,
                            const VoidFuncOneInt &cb);
  virtual void UpdatePacket(const std::string &packet_name,
                            const std::string &old_value,
                            const std::string &new_value,
                            passport::PacketType system_packet_type,
                            DirType dir_type,
                            const std::string &msid,
                            const VoidFuncOneInt &cb);
 private:
  LocalStoreManager &operator=(const LocalStoreManager&);
  LocalStoreManager(const LocalStoreManager&);

  bool ValidateGenericPacket(std::string ser_gp, std::string public_key);
  void CreateSerialisedSignedValue(const std::string &value,
                                   const std::string &private_key,
                                   std::string *ser_gp);
  void ExecuteReturnSignal(const std::string &chunkname, ReturnCode rc);
  void ExecReturnCodeCallback(VoidFuncOneInt cb, ReturnCode rc);
  void ExecReturnLoadPacketCallback(GetPacketFunctor cb,
                                    std::vector<std::string> results,
                                    ReturnCode rc);

  const boost::uint8_t K_;
  const boost::uint16_t kUpperThreshold_;
  boost::mutex mutex_;
  std::string local_sm_dir_;
  boost::asio::io_service service_;
  std::shared_ptr<boost::asio::io_service::work> work_;
  boost::thread_group thread_group_;
  std::shared_ptr<ChunkValidation> chunk_validation_;
  std::shared_ptr<BufferedChunkStore> client_chunkstore_;
  std::shared_ptr<Session> ss_;
  std::set<std::string> chunks_pending_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LOCALSTOREMANAGER_H_
