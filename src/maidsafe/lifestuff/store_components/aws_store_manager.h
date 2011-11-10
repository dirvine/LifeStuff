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

#include <string>
#include <vector>

#include "maidsafe/lifestuff/store_components/packet_manager.h"


namespace maidsafe {

namespace lifestuff {

class Session;

class AWSStoreManager : public PacketManager {
 public:
  explicit AWSStoreManager(std::shared_ptr<Session> session);
  ~AWSStoreManager();
  void Init(VoidFuncOneInt callback);
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

 private:
  AWSStoreManager &operator=(const AWSStoreManager&);
  AWSStoreManager(const AWSStoreManager&);

  std::shared_ptr<Session> session_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_AWS_STORE_MANAGER_H_
