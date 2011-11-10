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
    : session_(session) {
}

AWSStoreManager::~AWSStoreManager() {
}

void AWSStoreManager::Init(VoidFuncOneInt callback) {
}

int AWSStoreManager::Close(bool /*cancel_pending_ops*/) { return kSuccess; }

bool AWSStoreManager::KeyUnique(const std::string &/*key*/) {
  return true;
}

void AWSStoreManager::KeyUnique(const std::string &/*key*/,
                                const VoidFuncOneInt &/*cb*/) {
}

int AWSStoreManager::GetPacket(const std::string &/*packet_name*/,
                               std::vector<std::string> * /*results*/) {
  return kSuccess;
}

void AWSStoreManager::GetPacket(const std::string &/*packetname*/,
                                const GetPacketFunctor &/*lpf*/) {
}

void AWSStoreManager::StorePacket(const std::string &/*packet_name*/,
                                  const std::string &/*value*/,
                                  const VoidFuncOneInt &/*cb*/) {
}

void AWSStoreManager::DeletePacket(const std::string &/*packet_name*/,
                                   const std::string &/*value*/,
                                   const VoidFuncOneInt &/*cb*/) {
}

void AWSStoreManager::UpdatePacket(const std::string &/*packet_name*/,
                                   const std::string &/*old_value*/,
                                   const std::string &/*new_value*/,
                                   const VoidFuncOneInt &/*cb*/) {
}


}  // namespace lifestuff

}  // namespace maidsafe
