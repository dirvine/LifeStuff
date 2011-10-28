/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Nov 13, 2008
 *      Author: Team
 */

#include "maidsafe/lifestuff/localstoremanager.h"

#include "boost/filesystem.hpp"
#include "boost/scoped_ptr.hpp"

#include "maidsafe/common/buffered_chunk_store.h"
#include "maidsafe/common/chunk_validation.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/dht/contact.h"

#include "maidsafe/pki/maidsafe_validator.h"

#include "maidsafe/lifestuff/clientutils.h"
#include "maidsafe/lifestuff/data_handler.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/session.h"

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4244)
#endif
#include "maidsafe/lifestuff/lifestuff_messages.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

namespace {

void PrintDebugInfo(const std::string &packet_name,
                    const std::string &value1,
                    const std::string &value2,
                    const std::string &op_type,
                    passport::PacketType system_packet_type) {
  std::string packet_type(maidsafe::passport::DebugString(system_packet_type));
  if (value2.empty())
    DLOG(WARNING) << "LSM::" << op_type << " - " << packet_type
                  << " - <key, value>(" << HexSubstr(packet_name) << ", "
                  << HexSubstr(value1) << ")" << std::endl;
  else
    DLOG(WARNING) << "LSM::" << op_type << " - " << packet_type << " - <key>("
                  << HexSubstr(packet_name) << ") value("
                  << HexSubstr(value1) << " --> " << HexSubstr(value2)
                  << ")" << std::endl;
}

void ExecReturnCodeCallback(VoidFuncOneInt cb, ReturnCode rc) {
  boost::thread t(cb, rc);
}

void ExecReturnLoadPacketCallback(GetPacketFunctor cb,
                                  std::vector<std::string> results,
                                  ReturnCode rc) {
  boost::thread t(cb, results, rc);
}

class VeritasChunkValidation : public ChunkValidation {
 public:
  VeritasChunkValidation() : ChunkValidation() {}
  ~VeritasChunkValidation() {}

  bool ValidName(const std::string &/*name*/) { return true; }
  bool Hashable(const std::string &/*name*/) { return true; }
  bool ValidChunk(const std::string &/*name*/, const std::string &/*content*/) {
    return true;
  }
  bool ValidChunk(const std::string &/*name*/, const fs::path &/*path*/) {
    return true;
  }

 private:
  VeritasChunkValidation(const VeritasChunkValidation&);
  VeritasChunkValidation& operator=(const VeritasChunkValidation&);
};

}  // namespace


LocalStoreManager::LocalStoreManager(const fs::path &db_directory,
                                     std::shared_ptr<Session> ss)
    : local_sm_dir_(db_directory.string()),
      service_(),
      work_(),
      thread_group_(),
      chunk_validation_(new VeritasChunkValidation()),
      client_chunkstore_(new BufferedChunkStore(true,
                                                chunk_validation_,
                                                service_)),
      ss_(ss) {
  work_.reset(new boost::asio::io_service::work(service_));
  for (int i = 0; i < 3; ++i) {
    thread_group_.create_thread(
        std::bind(static_cast<std::size_t(boost::asio::io_service::*)()>
                      (&boost::asio::io_service::run), &service_));
  }
}

LocalStoreManager::~LocalStoreManager() {
  work_.reset();
  service_.stop();
  thread_group_.join_all();
}

void LocalStoreManager::Init(VoidFuncOneInt callback, const boost::uint16_t&) {
  boost::system::error_code ec;
  if (!fs::exists(local_sm_dir_ + "/StoreChunks", ec)) {
    fs::create_directories(local_sm_dir_ + "/StoreChunks", ec);
    if (ec) {
      DLOG(INFO) << "Init - Failed to create directory";
      ExecReturnCodeCallback(callback, kStoreManagerInitError);
    }
  }

  if (!client_chunkstore_->Init(local_sm_dir_ + "/StoreChunks"))
    ExecReturnCodeCallback(callback, kStoreManagerInitError);

  ExecReturnCodeCallback(callback, kSuccess);
}

int LocalStoreManager::Close(bool /*cancel_pending_ops*/) { return kSuccess; }

bool LocalStoreManager::KeyUnique(const std::string &key, bool) {
  return !client_chunkstore_->Has(key);
}

void LocalStoreManager::KeyUnique(const std::string &key,
                                  bool /*check_local*/,
                                  const VoidFuncOneInt &cb) {
  if (!client_chunkstore_->Has(key))
    ExecReturnCodeCallback(cb, kKeyUnique);
  else
    ExecReturnCodeCallback(cb, kKeyNotUnique);
}

int LocalStoreManager::GetPacket(const std::string &packet_name,
                                 std::vector<std::string> *results) {
  std::string packet(client_chunkstore_->Get(packet_name));
  if (packet.empty())
    return kFindValueFailure;

  results->push_back(packet);

  return kSuccess;
}

void LocalStoreManager::GetPacket(const std::string &packetname,
                                  const GetPacketFunctor &lpf) {
  std::vector<std::string> results;
  ReturnCode rc(static_cast<ReturnCode>(GetPacket(packetname, &results)));
  ExecReturnLoadPacketCallback(lpf, results, rc);
}

void LocalStoreManager::DeletePacket(const std::string &packet_name,
                                     const std::vector<std::string> values,
                                     passport::PacketType system_packet_type,
                                     DirType dir_type, const std::string &msid,
                                     const VoidFuncOneInt &cb) {
  PrintDebugInfo(packet_name, values.empty() ? "" : values.at(0), "",
                 "DeletePacket", system_packet_type);
  std::string key_id, public_key, public_key_signature, private_key;
  ClientUtils client_utils(ss_);
  client_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid,
                                      &key_id, &public_key,
                                      &public_key_signature, &private_key);
//  pki::MaidsafeValidator msv;
//  if (!msv.ValidateSignerId(key_id, public_key, public_key_signature)) {
//    ExecReturnCodeCallback(cb, kDeletePacketFailure);
//    return;
//  }

  std::string current_packet(client_chunkstore_->Get(packet_name));
  if (current_packet.empty()) {  // packet doesn't exist on net
    ExecReturnCodeCallback(cb, kSuccess);
  } else {
    GenericPacket sv;
    if (!sv.ParseFromString(current_packet)) {
      DLOG(INFO) << "DeletePacket - Error parsing packet";
      ExecReturnCodeCallback(cb, kDeletePacketFailure);
      return;
    }
    if (!crypto::AsymCheckSig(sv.data(), sv.signature(), public_key)) {
      DLOG(INFO) << "DeletePacket - Not owner of packet";
      ExecReturnCodeCallback(cb, kDeletePacketFailure);
      return;
    }
    if (!client_chunkstore_->Delete(packet_name)) {
      DLOG(INFO) << "DeletePacket - Error deleting packet";
      ExecReturnCodeCallback(cb, kDeletePacketFailure);
      return;
    }
    ExecReturnCodeCallback(cb, kSuccess);
  }
}

void LocalStoreManager::StorePacket(const std::string &packet_name,
                                    const std::string &value,
                                    passport::PacketType system_packet_type,
                                    DirType dir_type, const std::string& msid,
                                    const VoidFuncOneInt &cb) {
  PrintDebugInfo(packet_name, value, "", "StorePacket", system_packet_type);

  std::string key_id, public_key, public_key_signature, private_key;
  ClientUtils client_utils(ss_);
  client_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid,
                                      &key_id, &public_key,
                                      &public_key_signature, &private_key);
//  pki::MaidsafeValidator msv;
//  if (!msv.ValidateSignerId(key_id, public_key, public_key_signature)) {
//    ExecReturnCodeCallback(cb, kSendPacketFailure);
//    return;
//  }

  std::string ser_gp;
  CreateSerialisedSignedValue(value, private_key, &ser_gp);
  if (ser_gp.empty()) {
    ExecReturnCodeCallback(cb, kSendPacketFailure);
    return;
  }

  GenericPacket sv;
  if (sv.ParseFromString(ser_gp)) {
    if (!crypto::AsymCheckSig(sv.data(), sv.signature(), public_key)) {
      ExecReturnCodeCallback(cb, kSendPacketFailure);
      DLOG(WARNING) << "LSM::StorePacket - " << sv.data() << std::endl;
      return;
    }
  }

  if (client_chunkstore_->Has(packet_name)) {
    ExecReturnCodeCallback(cb, kStoreChunkError);
    return;
  }

  if (client_chunkstore_->Store(packet_name, ser_gp))
    ExecReturnCodeCallback(cb, kSuccess);
  else
    ExecReturnCodeCallback(cb, kStoreChunkError);
}

void LocalStoreManager::UpdatePacket(const std::string &packet_name,
                                     const std::string &old_value,
                                     const std::string &new_value,
                                     passport::PacketType system_packet_type,
                                     DirType dir_type, const std::string &msid,
                                     const VoidFuncOneInt &cb) {
  PrintDebugInfo(packet_name, old_value, new_value, "UpdatePacket",
                 system_packet_type);
  std::string key_id, public_key, public_key_signature, private_key;
  ClientUtils client_utils(ss_);
  client_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid,
                                      &key_id, &public_key,
                                      &public_key_signature, &private_key);
//  pki::MaidsafeValidator msv;
//  if (!msv.ValidateSignerId(key_id, public_key, public_key_signature)) {
//    ExecReturnCodeCallback(cb, kUpdatePacketFailure);
//    return;
//  }

  std::string old_ser_gp;
  CreateSerialisedSignedValue(old_value, private_key, &old_ser_gp);
  std::string new_ser_gp;
  CreateSerialisedSignedValue(new_value, private_key, &new_ser_gp);
  if (old_ser_gp.empty() || new_ser_gp.empty()) {
    ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
    DLOG(WARNING) << "LSM::UpdatePacket - Empty old or new" << std::endl;
    return;
  }

  std::string current_packet(client_chunkstore_->Get(packet_name));
  if (current_packet.empty()) {
    ExecReturnCodeCallback(cb, kStoreManagerError);
    DLOG(WARNING) << "LSM::UpdatePacket - Empty current" << std::endl;
    return;
  }

  GenericPacket sv;
  if (!sv.ParseFromString(current_packet) || sv.data() != old_value) {
    ExecReturnCodeCallback(cb, kStoreManagerError);
    DLOG(WARNING) << "LSM::UpdatePacket - Different current" << std::endl;
    return;
  } else if (!crypto::AsymCheckSig(sv.data(),
                                   sv.signature(),
                                   public_key)) {
    ExecReturnCodeCallback(cb, kStoreManagerError);
    DLOG(WARNING) << "LSM::UpdatePacket - Not owner" << std::endl;
    return;
  }

  if (!client_chunkstore_->Delete(packet_name)) {
    ExecReturnCodeCallback(cb, kStoreManagerError);
    DLOG(WARNING) << "LSM::UpdatePacket - Failed delete old" << std::endl;
    return;
  }

  if (!client_chunkstore_->Store(packet_name, new_ser_gp)) {
    ExecReturnCodeCallback(cb, kStoreManagerError);
    DLOG(WARNING) << "LSM::UpdatePacket - Failed store new" << std::endl;
    return;
  }

  ExecReturnCodeCallback(cb, kSuccess);
}

bool LocalStoreManager::ValidateGenericPacket(std::string ser_gp,
                                              std::string public_key) {
  GenericPacket gp;
  if (!gp.ParseFromString(ser_gp))
    return false;
  return crypto::AsymCheckSig(gp.data(), gp.signature(), public_key);
}

void LocalStoreManager::CreateSerialisedSignedValue(
    const std::string &value,
    const std::string &private_key,
    std::string *ser_gp) {
  ser_gp->clear();
  GenericPacket gp;
  gp.set_data(value);
  gp.set_signature(crypto::AsymSign(value, private_key));
  gp.SerializeToString(ser_gp);
}

}  // namespace lifestuff

}  // namespace maidsafe
