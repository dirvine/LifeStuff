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

#include "maidsafe/lifestuff/local_store_manager.h"

#include "boost/filesystem.hpp"
#include "boost/scoped_ptr.hpp"

#include "maidsafe/common/buffered_chunk_store.h"
#include "maidsafe/common/chunk_validation.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/dht/contact.h"

#include "maidsafe/lifestuff/client_utils.h"
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
                    const std::string &op_type) {
  if (op_type == "UpdatePacket")
    DLOG(WARNING) << "LSM::" << op_type << " - <key>(" << HexSubstr(packet_name)
                  << ") value(" << (value1.empty() ? "" : HexSubstr(value1))
                  << (value2.empty() ? "" : " --> " + HexSubstr(value2))
                  << ")" << std::endl;
  else
    DLOG(WARNING) << "LSM::" << op_type << " - <key>(" << HexSubstr(packet_name)
                  << ") value(" << (value1.empty() ? "" : HexSubstr(value1))
                  << (value2.empty() ? "" : " --> " + HexSubstr(value2))
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
  bool Modifiable(const std::string &/*name*/) { return true; }
  bool ValidChunk(const std::string &/*name*/, const std::string &/*content*/) {
    return true;
  }
  bool ValidChunk(const std::string &/*name*/, const fs::path &/*path*/) {
    return true;
  }
  std::string Version(const std::string &/*name*/,
                      const std::string &/*content*/) {
    return "1";
  }
  std::string Version(const std::string &/*name*/, const fs::path &/*path*/) {
    return "1";
  }

 private:
  VeritasChunkValidation(const VeritasChunkValidation&);
  VeritasChunkValidation& operator=(const VeritasChunkValidation&);
};

void GetDataSlot(const std::string &signal_data, std::string *slot_data) {
  *slot_data = signal_data;
}

}  // namespace

std::string GetPublicKey(const std::string &packet_name,
                         std::shared_ptr<Session> ss) {
  std::string public_key(ss->PublicKey(packet_name, false));
  if (public_key.empty())
    return ss->PublicKey(packet_name, true);
  return public_key;
}

LocalStoreManager::LocalStoreManager(const fs::path &db_directory,
                                     std::shared_ptr<Session> ss)
    : local_sm_dir_(db_directory.string()),
      service_(),
      work_(),
      thread_group_(),
      chunk_validation_(new VeritasChunkValidation()),
      client_chunkstore_(new BufferedChunkStore(chunk_validation_, service_)),
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

void LocalStoreManager::Init(VoidFuncOneInt callback) {
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

bool LocalStoreManager::KeyUnique(const std::string &key) {
  DataHandler data_handler;
  return data_handler.ProcessData(DataHandler::kHas,
                                  key,
                                  "",
                                  "",
                                  client_chunkstore_) == kKeyUnique;
}

void LocalStoreManager::KeyUnique(const std::string &key,
                                  const VoidFuncOneInt &cb) {
  DataHandler data_handler;
  ReturnCode result(
      static_cast<ReturnCode>(data_handler.ProcessData(DataHandler::kHas,
                                                       key,
                                                       "",
                                                       "",
                                                       client_chunkstore_)));
  ExecReturnCodeCallback(cb, result);
}

int LocalStoreManager::GetPacket(const std::string &packet_name,
                                 std::vector<std::string> *results) {
  PrintDebugInfo(packet_name, "", "", "GetPacket");
  DataHandler data_handler;
  std::string data;
  data_handler.get_data_signal()->connect(
      DataHandler::GetDataSignalPtr::element_type::slot_type(
          &GetDataSlot, _1, &data));

  int result(data_handler.ProcessData(DataHandler::kGet,
                                      packet_name,
                                      "",
                                      "",
                                      client_chunkstore_));
  if (result != kSuccess) {
    DLOG(ERROR) << "LSM::GetPacket - Failure in DH::ProcessData: "
                << result << std::endl;
    return kGetPacketFailure;
  }

  if (data.empty()) {
    DLOG(ERROR) << "LSM::GetPacket - data empty" << std::endl;
    return kGetPacketFailure;
  }

  results->push_back(data);

  return kSuccess;
}

void LocalStoreManager::GetPacket(const std::string &packetname,
                                  const GetPacketFunctor &lpf) {
  std::vector<std::string> results;
  ReturnCode rc(static_cast<ReturnCode>(GetPacket(packetname, &results)));
  ExecReturnLoadPacketCallback(lpf, results, rc);
}

void LocalStoreManager::DeletePacket(const std::string &packet_name,
                                     const std::string &value,
                                     const VoidFuncOneInt &cb) {
  PrintDebugInfo(packet_name, value, "", "DeletePacket");

  GenericPacket gp;
  if (!gp.ParseFromString(value)) {
    ExecReturnCodeCallback(cb, kDeletePacketFailure);
    DLOG(ERROR) << "LSM::DeletePacket - Failure to parse value" << std::endl;
    return;
  }

  std::string public_key(GetPublicKey(gp.signing_id(), ss_));
  if (public_key.empty()) {
    ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
    DLOG(ERROR) << "LSM::StorePacket - No public key" << std::endl;
    return;
  }

  std::string data;
  CreateSerialisedSignedValue(gp, &data);
  DataHandler data_handler;
  int result(data_handler.ProcessData(DataHandler::kDelete,
                                      packet_name,
                                      data,
                                      public_key,
                                      client_chunkstore_));
  if (result != kSuccess) {
    ExecReturnCodeCallback(cb, kDeletePacketFailure);
    DLOG(ERROR) << "LSM::DeletePacket - Failure in DH::ProcessData: "
                << result << std::endl;
    return;
  }

  ExecReturnCodeCallback(cb, kSuccess);
}

void LocalStoreManager::StorePacket(const std::string &packet_name,
                                    const std::string &value,
                                    const VoidFuncOneInt &cb) {
  PrintDebugInfo(packet_name, value, "", "StorePacket");

  GenericPacket gp;
  if (!gp.ParseFromString(value)) {
    ExecReturnCodeCallback(cb, kStorePacketFailure);
    DLOG(ERROR) << "LSM::StorePacket - Failure to parse value" << std::endl;
    return;
  }

  std::string public_key(GetPublicKey(gp.signing_id(), ss_));
  if (public_key.empty()) {
    ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
    DLOG(ERROR) << "LSM::StorePacket - No public key - ID: "
                << HexSubstr(gp.signing_id()) << std::endl;
    return;
  }

  std::string data;
  CreateSerialisedSignedValue(gp, &data);
  DataHandler data_handler;
  int result(data_handler.ProcessData(DataHandler::kStore,
                                      packet_name,
                                      data,
                                      public_key,
                                      client_chunkstore_));
  if (result != kSuccess) {
    ExecReturnCodeCallback(cb, kStorePacketFailure);
    DLOG(ERROR) << "LSM::StorePacket - Failure in DH::ProcessData: "
                << result << std::endl;
    return;
  }

  ExecReturnCodeCallback(cb, kSuccess);
}

void LocalStoreManager::UpdatePacket(const std::string &packet_name,
                                     const std::string &old_value,
                                     const std::string &new_value,
                                     const VoidFuncOneInt &cb) {
  PrintDebugInfo(packet_name, old_value, new_value, "UpdatePacket");


  GenericPacket old_gp, new_gp;
  if (!old_gp.ParseFromString(old_value)) {
    ExecReturnCodeCallback(cb, kDeletePacketFailure);
    DLOG(ERROR) << "LSM::UpdatePacket - Failure parsing old value" << std::endl;
    return;
  }
  if (!new_gp.ParseFromString(new_value)) {
    ExecReturnCodeCallback(cb, kDeletePacketFailure);
    DLOG(ERROR) << "LSM::UpdatePacket - Failure parsing new value" << std::endl;
    return;
  }

  // TODO(Team): Compare both signing ids?

  std::string public_key(GetPublicKey(old_gp.signing_id(), ss_));
  if (public_key.empty()) {
    ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
    DLOG(ERROR) << "LSM::StorePacket - No public key" << std::endl;
    return;
  }

  std::string old_data, new_data;
  CreateSerialisedSignedValue(old_gp, &old_data);
  CreateSerialisedSignedValue(new_gp, &new_data);

  DataHandler data_handler;
  int result(data_handler.ProcessData(DataHandler::kUpdate,
                                      packet_name,
                                      new_data,
                                      public_key,
                                      client_chunkstore_));
  if (result != kSuccess) {
    ExecReturnCodeCallback(cb, kUpdatePacketFailure);
    DLOG(ERROR) << "LSM::UpdatePacket - Failure in DH::ProcessData: "
                << result << std::endl;
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

void LocalStoreManager::CreateSerialisedSignedValue(const GenericPacket &data,
                                                    std::string *ser_gp) {
  ser_gp->clear();
  DataWrapper data_wrapper;
  if (data.hashable())
    data_wrapper.set_data_type(DataWrapper::kHashableSigned);
  else
    data_wrapper.set_data_type(DataWrapper::kNonHashableSigned);
  GenericPacket *gp = data_wrapper.mutable_signed_data();
  *gp = data;
  *ser_gp = data_wrapper.SerializeAsString();
}

}  // namespace lifestuff

}  // namespace maidsafe
