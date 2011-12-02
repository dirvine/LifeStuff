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


#include "maidsafe/lifestuff/store_components/fake_store_manager.h"

#include "boost/filesystem.hpp"

#include "maidsafe/common/chunk_validation.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/dht/contact.h"

#include "maidsafe/lifestuff/data_handler.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/lifestuff_messages_pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

namespace {

void PrintDebugInfo(const std::string &packet_name,
                    const std::string &value1,
                    const std::string &value2,
                    const std::string &op_type) {
  if (value2.empty())
    DLOG(WARNING) << "FakeStoreManager::" << op_type << " - <key, value>("
                  << Base32Substr(packet_name) << ", " << Base32Substr(value1)
                  << ")";
  else
    DLOG(WARNING) << "FakeStoreManager::" << op_type << " - <key>("
                  << Base32Substr(packet_name) << ") value("
                  << Base32Substr(value1) << " --> " << Base32Substr(value2)
                  << ")";
}

class VeritasChunkValidation : public ChunkValidation {
 public:
  VeritasChunkValidation() : ChunkValidation() {}
  ~VeritasChunkValidation() {}

  bool ValidName(const std::string &/*name*/) { return true; }
  bool Hashable(const std::string &/*name*/) { return false; }
  bool Modifiable(const std::string &/*name*/) { return true; }
  bool ValidChunk(const std::string &/*name*/, const std::string &/*content*/) {
    return true;
  }
  bool ValidChunk(const std::string &/*name*/, const fs::path &/*path*/) {
    return true;
  }
  std::string Version(const std::string &/*name*/,
                      const std::string &/*content*/) {
    return "";
  }
  std::string Version(const std::string &/*name*/, const fs::path &/*path*/) {
    return "";
  }

 private:
  VeritasChunkValidation(const VeritasChunkValidation&);
  VeritasChunkValidation& operator=(const VeritasChunkValidation&);
};

void GetDataSlot(const std::string &signal_data, std::string *slot_data) {
  *slot_data = signal_data;
}

std::string DebugString(const int &packet_type) {
  switch (packet_type) {
    case passport::kUnknown:
      return "unknown";
    case passport::kMid:
      return "MID";
    case passport::kSmid:
      return "SMID";
    case passport::kTmid:
      return "TMID";
    case passport::kStmid:
      return "STMID";
    case passport::kMpid:
      return "MPID";
    case passport::kPmid:
      return "PMID";
    case passport::kMaid:
      return "MAID";
    case passport::kAnmid:
      return "ANMID";
    case passport::kAnsmid:
      return "ANSMID";
    case passport::kAntmid:
      return "ANTMID";
    case passport::kAnmpid:
      return "ANMPID";
    case passport::kAnmaid:
      return "ANMAID";
    default:
      return "error";
  }
}

}  // namespace

void GetPublicKey(const std::string &packet_name,
                  std::shared_ptr<Session> session,
                  rsa::PublicKey *public_key,
                  int type) {
  std::shared_ptr<passport::Passport> pprt(session->passport_);
  passport::PacketType packet_type;
  for (int i(passport::kAnmid); i != passport::kMid; ++i) {
    packet_type = static_cast<passport::PacketType>(i);
#ifdef DEBUG
    int previous(FLAGS_ms_logging_passport);
    FLAGS_ms_logging_passport = google::FATAL;
#endif
    if (pprt->PacketName(packet_type, false) == packet_name) {
#ifdef DEBUG
      FLAGS_ms_logging_passport = previous;
#endif
      *public_key = pprt->SignaturePacketValue(packet_type, false);
      return;
    }
    if (pprt->PacketName(packet_type, true) == packet_name) {
#ifdef DEBUG
      FLAGS_ms_logging_passport = previous;
#endif
      *public_key = pprt->SignaturePacketValue(packet_type, true);
      return;
    }
  }

  switch (type) {
    case DataWrapper::kMmid:
      packet_type = passport::kMmid;
      break;
    case DataWrapper::kMpid:
      packet_type = passport::kAnmpid;
      break;
    case DataWrapper::kAnmpid:
      packet_type = passport::kAnmpid;
      break;
    case DataWrapper::kMsid:
      packet_type = passport::kAnmpid;
      break;
    default: packet_type = passport::kUnknown;
      break;
  }
  *public_key = pprt->SignaturePacketValue(packet_type, false, packet_name);
  if (asymm::ValidateKey(*public_key))
    return;
  *public_key = pprt->SignaturePacketValue(packet_type, true, packet_name);
}

FakeStoreManager::FakeStoreManager(std::shared_ptr<Session> session)
    : asio_service_(),
      work_(new boost::asio::io_service::work(asio_service_)),
      thread_group_(),
      chunk_validation_(new VeritasChunkValidation),
      client_chunk_store_(),
      session_(session),
      temp_directory_path_() {
  boost::system::error_code error_code;
  temp_directory_path_ = fs::temp_directory_path(error_code);
  if (error_code)
    DLOG(ERROR) << "Failed to get temp directory: " << error_code.message();
}

ReturnCode FakeStoreManager::Init(const fs::path &buffered_chunk_store_dir) {
  for (int i = 0; i < 3; ++i) {
    thread_group_.create_thread(
        std::bind(static_cast<std::size_t(boost::asio::io_service::*)()>
                      (&boost::asio::io_service::run), &asio_service_));
  }

  boost::system::error_code error_code;
  if (!fs::exists(buffered_chunk_store_dir, error_code)) {
    fs::create_directories(buffered_chunk_store_dir, error_code);
    if (error_code) {
      DLOG(ERROR) << "Failed to create " << buffered_chunk_store_dir
                  << ": " << error_code.message();
      return kStoreManagerInitError;
    }
  }

  return kSuccess;
}

FakeStoreManager::~FakeStoreManager() {
  work_.reset();
  asio_service_.stop();
  thread_group_.join_all();
}

int FakeStoreManager::Close(bool /*cancel_pending_ops*/) { return kSuccess; }

bool FakeStoreManager::KeyUnique(const std::string &key) {
  DataHandler data_handler;
  return data_handler.ProcessData(DataHandler::kHas,
                                  key,
                                  "",
                                  rsa::PublicKey(),
                                  client_chunk_store_) == kKeyUnique;
}

void FakeStoreManager::KeyUnique(const std::string &key,
                                 const VoidFuncOneInt &cb) {
  DataHandler data_handler;
  ReturnCode result(
      static_cast<ReturnCode>(data_handler.ProcessData(DataHandler::kHas,
                                                       key,
                                                       "",
                                                       rsa::PublicKey(),
                                                       client_chunk_store_)));
  ExecReturnCodeCallback(cb, result);
}

int FakeStoreManager::GetPacket(const std::string &packet_name,
                                std::vector<std::string> *results) {
  DataHandler data_handler;
  std::string data;
  data_handler.get_data_signal()->connect(
      DataHandler::GetDataSignalPtr::element_type::slot_type(
          &GetDataSlot, _1, &data));

  int result(data_handler.ProcessData(DataHandler::kGet,
                                      packet_name,
                                      "",
                                      rsa::PublicKey(),
                                      client_chunk_store_));
  if (result != kSuccess) {
    DLOG(ERROR) << "FakeStoreManager::GetPacket - Failure in DH::ProcessData: "
                << result;
    return kGetPacketFailure;
  }

  if (data.empty()) {
    DLOG(ERROR) << "FakeStoreManager::GetPacket - data empty";
    return kGetPacketFailure;
  }

  results->push_back(data);

  return kSuccess;
}

void FakeStoreManager::GetPacket(const std::string &packetname,
                                 const GetPacketFunctor &lpf) {
  std::vector<std::string> results;
  ReturnCode rc(static_cast<ReturnCode>(GetPacket(packetname, &results)));
  ExecReturnLoadPacketCallback(lpf, results, rc);
}

void FakeStoreManager::DeletePacket(const std::string &packet_name,
                                    const std::string &value,
                                    const VoidFuncOneInt &cb) {
  GenericPacket gp;
  if (!gp.ParseFromString(value)) {
    ExecReturnCodeCallback(cb, kDeletePacketFailure);
    DLOG(ERROR) << "FakeStoreManager::DeletePacket - Failure to parse value";
    return;
  }

  DLOG(INFO) << "Deleting <" << Base32Substr(packet_name) << ", "
             << Base32Substr(gp.data()) << ">";

  rsa::PublicKey public_key;
  GetPublicKey(gp.signing_id(), session_, &public_key, gp.type());
  if (!rsa::ValidateKey(public_key)) {
    ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
    DLOG(ERROR) << "FakeStoreManager::StorePacket - No public key";
    return;
  }

  std::string data;
  CreateSerialisedSignedValue(gp, &data);
  DataHandler data_handler;
  int result(data_handler.ProcessData(DataHandler::kDelete,
                                      packet_name,
                                      data,
                                      public_key,
                                      client_chunk_store_));
  if (result != kSuccess) {
    ExecReturnCodeCallback(cb, kDeletePacketFailure);
    DLOG(ERROR) << "FakeStoreManager::DeletePacket - Failure in "
                << "DH::ProcessData: " << result;
    return;
  }

  ExecReturnCodeCallback(cb, kSuccess);
}

void FakeStoreManager::StorePacket(const std::string &packet_name,
                                   const std::string &value,
                                   const VoidFuncOneInt &cb) {
  GenericPacket gp;
  if (!gp.ParseFromString(value)) {
    ExecReturnCodeCallback(cb, kStorePacketFailure);
    DLOG(ERROR) << "FakeStoreManager::StorePacket - Failure to parse value";
    return;
  }

  DLOG(INFO) << "Storing <" << Base32Substr(packet_name) << ", "
             << Base32Substr(gp.data()) << ">";

  rsa::PublicKey public_key;
  if (gp.has_signing_id()) {
    GetPublicKey(gp.signing_id(), session_, &public_key, gp.type());
    if (!rsa::ValidateKey(public_key)) {
      ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
      DLOG(ERROR) << "FakeStoreManager::StorePacket - No public key - ID: "
                  << Base32Substr(gp.signing_id());
      return;
    }
  } else {
    DLOG(INFO) << "NOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO " << DebugString(gp.type());
  }

  std::string data;
  CreateSerialisedSignedValue(gp, &data);
  DataHandler data_handler;
  int result(data_handler.ProcessData(DataHandler::kStore,
                                      packet_name,
                                      data,
                                      public_key,
                                      client_chunk_store_));
  if (result != kSuccess) {
    ExecReturnCodeCallback(cb, kStorePacketFailure);
    DLOG(ERROR) << "FakeStoreManager::StorePacket - Failure in "
                << "DH::ProcessData: " << result;
    return;
  }

  ExecReturnCodeCallback(cb, kSuccess);
}

void FakeStoreManager::UpdatePacket(const std::string &packet_name,
                                    const std::string &old_value,
                                    const std::string &new_value,
                                    const VoidFuncOneInt &cb) {
  DLOG(INFO) << "Updating <" << Base32Substr(packet_name) << ", "
             << Base32Substr(old_value) << "> to <" << Base32Substr(packet_name)
             << ", " << Base32Substr(new_value) << ">";
  PrintDebugInfo(packet_name, old_value, new_value, "UpdatePacket");

  GenericPacket old_gp, new_gp;
  if (!old_gp.ParseFromString(old_value)) {
    ExecReturnCodeCallback(cb, kDeletePacketFailure);
    DLOG(ERROR) << "FakeStoreManager::UpdatePacket - Failure parsing old value";
    return;
  }
  if (!new_gp.ParseFromString(new_value)) {
    ExecReturnCodeCallback(cb, kDeletePacketFailure);
    DLOG(ERROR) << "FakeStoreManager::UpdatePacket - Failure parsing new value";
    return;
  }

  // TODO(Team): Compare both signing ids?

  rsa::PublicKey public_key;
  GetPublicKey(old_gp.signing_id(), session_, &public_key, old_gp.type());
  if (!rsa::ValidateKey(public_key)) {
    ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
    DLOG(ERROR) << "FakeStoreManager::StorePacket - No public key";
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
                                      client_chunk_store_));
  if (result != kSuccess) {
    ExecReturnCodeCallback(cb, kUpdatePacketFailure);
    DLOG(ERROR) << "FakeStoreManager::UpdatePacket - Failure in "
                << "DH::ProcessData: " << result;
    return;
  }

  ExecReturnCodeCallback(cb, kSuccess);
}

void FakeStoreManager::ExecReturnCodeCallback(VoidFuncOneInt callback,
                                              ReturnCode return_code) {
  asio_service_.post(std::bind(callback, return_code));
}

void FakeStoreManager::ExecReturnLoadPacketCallback(
    GetPacketFunctor callback,
    std::vector<std::string> results,
    ReturnCode return_code) {
  asio_service_.post(std::bind(callback, results, return_code));
}


void FakeStoreManager::CreateSerialisedSignedValue(const GenericPacket &data,
                                                   std::string *ser_gp) {
  ser_gp->clear();
  DataWrapper data_wrapper;
  data_wrapper.set_data_type(static_cast<DataWrapper::DataType>(data.type()));
  GenericPacket *gp = data_wrapper.mutable_signed_data();
  *gp = data;
  *ser_gp = data_wrapper.SerializeAsString();
}

std::shared_ptr<ChunkStore> FakeStoreManager::chunk_store() const {
  return client_chunk_store_;
}


}  // namespace lifestuff

}  // namespace maidsafe
