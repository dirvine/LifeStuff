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


#include "maidsafe/lifestuff/store_components/remote_store_manager.h"

#include <functional>

#include "boost/filesystem.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#include "maidsafe/pd/client/remote_chunk_store.h"
#include "maidsafe/pd/client/vault_chunk_manager.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/session.h"

namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;
namespace args = std::placeholders;

namespace maidsafe {

namespace lifestuff {

namespace {

void PrintDebugInfo(const std::string &packet_name,
                    const std::string &value1,
                    const std::string &value2,
                    const std::string &op_type) {
  if (value2.empty())
    DLOG(WARNING) << "RemoteStoreManager::" << op_type << " - <key, value>("
                  << Base32Substr(packet_name) << ", " << Base32Substr(value1)
                  << ")";
  else
    DLOG(WARNING) << "RemoteStoreManager::" << op_type << " - <key>("
                  << Base32Substr(packet_name) << ") value("
                  << Base32Substr(value1) << " --> " << Base32Substr(value2)
                  << ")";
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

std::string CreateOwnershipProof(const asymm::PrivateKey &private_key) {
  pca::SignedData signed_data;
  signed_data.set_data(RandomString(crypto::SHA512::DIGESTSIZE));
  std::string signature;
  int result(asymm::Sign(signed_data.data(), private_key, &signature));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to sign something: " << result;
    return "";
  }
  signed_data.set_signature(signature);
  return signed_data.SerializeAsString();
}

void ExecuteHas(std::shared_ptr<ChunkStore> client_chunk_store,
                const std::string &key,
                const VoidFuncOneInt &cb) {
  ReturnCode rc(client_chunk_store_->Has(key) ? kKeyNotUnique : kKeyUnique);
  cb(rc);
}

}  // namespace

struct RemoteStoreManager::SignalToCallback {
  SignalToCallback()
      : chunk_name(),
        cb(),
        type(RemoteChunkStore::kOpGet) {}
  SignalToCallback(const std::string &chunk_name_in,
                   const VoidFuncOneInt &cb_in,
                   RemoteChunkStore::OperationType type_in)
      : chunk_name(chunk_name_in),
        cb(cb_in),
        type(type_in) {}
  std::string chunk_name;
  VoidFuncOneInt cb;
  RemoteChunkStore::OperationType type;
};

void GetPublicKey(const std::string &packet_name,
                  std::shared_ptr<Session> session,
                  asymm::PublicKey *public_key) {
  std::shared_ptr<passport::Passport> pprt(session->passport_);
  passport::PacketType packet_type(passport::kUnknown);
  for (int i(passport::kAnmid); i != passport::kMid; ++i) {
    packet_type = static_cast<passport::PacketType>(i);
    if (pprt->PacketName(packet_type, false) == packet_name) {
      *public_key = pprt->SignaturePacketValue(packet_type, false);
      return;
    }
    if (pprt->PacketName(packet_type, true) == packet_name) {
      *public_key = pprt->SignaturePacketValue(packet_type, true);
      return;
    }
  }

  int result(-1);
  passport::SelectableIdentityData data;
  std::vector<passport::SelectableIdData> selectables;
  session->passport_->SelectableIdentitiesList(&selectables);
  auto it(selectables.begin());
  while (it != selectables.end()) {
    std::string public_username(std::get<0>(*it));
    result = session->passport_->GetSelectableIdentityData(public_username,
                                                           false,
                                                           &data);
    if (result == kSuccess && data.size() == 3U) {
      for (int n(0); n < 3; ++n) {
      	if (std::get<0>(data.at(n)) == packet_name) {
          *public_key = std::get<1>(data.at(n));
          if (asymm::ValidateKey(*public_key))
            return;
      	}
      }
    }
    result = session->passport_->GetSelectableIdentityData(public_username,
                                                           true,
                                                           &data);
    if (result == kSuccess && data.size() == 3U) {
      for (int n(0); n < 3; ++n) {
        if (std::get<0>(data.at(n)) == packet_name) {
          *public_key = std::get<1>(data.at(n));
          if (asymm::ValidateKey(*public_key))
            return;
        }
      }
    }
    ++it;
  }
}

void GetPrivateKey(const std::string &packet_name,
                   std::shared_ptr<Session> session,
                   asymm::PrivateKey *private_key) {
  std::shared_ptr<passport::Passport> pprt(session->passport_);
  passport::PacketType packet_type(passport::kUnknown);
  for (int i(passport::kAnmid); i != passport::kMid; ++i) {
    packet_type = static_cast<passport::PacketType>(i);
    if (pprt->PacketName(packet_type, false) == packet_name) {
      *private_key = pprt->PacketPrivateKey(packet_type, false);
      return;
    }
    if (pprt->PacketName(packet_type, true) == packet_name) {
      *private_key = pprt->PacketPrivateKey(packet_type, true);
      return;
    }
  }

  *private_key = pprt->PacketPrivateKey(packet_type, false, packet_name);
  if (asymm::ValidateKey(*private_key))
    return;
  *private_key = pprt->PacketPrivateKey(packet_type, true, packet_name);
  if (!asymm::ValidateKey(*private_key))
    DLOG(ERROR) << "Failed to validate confirmed private key";
}

RemoteStoreManager::RemoteStoreManager(std::shared_ptr<Session> session,
                                       const std::string &/*db_directory*/)
    : sig_to_cb_list_(),
      signal_to_cb_mutex_(),
      client_container_(),
      client_chunk_store_(),
      session_(session) {}

RemoteStoreManager::~RemoteStoreManager() {
  client_container_.Stop();
}

void RemoteStoreManager::Init(VoidFuncOneInt callback) {
  client_chunk_store_.reset(
      new maidsafe::pd::RemoteChunkStore(
          client_container_.chunk_store(),
          client_container_.chunk_manager(),
          client_container_.chunk_action_authority()));
  // TODO(Dan): Make connections trackable or keep connections as class members.
  client_chunk_store_->sig_chunk_got()->connect(
      std::bind(&RemoteStoreManager::ChunkGot, this, args::_1, args::_2));
  client_chunk_store_->sig_chunk_stored()->connect(
      std::bind(&RemoteStoreManager::ChunkStored, this, args::_1, args::_2));
  client_chunk_store_->sig_chunk_deleted()->connect(
      std::bind(&RemoteStoreManager::ChunkDeleted, this, args::_1, args::_2));
  ExecReturnCodeCallback(callback, kSuccess);
}

int RemoteStoreManager::Close(bool /*cancel_pending_ops*/) {
  client_container_.Stop();
}

bool RemoteStoreManager::KeyUnique(const std::string &key,
                                   const asymm::Identity &/*signing_key_id*/) {
  return !client_chunk_store_->Has(key);
}

void RemoteStoreManager::KeyUnique(const std::string &key,
                                   const asymm::Identity &/*signing_key_id*/,
                                   const VoidFuncOneInt &cb) {
  client_container_.asio_service().post(std::bind(&ExecuteHas,
                                                  chunk_action_authority_,
                                                  key,
                                                  cb));
}

int RemoteStoreManager::GetPacket(const std::string &packet_name,
                                  const std::string &signing_key_id,
                                  std::vector<std::string> *results) {
  DLOG(INFO) << "Searching <" << Base32Substr(packet_name) << ">";

  {
    boost::mutex::scoped_lock loch_harray(signal_to_cb_mutex_);
  }
  BOOST_ASSERT(results);
  results->clear();

  asymm::PublicKey public_key;
  if (!signing_key_id.empty())
    GetPublicKey(signing_key_id, session_, &public_key);

  std::string data(chunk_action_authority_->Get(packet_name, "", public_key));
  if (data.empty()) {
    DLOG(ERROR) << "RemoteStoreManager::GetPacket - Failure";
    return kGetPacketFailure;
  }

  results->push_back(data);
  return kSuccess;
}

void RemoteStoreManager::GetPacket(const std::string &packetname,
                                 const asymm::Identity &signing_key_id,
                                 const GetPacketFunctor &lpf) {
  std::vector<std::string> results;
  ReturnCode rc(static_cast<ReturnCode>(GetPacket(packetname,
                                                  signing_key_id,
                                                  &results)));
  ExecReturnLoadPacketCallback(lpf, results, rc);
}

void RemoteStoreManager::StorePacket(const std::string &packet_name,
                                   const std::string &value,
                                   const asymm::Identity &signing_key_id,
                                   const VoidFuncOneInt &cb) {
  DLOG(INFO) << "Storing <" << Base32Substr(packet_name) << ", "
             << Base32Substr(value) << ">";

  if (signing_key_id.empty()) {
    DLOG(ERROR) << "RemoteStoreManager::StorePacket - No public key ID";
    ExecReturnCodeCallback(cb, kStorePacketFailure);
    return;
  }

  asymm::PublicKey public_key;
  GetPublicKey(signing_key_id, session_, &public_key);
  if (!asymm::ValidateKey(public_key)) {
    if (signing_key_id == packet_name.substr(0, signing_key_id.size())) {
      public_key = asymm::PublicKey();
      pca::SignedData signed_data;
      signed_data.ParseFromString(value);
      asymm::DecodePublicKey(signed_data.data(), &public_key);
      if (!asymm::ValidateKey(public_key)) {
        DLOG(ERROR) << "RemoteStoreManager::StorePacket - No public key";
        ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
        return;
      }
    }
  }


  if (!chunk_action_authority_->Store(packet_name, value, public_key)) {
    ExecReturnCodeCallback(cb, kStorePacketFailure);
    DLOG(ERROR) << "RemoteStoreManager::StorePacket - Failure";
    return;
  }

  ExecReturnCodeCallback(cb, kSuccess);
}

void RemoteStoreManager::DeletePacket(const std::string &packet_name,
                                    const asymm::Identity &signing_key_id,
                                    const VoidFuncOneInt &cb) {
  DLOG(INFO) << "Deleting <" << Base32Substr(packet_name);

  if (signing_key_id.empty()) {
    DLOG(ERROR) << "RemoteStoreManager::DeletePacket - No public key ID";
    ExecReturnCodeCallback(cb, kDeletePacketFailure);
    return;
  }

  asymm::PublicKey public_key;
  GetPublicKey(signing_key_id, session_, &public_key);
  if (!asymm::ValidateKey(public_key)) {
    DLOG(ERROR) << "RemoteStoreManager::DeletePacket - No public key";
    ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
    return;
  }

  asymm::PrivateKey private_key;
  GetPrivateKey(signing_key_id, session_, &private_key);
  if (!asymm::ValidateKey(private_key)) {
    DLOG(ERROR) << "RemoteStoreManager::DeletePacket - No private key";
    ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
    return;
  }
  std::string ownership_proof(CreateOwnershipProof(private_key));

  if (!chunk_action_authority_->Delete(packet_name,
                                       "",
                                       ownership_proof,
                                       public_key)) {
    DLOG(ERROR) << "RemoteStoreManager::DeletePacket - Failure";
    ExecReturnCodeCallback(cb, kDeletePacketFailure);
    return;
  }

  ExecReturnCodeCallback(cb, kSuccess);
}

void RemoteStoreManager::ModifyPacket(const std::string &packet_name,
                                    const std::string &value,
                                    const asymm::Identity &signing_key_id,
                                    const VoidFuncOneInt &cb) {
  DLOG(INFO) << "Modifying <" << Base32Substr(packet_name) << "> to <"
             << Base32Substr(value) << ">";
  PrintDebugInfo(packet_name, value, "", "ModifyPacket");

  if (signing_key_id.empty()) {
    DLOG(ERROR) << "RemoteStoreManager::ModifyPacket - No public key ID";
    ExecReturnCodeCallback(cb, kUpdatePacketFailure);
    return;
  }

  asymm::PublicKey public_key;
  GetPublicKey(signing_key_id, session_, &public_key);
  if (!asymm::ValidateKey(public_key)) {
    ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
    DLOG(ERROR) << "RemoteStoreManager::ModifyPacket - No public key";
    return;
  }

  int64_t operation_diff;
  if (!chunk_action_authority_->Modify(packet_name,
                                       value,
                                       "",
                                       public_key,
                                       &operation_diff)) {
    DLOG(ERROR) << "RemoteStoreManager::ModifyPacket - Failure - OD: "
                << operation_diff;
    ExecReturnCodeCallback(cb, kUpdatePacketFailure);
    return;
  }

  ExecReturnCodeCallback(cb, kSuccess);
}

void RemoteStoreManager::ExecReturnCodeCallback(VoidFuncOneInt callback,
                                              ReturnCode return_code) {
  asio_service_.post(std::bind(callback, return_code));
}

void RemoteStoreManager::ExecReturnLoadPacketCallback(
    GetPacketFunctor callback,
    std::vector<std::string> results,
    ReturnCode return_code) {
  asio_service_.post(std::bind(callback, results, return_code));
}

std::shared_ptr<ChunkStore> RemoteStoreManager::chunk_store() const {
  return client_chunk_store_;
}

}  // namespace lifestuff

}  // namespace maidsafe
