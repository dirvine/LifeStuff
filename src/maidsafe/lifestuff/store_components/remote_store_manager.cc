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

#include "boost/bind.hpp"
#include "boost/filesystem.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#include "maidsafe/pd/client/remote_chunk_store.h"
#include "maidsafe/pd/client/chunk_manager.h"

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

//void GetPublicKey(const std::string &packet_name,
//                  std::shared_ptr<Session> session,
//                  asymm::PublicKey *public_key) {
//  std::shared_ptr<passport::Passport> pprt(session->passport_);
//  passport::PacketType packet_type(passport::kUnknown);
//  for (int i(passport::kAnmid); i != passport::kMid; ++i) {
//    packet_type = static_cast<passport::PacketType>(i);
//    if (pprt->PacketName(packet_type, false) == packet_name) {
//      *public_key = pprt->SignaturePacketValue(packet_type, false);
//      return;
//    }
//    if (pprt->PacketName(packet_type, true) == packet_name) {
//      *public_key = pprt->SignaturePacketValue(packet_type, true);
//      return;
//    }
//  }
//
//  int result(-1);
//  passport::SelectableIdentityData data;
//  std::vector<passport::SelectableIdData> selectables;
//  session->passport_->SelectableIdentitiesList(&selectables);
//  auto it(selectables.begin());
//  while (it != selectables.end()) {
//    std::string public_username(std::get<0>(*it));
//    result = session->passport_->GetSelectableIdentityData(public_username,
//                                                           false,
//                                                           &data);
//    if (result == kSuccess && data.size() == 3U) {
//      for (int n(0); n < 3; ++n) {
//        if (std::get<0>(data.at(n)) == packet_name) {
//          *public_key = std::get<1>(data.at(n));
//          if (asymm::ValidateKey(*public_key))
//            return;
//        }
//      }
//    }
//    result = session->passport_->GetSelectableIdentityData(public_username,
//                                                           true,
//                                                           &data);
//    if (result == kSuccess && data.size() == 3U) {
//      for (int n(0); n < 3; ++n) {
//        if (std::get<0>(data.at(n)) == packet_name) {
//          *public_key = std::get<1>(data.at(n));
//          if (asymm::ValidateKey(*public_key))
//            return;
//        }
//      }
//    }
//    ++it;
//  }
//}
//
//void GetPrivateKey(const std::string &packet_name,
//                   std::shared_ptr<Session> session,
//                   asymm::PrivateKey *private_key) {
//  std::shared_ptr<passport::Passport> pprt(session->passport_);
//  passport::PacketType packet_type(passport::kUnknown);
//  for (int i(passport::kAnmid); i != passport::kMid; ++i) {
//    packet_type = static_cast<passport::PacketType>(i);
//    if (pprt->PacketName(packet_type, false) == packet_name) {
//      *private_key = pprt->PacketPrivateKey(packet_type, false);
//      return;
//    }
//    if (pprt->PacketName(packet_type, true) == packet_name) {
//      *private_key = pprt->PacketPrivateKey(packet_type, true);
//      return;
//    }
//  }
//
//  *private_key = pprt->PacketPrivateKey(packet_type, false, packet_name);
//  if (asymm::ValidateKey(*private_key))
//    return;
//  *private_key = pprt->PacketPrivateKey(packet_type, true, packet_name);
//  if (!asymm::ValidateKey(*private_key))
//    DLOG(ERROR) << "Failed to validate confirmed private key";
//}

void ExecuteHas(std::shared_ptr<ChunkStore> client_chunk_store,
                const std::string &key,
                const VoidFuncOneInt &callback) {
  callback(client_chunk_store->Has(key) ? kKeyNotUnique : kKeyUnique);
}

void ExecuteGet(std::shared_ptr<ChunkStore> client_chunk_store,
                const std::string &packet_name,
                const AlternativeStore::ValidationData &validation_data,
                const GetPacketFunctor &callback) {
  std::string value(client_chunk_store->Get(packet_name, validation_data));
  if (value.empty()) {
    DLOG(ERROR) << "RemoteStoreManager::GetPacket - Failure";
    callback(value, kGetPacketFailure);
  }
  callback(value, kSuccess);
}

}  // namespace

void GetKeyring(const std::string &packet_name,
                std::shared_ptr<Session> session,
                asymm::Keys *keyring) {
  std::shared_ptr<passport::Passport> pprt(session->passport_);
  passport::PacketType packet_type(passport::kUnknown);
  for (int i(passport::kAnmid); i != passport::kMid; ++i) {
    packet_type = static_cast<passport::PacketType>(i);
    if (pprt->PacketName(packet_type, false) == packet_name) {
      keyring->public_key = pprt->SignaturePacketValue(packet_type, false);
      keyring->private_key = pprt->PacketPrivateKey(packet_type, false);
      keyring->identity = pprt->PacketName(packet_type, false);
      keyring->validation_token = pprt->PacketSignature(packet_type, false);
      return;
    }
    if (pprt->PacketName(packet_type, true) == packet_name) {
      keyring->public_key = pprt->SignaturePacketValue(packet_type, true);
      keyring->private_key = pprt->PacketPrivateKey(packet_type, true);
      keyring->identity = pprt->PacketName(packet_type, true);
      keyring->validation_token = pprt->PacketSignature(packet_type, true);
      return;
    }
  }

  int result(-1);
  passport::SelectableIdentityData data;
  std::vector<passport::SelectableIdData> selectables;
  pprt->SelectableIdentitiesList(&selectables);
  auto it(selectables.begin());
  while (it != selectables.end()) {
    std::string public_username(std::get<0>(*it));
    result = pprt->GetSelectableIdentityData(public_username, false, &data);
    if (result == kSuccess && data.size() == 3U) {
      for (int n(0); n < 3; ++n) {
        if (std::get<0>(data.at(n)) == packet_name) {
          passport::PacketType pt(passport::kAnmpid);
          if (n == 1) {
            pt = passport::kMpid;
          } else if (n == 2) {
            pt = passport::kMmid;
          }
          keyring->public_key = std::get<1>(data.at(n));
          if (asymm::ValidateKey(keyring->public_key)) {
            keyring->private_key =
                pprt->PacketPrivateKey(pt, false, packet_name);
            keyring->identity = pprt->PacketName(pt, false, packet_name);
            keyring->validation_token =
                pprt->PacketSignature(pt, false, packet_name);
            return;
          }
        }
      }
    }
    result = pprt->GetSelectableIdentityData(public_username, true, &data);
    if (result == kSuccess && data.size() == 3U) {
      for (int n(0); n < 3; ++n) {
        if (std::get<0>(data.at(n)) == packet_name) {
          passport::PacketType pt(passport::kAnmpid);
          if (n == 1) {
            pt = passport::kMpid;
          } else if (n == 2) {
            pt = passport::kMmid;
          }
          keyring->public_key = std::get<1>(data.at(n));
          if (asymm::ValidateKey(keyring->public_key)) {
            keyring->private_key =
                pprt->PacketPrivateKey(pt, true, packet_name);
            keyring->identity =
                pprt->PacketName(pt, true, packet_name);
            keyring->validation_token =
                pprt->PacketSignature(pt, true, packet_name);
            return;
          }
        }
      }
    }
    ++it;
  }
}


struct RemoteStoreManager::SignalToCallback {
  SignalToCallback()
      : chunk_name(),
        callback(),
        type(pd::RemoteChunkStore::kOpGet) {}
  SignalToCallback(const std::string &chunk_name_in,
                   const VoidFuncOneInt &cb_in,
                   pd::RemoteChunkStore::OperationType type_in)
      : chunk_name(chunk_name_in),
        callback(cb_in),
        get_packet_callback(),
        type(type_in) {}
  SignalToCallback(const std::string &chunk_name_in,
                   const GetPacketFunctor &get_packet_callback_in,
                   pd::RemoteChunkStore::OperationType type_in)
      : chunk_name(chunk_name_in),
        callback(),
        get_packet_callback(get_packet_callback_in),
        type(type_in) {}
  std::string chunk_name;
  VoidFuncOneInt callback;
  GetPacketFunctor get_packet_callback;
  pd::RemoteChunkStore::OperationType type;
};

RemoteStoreManager::RemoteStoreManager(std::shared_ptr<Session> session,
                                       const std::string &/*db_directory*/)
    : client_container_(),
      client_chunk_store_(),
      session_(session),
      sig_to_cb_list_(new std::list<SignalToCallback>),
      signal_to_cb_mutex_() {}

RemoteStoreManager::~RemoteStoreManager() {
  client_container_.Stop(nullptr);
}

void RemoteStoreManager::Init(VoidFuncOneInt callback) {
  client_chunk_store_.reset(
      new maidsafe::pd::RemoteChunkStore(
          client_container_.chunk_store(),
          client_container_.chunk_manager(),
          client_container_.chunk_action_authority()));
  client_chunk_store_->sig_chunk_stored()->connect(
      pd::ChunkManager::ChunkStoredSig::slot_type(
          &RemoteStoreManager::FindAndExecCallback,
          this,
          _1,
          pd::RemoteChunkStore::kOpStore,
          _2).track_foreign(sig_to_cb_list_));
  client_chunk_store_->sig_chunk_deleted()->connect(
      pd::ChunkManager::ChunkGotSig::slot_type(
          &RemoteStoreManager::FindAndExecCallback,
          this,
          _1,
          pd::RemoteChunkStore::kOpDelete,
          _2).track_foreign(sig_to_cb_list_));
//  client_chunk_store_->sig_chunk_modified()->connect(
//      pd::ChunkManager::ChunkModifiedSig::slot_type(
//          &RemoteStoreManager::FindAndExecCallback,
//          this,
//          _1,
//          pd::RemoteChunkStore::kOpModify,
//          _2).track_foreign(sig_to_cb_list_));
  ExecReturnCodeCallback(callback, kSuccess);
}

int RemoteStoreManager::Close(bool /*cancel_pending_ops*/) {
  return client_container_.Stop(nullptr);
}

bool RemoteStoreManager::KeyUnique(const std::string &key,
                                   const asymm::Identity &/*signing_key_id*/) {
  return !client_chunk_store_->Has(key);
}

void RemoteStoreManager::KeyUnique(const std::string &key,
                                   const asymm::Identity &/*signing_key_id*/,
                                   const VoidFuncOneInt &callback) {
  client_container_.asio_service().post(std::bind(&ExecuteHas,
                                                  client_chunk_store_,
                                                  key,
                                                  callback));
}

int RemoteStoreManager::GetPacket(const std::string &packet_name,
                                  const std::string &signing_key_id,
                                  std::string *value) {
  DLOG(INFO) << "Searching <" << Base32Substr(packet_name) << ">";

  BOOST_ASSERT(value);
  value->clear();

  *value = client_chunk_store_->Get(packet_name,
                                    GetValidationData(signing_key_id, false));
  if (value->empty()) {
    DLOG(ERROR) << "RemoteStoreManager::GetPacket - Failure";
    return kGetPacketFailure;
  }

  return kSuccess;
}

void RemoteStoreManager::GetPacket(const std::string &packet_name,
                                   const asymm::Identity &signing_key_id,
                                   const GetPacketFunctor &callback) {
  client_container_.asio_service().post(std::bind(
      &ExecuteGet,
      client_chunk_store_,
      packet_name,
      GetValidationData(signing_key_id, false),
      callback));
}

void RemoteStoreManager::StorePacket(const std::string &packet_name,
                                     const std::string &value,
                                     const asymm::Identity &signing_key_id,
                                     const VoidFuncOneInt &callback) {
  DLOG(INFO) << "Storing <" << Base32Substr(packet_name) << ", "
             << Base32Substr(value) << ">";

  if (signing_key_id.empty()) {
    DLOG(ERROR) << "RemoteStoreManager::StorePacket - No public key ID";
    ExecReturnCodeCallback(callback, kStorePacketFailure);
    return;
  }

  boost::mutex::scoped_lock loch_harray(signal_to_cb_mutex_);
  sig_to_cb_list_->push_back(
      SignalToCallback(packet_name,
                       callback,
                       pd::RemoteChunkStore::kOpStore));

  if (!client_chunk_store_->Store(packet_name,
                                  value,
                                  GetValidationData(signing_key_id, false))) {
    sig_to_cb_list_->pop_back();
    DLOG(ERROR) << "RemoteStoreManager::StorePacket - Failure";
    ExecReturnCodeCallback(callback, kStorePacketFailure);
    return;
  }
}

void RemoteStoreManager::DeletePacket(const std::string &packet_name,
                                    const asymm::Identity &signing_key_id,
                                    const VoidFuncOneInt &callback) {
  DLOG(INFO) << "Deleting <" << Base32Substr(packet_name);

  if (signing_key_id.empty()) {
    DLOG(ERROR) << "RemoteStoreManager::DeletePacket - No public key ID";
    ExecReturnCodeCallback(callback, kDeletePacketFailure);
    return;
  }

  boost::mutex::scoped_lock loch_harray(signal_to_cb_mutex_);
  sig_to_cb_list_->push_back(
      SignalToCallback(packet_name,
                       callback,
                       pd::RemoteChunkStore::kOpDelete));

  if (!client_chunk_store_->Delete(packet_name,
                                   GetValidationData(signing_key_id, true))) {
    sig_to_cb_list_->pop_back();
    DLOG(ERROR) << "RemoteStoreManager::DeletePacket - Failure";
    ExecReturnCodeCallback(callback, kDeletePacketFailure);
    return;
  }
}

// TODO(Fraser#5#): 2012-01-27 - Uncomment once RemoteChunkStore implements Modify
//void RemoteStoreManager::ModifyPacket(const std::string &packet_name,
//                                      const std::string &value,
//                                      const asymm::Identity &signing_key_id,
//                                      const VoidFuncOneInt &callback) {
//  DLOG(INFO) << "Modifying <" << Base32Substr(packet_name) << "> to <"
//             << Base32Substr(value) << ">";
//  PrintDebugInfo(packet_name, value, "", "ModifyPacket");
//
//  if (signing_key_id.empty()) {
//    DLOG(ERROR) << "RemoteStoreManager::ModifyPacket - No public key ID";
//    ExecReturnCodeCallback(callback, kUpdatePacketFailure);
//    return;
//  }
//
//  boost::mutex::scoped_lock loch_harray(signal_to_cb_mutex_);
//  sig_to_cb_list_->push_back(
//      SignalToCallback(packet_name,
//                       callback,
//                       pd::RemoteChunkStore::kOpModify));
//
//  if (!client_chunk_store_->Modify(packet_name,
//                                   value,
//                                   GetValidationData(signing_key_id, false))) {
//    sig_to_cb_list_->pop_back();
//    DLOG(ERROR) << "RemoteStoreManager::ModifyPacket - Failure";
//    ExecReturnCodeCallback(callback, kUpdatePacketFailure);
//    return;
//  }
//  ExecReturnCodeCallback(callback, kSuccess);
//}

void RemoteStoreManager::ModifyPacket(const std::string &packet_name,
                                      const std::string &value,
                                      const asymm::Identity &signing_key_id,
                                      const VoidFuncOneInt &callback) {
  DLOG(INFO) << "Modifying <" << Base32Substr(packet_name) << "> to <"
             << Base32Substr(value) << ">";
  PrintDebugInfo(packet_name, value, "", "ModifyPacket");

  if (signing_key_id.empty()) {
    DLOG(ERROR) << "RemoteStoreManager::ModifyPacket - No public key ID";
    ExecReturnCodeCallback(callback, kUpdatePacketFailure);
    return;
  }

  AlternativeStore::ValidationData validation_data(
      GetValidationData(signing_key_id, true));
  VoidFuncOneInt functor(std::bind(
      &RemoteStoreManager::TempExecStoreAfterDelete,
      this,
      packet_name,
      value,
      validation_data,
      callback));

  boost::mutex::scoped_lock loch_harray(signal_to_cb_mutex_);
  sig_to_cb_list_->push_back(
      SignalToCallback(packet_name,
                       functor,
                       pd::RemoteChunkStore::kOpDelete));

  if (!client_chunk_store_->Delete(packet_name, validation_data)) {
    sig_to_cb_list_->pop_back();
    DLOG(ERROR) << "RemoteStoreManager::ModifyPacket - Delete Failure";
    ExecReturnCodeCallback(callback, kUpdatePacketFailure);
    return;
  }
}

void RemoteStoreManager::TempExecStoreAfterDelete(
    const std::string &packet_name,
    const std::string &value,
    AlternativeStore::ValidationData validation_data,
    const VoidFuncOneInt &callback) {
  validation_data.ownership_proof.clear();
  boost::mutex::scoped_lock loch_harray(signal_to_cb_mutex_);
  sig_to_cb_list_->push_back(
      SignalToCallback(packet_name,
                       callback,
                       pd::RemoteChunkStore::kOpStore));

  if (!client_chunk_store_->Store(packet_name, value, validation_data)) {
    sig_to_cb_list_->pop_back();
    DLOG(ERROR) << "RemoteStoreManager::UpdatePacket - Store Failure";
    ExecReturnCodeCallback(callback, kUpdatePacketFailure);
    return;
  }
}

void RemoteStoreManager::FindAndExecCallback(const std::string &chunk_name,
                                             const int &op_type,
                                             const int &return_code) {
  VoidFuncOneInt callback;
  {
    boost::mutex::scoped_lock loch_harray(signal_to_cb_mutex_);
    auto itr(std::find_if(
        sig_to_cb_list_->begin(),
        sig_to_cb_list_->end(),
        [&chunk_name, &op_type]
            (const SignalToCallback &signal_to_callback)->bool {
                return signal_to_callback.chunk_name == chunk_name &&
                       signal_to_callback.type == op_type;
        }));
    if (itr == sig_to_cb_list_->end()) {
      DLOG(ERROR) << "Failed to find callback for "
                  << Base32Substr(chunk_name) << ", op type " << op_type;
      return;
    }
    callback = (*itr).callback;
    sig_to_cb_list_->erase(itr);
  }
  callback(return_code);
}

void RemoteStoreManager::ExecReturnCodeCallback(VoidFuncOneInt callback,
                                                ReturnCode return_code) {
  client_container_.asio_service().post(std::bind(callback, return_code));
}

void RemoteStoreManager::ExecReturnGetPacketCallback(
    GetPacketFunctor callback,
    std::string result,
    ReturnCode return_code) {
  client_container_.asio_service().post(std::bind(callback, result,
                                                  return_code));
}

std::shared_ptr<ChunkStore> RemoteStoreManager::chunk_store() const {
  return client_chunk_store_;
}

AlternativeStore::ValidationData RemoteStoreManager::GetValidationData(
    const std::string &packet_name,
    bool create_proof) const {
  AlternativeStore::ValidationData validation_data;
  if (!packet_name.empty()) {
    GetKeyring(packet_name, session_, &validation_data.key_pair);
    if (create_proof) {
      validation_data.ownership_proof =
          CreateOwnershipProof(validation_data.key_pair.private_key);
    }
  }

  return validation_data;
}

}  // namespace lifestuff

}  // namespace maidsafe
