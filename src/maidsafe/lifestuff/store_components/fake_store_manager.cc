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

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#include "maidsafe/dht/contact.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/session.h"

namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;

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

}  // namespace


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

FakeStoreManager::FakeStoreManager(std::shared_ptr<Session> session)
    : asio_service_(),
      work_(new boost::asio::io_service::work(asio_service_)),
      thread_group_(),
      client_chunk_store_(),
      chunk_action_authority_(),
      session_(session),
      temp_directory_path_() {
  boost::system::error_code error_code;
  temp_directory_path_ = fs::temp_directory_path(error_code);
  if (error_code)
    DLOG(ERROR) << "Failed to get temp directory: " << error_code.message();
  for (int i = 0; i < 3; ++i) {
    thread_group_.create_thread(
        std::bind(static_cast<std::size_t(boost::asio::io_service::*)()>
                      (&boost::asio::io_service::run), &asio_service_));
  }
}

FakeStoreManager::~FakeStoreManager() {
  work_.reset();
  asio_service_.stop();
  thread_group_.join_all();
}

int FakeStoreManager::Close(bool /*cancel_pending_ops*/) { return kSuccess; }

bool FakeStoreManager::KeyUnique(const std::string &key,
                                 const asymm::Identity &signing_key_id) {
  asymm::PublicKey public_key;
  if (!signing_key_id.empty())
    GetPublicKey(signing_key_id, session_, &public_key);
  return !chunk_action_authority_->Has(key, "", public_key);
}

void FakeStoreManager::KeyUnique(const std::string &key,
                                 const asymm::Identity &signing_key_id,
                                 const VoidFuncOneInt &cb) {
  asymm::PublicKey public_key;
  if (!signing_key_id.empty())
    GetPublicKey(signing_key_id, session_, &public_key);
  ReturnCode result(chunk_action_authority_->Has(key, "", public_key) ?
                    kKeyNotUnique : kKeyUnique);
  ExecReturnCodeCallback(cb, result);
}

int FakeStoreManager::GetPacket(const std::string &packet_name,
                                const std::string &signing_key_id,
                                std::string *result) {
  DLOG(INFO) << "Searching <" << Base32Substr(packet_name) << ">";

  BOOST_ASSERT(result);
  result->clear();

  asymm::PublicKey public_key;
  if (!signing_key_id.empty())
    GetPublicKey(signing_key_id, session_, &public_key);

  *result = chunk_action_authority_->Get(packet_name, "", public_key);
  if (result->empty()) {
    DLOG(ERROR) << "FakeStoreManager::GetPacket - Failure";
    return kGetPacketFailure;
  }

  return kSuccess;
}

void FakeStoreManager::GetPacket(const std::string &packetname,
                                 const asymm::Identity &signing_key_id,
                                 const GetPacketFunctor &lpf) {
  std::string result;
  ReturnCode rc(static_cast<ReturnCode>(GetPacket(packetname,
                                                  signing_key_id,
                                                  &result)));
  ExecReturnLoadPacketCallback(lpf, result, rc);
}

void FakeStoreManager::StorePacket(const std::string &packet_name,
                                   const std::string &value,
                                   const asymm::Identity &signing_key_id,
                                   const VoidFuncOneInt &cb) {
  DLOG(INFO) << "Storing <" << Base32Substr(packet_name) << ", "
             << Base32Substr(value) << ">";

  if (signing_key_id.empty()) {
    DLOG(ERROR) << "FakeStoreManager::StorePacket - No public key ID";
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
        DLOG(ERROR) << "FakeStoreManager::StorePacket - No public key";
        ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
        return;
      }
    }
  }


  if (!chunk_action_authority_->Store(packet_name, value, public_key)) {
    ExecReturnCodeCallback(cb, kStorePacketFailure);
    DLOG(ERROR) << "FakeStoreManager::StorePacket - Failure";
    return;
  }

  ExecReturnCodeCallback(cb, kSuccess);
}

void FakeStoreManager::DeletePacket(const std::string &packet_name,
                                    const asymm::Identity &signing_key_id,
                                    const VoidFuncOneInt &cb) {
  DLOG(INFO) << "Deleting <" << Base32Substr(packet_name);

  if (signing_key_id.empty()) {
    DLOG(ERROR) << "FakeStoreManager::DeletePacket - No public key ID";
    ExecReturnCodeCallback(cb, kDeletePacketFailure);
    return;
  }

  asymm::PublicKey public_key;
  GetPublicKey(signing_key_id, session_, &public_key);
  if (!asymm::ValidateKey(public_key)) {
    DLOG(ERROR) << "FakeStoreManager::DeletePacket - No public key";
    ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
    return;
  }

  asymm::PrivateKey private_key;
  GetPrivateKey(signing_key_id, session_, &private_key);
  if (!asymm::ValidateKey(private_key)) {
    DLOG(ERROR) << "FakeStoreManager::DeletePacket - No private key";
    ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
    return;
  }
  std::string ownership_proof(CreateOwnershipProof(private_key));

  if (!chunk_action_authority_->Delete(packet_name,
                                       "",
                                       ownership_proof,
                                       public_key)) {
    DLOG(ERROR) << "FakeStoreManager::DeletePacket - Failure";
    ExecReturnCodeCallback(cb, kDeletePacketFailure);
    return;
  }

  ExecReturnCodeCallback(cb, kSuccess);
}

void FakeStoreManager::ModifyPacket(const std::string &packet_name,
                                    const std::string &value,
                                    const asymm::Identity &signing_key_id,
                                    const VoidFuncOneInt &cb) {
  DLOG(INFO) << "Modifying <" << Base32Substr(packet_name) << "> to <"
             << Base32Substr(value) << ">";
  PrintDebugInfo(packet_name, value, "", "ModifyPacket");

  if (signing_key_id.empty()) {
    DLOG(ERROR) << "FakeStoreManager::ModifyPacket - No public key ID";
    ExecReturnCodeCallback(cb, kUpdatePacketFailure);
    return;
  }

  asymm::PublicKey public_key;
  GetPublicKey(signing_key_id, session_, &public_key);
  if (!asymm::ValidateKey(public_key)) {
    ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
    DLOG(ERROR) << "FakeStoreManager::ModifyPacket - No public key";
    return;
  }

  int64_t operation_diff;
  if (!chunk_action_authority_->Modify(packet_name,
                                       value,
                                       public_key,
                                       &operation_diff)) {
    DLOG(ERROR) << "FakeStoreManager::ModifyPacket - Failure - OD: "
                << operation_diff;
    ExecReturnCodeCallback(cb, kUpdatePacketFailure);
    return;
  }

  ExecReturnCodeCallback(cb, kSuccess);
}

void FakeStoreManager::ExecReturnCodeCallback(VoidFuncOneInt callback,
                                              ReturnCode return_code) {
  asio_service_.post(std::bind(callback, return_code));
}

void FakeStoreManager::ExecReturnLoadPacketCallback(GetPacketFunctor callback,
                                                    std::string result,
                                                    ReturnCode return_code) {
  asio_service_.post(std::bind(callback, result, return_code));
}

std::shared_ptr<ChunkStore> FakeStoreManager::chunk_store() const {
  return client_chunk_store_;
}

}  // namespace lifestuff

}  // namespace maidsafe
