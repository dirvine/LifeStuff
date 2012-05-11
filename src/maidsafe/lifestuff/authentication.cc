/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Creates, stores and accesses user details
* Version:      1.0
* Created:      2009-01-28-22.18.47
* Revision:     none
* Author:       Team
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

#include "maidsafe/lifestuff/authentication.h"

#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/regex.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/session.h"

namespace args = std::placeholders;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

namespace {

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

bool IsSignature(const int &packet_type) {
  switch (packet_type) {
    case passport::kMid:
    case passport::kSmid:
    case passport::kTmid:
    case passport::kStmid: return false; break;
    case passport::kPmid:
    case passport::kMaid:
    case passport::kAnmid:
    case passport::kAnsmid:
    case passport::kAntmid:
    case passport::kAnmpid:
    case passport::kAnmaid: return true;
    default: return false;
  }
}

passport::PacketType SigningPacket(passport::PacketType packet_type) {
  switch (packet_type) {
    case passport::kAnmid:
    case passport::kAnsmid:
    case passport::kAntmid:
    case passport::kAnmpid:
    case passport::kAnmaid: return packet_type;
    case passport::kMid: return passport::kAnmid;
    case passport::kSmid: return passport::kAnsmid;
    case passport::kTmid:
    case passport::kStmid: return passport::kAntmid;
    case passport::kMpid: return passport::kAnmpid;
    case passport::kMaid: return passport::kAnmaid;
    case passport::kPmid: return passport::kMaid;
    default: return passport::kUnknown;
  }
}

}  // unnamed namespace

// Internal Authentication struct
Authentication::PacketData::PacketData()
    : type(passport::kUnknown),
      name(),
      value(),
      signature(),
      public_key() {}

Authentication::PacketData::PacketData(
    const passport::PacketType &packet_type,
    std::shared_ptr<passport::Passport> passport,
    bool confirmed)
        : type(packet_type),
          name(passport->PacketName(type, confirmed)),
          value(),
          signature(passport->PacketSignature(packet_type, confirmed)),
          public_key() {
  if (IsSignature(packet_type)) {
    public_key = passport->SignaturePacketValue(packet_type, confirmed);
    BOOST_ASSERT(asymm::ValidateKey(public_key));
  } else {
    value = passport->IdentityPacketValue(packet_type, confirmed);
    BOOST_ASSERT(!value.empty());
  }
  BOOST_ASSERT(!name.empty());
  BOOST_ASSERT(!signature.empty());
}


Authentication::Authentication(
    std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
    std::shared_ptr<Session> session)
    : remote_chunk_store_(remote_chunk_store),
      session_(session),
      mutex_(),
      mid_mutex_(),
      smid_mutex_(),
      cond_var_(),
      tmid_op_status_(kNoUser),
      stmid_op_status_(kNoUser),
      kSingleOpTimeout_(20000) {}

Authentication::~Authentication() {
  if (tmid_op_status_ != kPendingMid || stmid_op_status_ != kPendingMid) {
    bool tmid_success(false), stmid_success(false);
    try {
      boost::mutex::scoped_lock lock(mutex_);
      tmid_success = cond_var_.timed_wait(
                         lock,
                         kSingleOpTimeout_ * 4,
                         std::bind(&Authentication::TmidOpDone, this));
      stmid_success = cond_var_.timed_wait(
                          lock,
                          kSingleOpTimeout_ * 2,
                          std::bind(&Authentication::StmidOpDone, this));
    }
    catch(const std::exception &e) {
      DLOG(WARNING) << "Authentication dtor: " << e.what()
                    << ", tmid_success: " << std::boolalpha << tmid_success
                    << ", stmid_success: " << std::boolalpha << stmid_success;
    }
#ifdef DEBUG
    if (!tmid_success)
      DLOG(WARNING) << "Authentication dtor: timed out waiting for TMID - "
                    << tmid_op_status_;
    if (!stmid_success)
      DLOG(WARNING) << "Authentication dtor: timed out waiting for STMID - "
                    << stmid_op_status_;
#endif
  }
}

int Authentication::GetUserInfo(const std::string &username,
                                const std::string &pin) {
  std::string mid_name(passport::MidName(username, pin, false)),
              smid_name(passport::MidName(username, pin, true));
  if (mid_name.empty() || smid_name.empty()) {
    tmid_op_status_ = kFailed;
    stmid_op_status_ = kFailed;
    DLOG(ERROR) << "Failed to get MID/SMID name";
    return kAuthenticationError;
  }

  session_->set_username(username);
  session_->set_pin(pin);
  tmid_op_status_ = kPending;
  stmid_op_status_ = kPending;

  pcs::RemoteChunkStore::ValidationData validation_data;
  KeysAndProof(passport::kAnmid, &validation_data, false);
  std::string encrypted_mid(
      remote_chunk_store_->Get(pca::ApplyTypeToName(mid_name,
                                                    pca::kModifiableByOwner),
                               validation_data));
  if (encrypted_mid.empty()) {
    DLOG(ERROR) << "Failed to obtain MID";
    tmid_op_status_ = kFailed;
    stmid_op_status_ = kFailed;
//    return kAuthenticationError;
  } else {
    GetMidCallback(encrypted_mid, true);

    validation_data = pcs::RemoteChunkStore::ValidationData();
    KeysAndProof(passport::kAnsmid, &validation_data, false);
    std::string encrypted_smid(
        remote_chunk_store_->Get(pca::ApplyTypeToName(smid_name,
                                                      pca::kModifiableByOwner),
                                 validation_data));
    if (encrypted_smid.empty()) {
      DLOG(ERROR) << "Failed to obtain SMID";
      tmid_op_status_ = kFailed;
      stmid_op_status_ = kFailed;
  //    return kAuthenticationError;
    } else {
      GetSmidCallback(encrypted_smid, true);
    }
  }

  // Wait until both ops are finished here
  bool mid_finished(false), smid_finished(false);
  while (!(mid_finished && smid_finished)) {
    Sleep(boost::posix_time::milliseconds(500));
    {
      boost::mutex::scoped_lock lochly(mid_mutex_);
      mid_finished = tmid_op_status_ != kPending;
    }
    {
      boost::mutex::scoped_lock lochverly(smid_mutex_);
      smid_finished = stmid_op_status_ != kPending;
    }
  }

  if (tmid_op_status_ == kSucceeded || stmid_op_status_ == kSucceeded)
    return kUserExists;

  session_->set_username("");
  session_->set_pin("");
  tmid_op_status_ = kNoUser;
  stmid_op_status_ = kNoUser;
  return kUserDoesntExist;
}

void Authentication::GetMidCallback(const std::string &value,
                                    bool return_code) {
  if (!return_code) {
    DLOG(WARNING) << "Auth::GetMidCallback: No MID";
    {
      boost::mutex::scoped_lock loch_chapala(mid_mutex_);
      tmid_op_status_ = kFailed;
    }
    return;
  }

  pca::SignedData packet;
  if (!packet.ParseFromString(value) || packet.data().empty()) {
    DLOG(WARNING) << "Auth::GetMidCallback: Failed to parse";
    {
      boost::mutex::scoped_lock loch_chapala(mid_mutex_);
      tmid_op_status_ = kFailed;
    }
    return;
  }

  std::string tmid_name(passport::DecryptRid(session_->username(),
                                             session_->pin(),
                                             packet.data()));
  if (tmid_name.empty()) {
    DLOG(WARNING) << "Failed to decrypt rid";
    {
      boost::mutex::scoped_lock loch_chapala(mid_mutex_);
      tmid_op_status_ = kFailed;
    }
    return;
  }

  DLOG(INFO) << "Auth::GetMidCallback: TMID - (" << Base32Substr(tmid_name)
                << ", " << Base32Substr(value) << ")";

  pcs::RemoteChunkStore::ValidationData validation_data;
  KeysAndProof(passport::kAntmid, &validation_data, false);
  std::string encrypted_tmid(
      remote_chunk_store_->Get(pca::ApplyTypeToName(tmid_name,
                                                    pca::kModifiableByOwner),
                               validation_data));
  if (encrypted_tmid.empty()) {
    DLOG(ERROR) << "Failed to obtain TMID";
    tmid_op_status_ = kFailed;
    return;
  }
  GetTmidCallback(encrypted_tmid, true);
}

void Authentication::GetSmidCallback(const std::string &value,
                                     bool return_code) {
  if (!return_code) {
    DLOG(WARNING) << "Auth::GetSmidCallback: No SMID";
    {
      boost::mutex::scoped_lock loch_chapala(smid_mutex_);
      stmid_op_status_ = kFailed;
    }
    return;
  }

  pca::SignedData packet;
  if (!packet.ParseFromString(value) || packet.data().empty()) {
    DLOG(WARNING) << "Auth::GetSmidCallback: Failed to parse";
    {
      boost::mutex::scoped_lock loch_chapala(smid_mutex_);
      stmid_op_status_ = kFailed;
    }
    return;
  }

  std::string stmid_name(passport::DecryptRid(session_->username(),
                                              session_->pin(),
                                              packet.data()));
  if (stmid_name.empty()) {
    DLOG(WARNING) << "Failed to decrypt surrogate rid";
    {
      boost::mutex::scoped_lock loch_chapala(smid_mutex_);
      stmid_op_status_ = kFailed;
    }
    return;
  }

  pcs::RemoteChunkStore::ValidationData validation_data;
  KeysAndProof(passport::kAntmid, &validation_data, false);
  std::string encrypted_stmid(
      remote_chunk_store_->Get(pca::ApplyTypeToName(stmid_name,
                                                    pca::kModifiableByOwner),
                               validation_data));
  if (encrypted_stmid.empty()) {
    DLOG(ERROR) << "Failed to obtain TMID";
    stmid_op_status_ = kFailed;
    return;
  }
  GetStmidCallback(encrypted_stmid, true);
}

void Authentication::GetTmidCallback(const std::string &value,
                                     bool return_code) {
  if (!return_code) {
    DLOG(WARNING) << "Auth::GetTmidCallback: No TMID";
    {
      boost::mutex::scoped_lock loch_chapala(mid_mutex_);
      tmid_op_status_ = kFailed;
    }
    return;
  }

  pca::SignedData packet;
  if (!packet.ParseFromString(value) || packet.data().empty()) {
    DLOG(WARNING) << "Auth::GetTmidCallback: Failed to parse";
    {
      boost::mutex::scoped_lock loch_chapala(mid_mutex_);
      tmid_op_status_ = kFailed;
    }
    return;
  }

//  encrypted_tmid_ = packet.data();
  session_->set_encrypted_tmid(packet.data());  
  tmid_op_status_ = kSucceeded;
}

void Authentication::GetStmidCallback(const std::string &value,
                                      bool return_code) {
  if (!return_code) {
    DLOG(WARNING) << "Auth::GetStmidCallback: No TMID";
    {
      boost::mutex::scoped_lock loch_chapala(smid_mutex_);
      stmid_op_status_ = kFailed;
    }
    return;
  }

  pca::SignedData packet;
  if (!packet.ParseFromString(value) || packet.data().empty()) {
    DLOG(WARNING) << "Auth::GetStmidCallback: Failed to parse";
    {
      boost::mutex::scoped_lock loch_chapala(smid_mutex_);
      stmid_op_status_ = kFailed;
    }
    return;
  }

  session_->set_encrypted_stmid(packet.data());
  stmid_op_status_ = kSucceeded;
}

int Authentication::CreateUserSysPackets(const std::string &username,
                                         const std::string &pin) {
  bool already_initialised(false);
  {
    boost::mutex::scoped_lock lock(mutex_);
    if (tmid_op_status_ == kNoUser) {
      if (stmid_op_status_ == kNoUser || stmid_op_status_ == kFailed)
        already_initialised = true;
    } else if (tmid_op_status_ == kFailed) {
      if (stmid_op_status_ == kNoUser || stmid_op_status_ == kFailed)
        already_initialised = true;
    }
  }

  if (!already_initialised) {
    DLOG(ERROR) << "Authentication::CreateUserSysPackets - NOT INTIALISED";
    return kAuthenticationError;
  }
  session_->set_username(username);
  session_->set_pin(pin);

  if (session_->passport_->CreateSigningPackets() != kSuccess) {
    DLOG(ERROR) << "Authentication::CreateUserSysPackets - Not initialised";
    session_->set_username("");
    session_->set_pin("");
    return kAuthenticationError;
  }

  OpStatus anmaid_status(kPending);
  StoreSignaturePacket(passport::kAnmaid, &anmaid_status, NULL);
  OpStatus anmid_status(kPending);
  StoreSignaturePacket(passport::kAnmid, &anmid_status, NULL);
  OpStatus ansmid_status(kPending);
  StoreSignaturePacket(passport::kAnsmid, &ansmid_status, NULL);
  OpStatus antmid_status(kPending);
  StoreSignaturePacket(passport::kAntmid, &antmid_status, NULL);
  OpStatus maid_status(kPending);
  StoreSignaturePacket(passport::kMaid, &maid_status, &anmaid_status);
  OpStatus pmid_status(kPending);
  StoreSignaturePacket(passport::kPmid, &pmid_status, &maid_status);
  bool success(false);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(
                  lock,
                  kSingleOpTimeout_ * 10,
                  std::bind(&Authentication::ThreeSystemPacketsOpDone, this,
                            &pmid_status, &anmid_status, &antmid_status));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::CreateUserSysPackets: " << e.what()
                << ", success: " << std::boolalpha << success;
  }

#ifdef DEBUG
  if (!success)
    DLOG(INFO) << "Authentication::CreateUserSysPackets: timed out.";
#endif

  if ((anmaid_status == kSucceeded) && (anmid_status == kSucceeded) &&
      (ansmid_status == kSucceeded) && (antmid_status == kSucceeded) &&
      (maid_status == kSucceeded) && (pmid_status == kSucceeded)) {
    if (session_->passport_->ConfirmSigningPackets() == kSuccess) {
      return kSuccess;
    } else {
      DLOG(ERROR) << "ConfirmSigningPackets failed";
    }
  }

  session_->set_username("");
  session_->set_pin("");

  return kAuthenticationError;
}

void Authentication::StoreSignaturePacket(
    const passport::PacketType &packet_type,
    OpStatus *op_status,
    OpStatus *dependent_op_status) {
  // Wait for dependent op or timeout.
  bool success(true);
  if (dependent_op_status) {
    boost::mutex::scoped_lock lock(mutex_);
    try {
      success = cond_var_.timed_wait(
                    lock,
                    kSingleOpTimeout_,
                    std::bind(&Authentication::SignerDone, this,
                              dependent_op_status));
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << DebugStr(packet_type) << ": " << e.what();
      success = false;
    }
    success = (*dependent_op_status == kSucceeded);
  }
  if (!success) {
    DLOG(ERROR) << DebugStr(packet_type) << ": failed wait for dependent op";
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kFailed;
    cond_var_.notify_all();
    return;
  }

  // Get packet
  std::string packet_name(
      pca::ApplyTypeToName(session_->passport_->PacketName(packet_type, false),
                           pca::kModifiableByOwner));
  if (packet_name.empty()) {
    DLOG(ERROR) << DebugStr(packet_type) << ": failed init";
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kFailed;
    cond_var_.notify_all();
    return;
  }

  VoidFunctionOneBool functor =
      std::bind(&Authentication::SignaturePacketStoreCallback,
                this, args::_1, packet_type, op_status);
  pcs::RemoteChunkStore::ValidationData validation_data;
  KeysAndProof(passport::kAnmid, &validation_data, false);
  pca::SignedData signed_data;
  std::string encoded_public_key;
  asymm::EncodePublicKey(validation_data.key_pair.public_key,
                         &encoded_public_key);
  BOOST_ASSERT(!encoded_public_key.empty());
  signed_data.set_data(encoded_public_key);
  signed_data.set_signature(validation_data.key_pair.validation_token);

  remote_chunk_store_->Store(packet_name,
                             signed_data.SerializeAsString(),
                             functor,
                             validation_data);
}

void Authentication::SignaturePacketStoreCallback(
    bool return_code,
    passport::PacketType packet_type,
    OpStatus *op_status) {
  boost::mutex::scoped_lock lock(mutex_);
  if (return_code) {
    *op_status = kSucceeded;
  } else {
    DLOG(ERROR) << DebugStr(packet_type) << ": Failed to store.";
    *op_status = kFailed;
//    session_->passport_->RevertSignaturePacket(packet_type);
  }
  cond_var_.notify_all();
}

int Authentication::CreateTmidPacket(
    const std::string &password,
    const std::string &serialised_data_atlas,
    const std::string &surrogate_serialised_data_atlas) {
  int result(kPendingResult);
  result = session_->passport_->SetIdentityPackets(
               session_->username(),
               session_->pin(),
               password,
               serialised_data_atlas,
               surrogate_serialised_data_atlas);
  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::CreateTmidPacket: Failed init.";
    return kAuthenticationError;
  }

  PacketData mid(passport::kMid, session_->passport_, false),
             smid(passport::kSmid, session_->passport_, false),
             tmid(passport::kTmid, session_->passport_, false),
             stmid(passport::kStmid, session_->passport_, false);

  pcs::RemoteChunkStore::ValidationData validation_data_mid;
  KeysAndProof(passport::kAnmid, &validation_data_mid, true);
  pcs::RemoteChunkStore::ValidationData validation_data_smid;
  KeysAndProof(passport::kAnsmid, &validation_data_smid, true);
  pcs::RemoteChunkStore::ValidationData validation_data_tmid;
  KeysAndProof(passport::kAntmid, &validation_data_tmid, true);

  result = StorePacket(mid, validation_data_mid);
  if (result == kSuccess) {
    result = StorePacket(smid, validation_data_smid);
    if (result == kSuccess) {
      result = StorePacket(tmid, validation_data_tmid);
      if (result == kSuccess) {
        result = StorePacket(stmid, validation_data_tmid);
      }
    }
  }

  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::CreateTmidPacket: Failed.";
    return kAuthenticationError;
  }
  if (session_->passport_->ConfirmIdentityPackets() != kSuccess) {
    DLOG(ERROR) << "Authentication::CreateTmidPacket: Failed to confirm.";
    return kAuthenticationError;
  }
  session_->set_password(password);
  session_->set_serialised_data_atlas(serialised_data_atlas);  
  return kSuccess;
}

void Authentication::SaveSession(const std::string &serialised_data_atlas,
                                 const VoidFunctionOneInt &functor) {
  int result(session_->passport_->SetIdentityPackets(session_->username(),
                                                     session_->pin(),
                                                     session_->password(),
                                                     serialised_data_atlas,
                                                     /*serialised_data_atlas_*/
                                                     session_->serialised_data_atlas()));
  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::SaveSession: failed SetIdentityPackets.";
    return functor(kAuthenticationError);
  }

  PacketData mid(passport::kMid, session_->passport_, false),
             smid(passport::kSmid, session_->passport_, false),
             tmid(passport::kTmid, session_->passport_, false),
             old_stmid(passport::kStmid, session_->passport_, true);
  std::string mid_name, serialised_mid, mid_signing_id;
  std::string smid_name, serialised_smid, smid_signing_id;
  std::string tmid_name, serialised_tmid, tmid_signing_id;
  CreateSignedData(mid, true, &mid_name, &serialised_mid, &mid_signing_id);
  CreateSignedData(smid, true, &smid_name, &serialised_smid, &smid_signing_id);
  CreateSignedData(tmid, true, &tmid_name, &serialised_tmid, &tmid_signing_id);

  pcs::RemoteChunkStore::ValidationData validation_data_mid;
  KeysAndProof(passport::kAnmid, &validation_data_mid, true);
  pcs::RemoteChunkStore::ValidationData validation_data_smid;
  KeysAndProof(passport::kAnsmid, &validation_data_smid, true);
  pcs::RemoteChunkStore::ValidationData validation_data_tmid;
  KeysAndProof(passport::kAntmid, &validation_data_tmid, true);

  SaveSessionDataPtr save_session_data(
      new SaveSessionData(functor, kRegular, serialised_data_atlas));

  // Update MID
  VoidFunctionOneBool callback(std::bind(&Authentication::ProcessingSaveSession,
                                         this, args::_1, passport::kMid,
                                         save_session_data));
  remote_chunk_store_->Modify(mid_name,
                              serialised_mid,
                              callback,
                              validation_data_mid);

  // Update SMID
  callback = std::bind(&Authentication::ProcessingSaveSession, this, args::_1,
                       passport::kSmid, save_session_data);
  remote_chunk_store_->Modify(smid_name,
                              serialised_smid,
                              callback,
                              validation_data_smid);

  // Store new TMID
  callback = std::bind(&Authentication::ProcessingSaveSession, this, args::_1,
                       passport::kTmid, save_session_data);
  remote_chunk_store_->Store(tmid_name,
                             serialised_tmid,
                             callback,
                             validation_data_tmid);

  // Delete old STMID
  callback = std::bind(&Authentication::ProcessingSaveSession, this, args::_1,
                       passport::kStmid, save_session_data);
  std::string old_stmid_name(pca::ApplyTypeToName(old_stmid.name,
                                                  pca::kModifiableByOwner));
  remote_chunk_store_->Delete(old_stmid_name, callback, validation_data_tmid);
}

void Authentication::ProcessingSaveSession(
    bool return_code,
    passport::PacketType packet_type,
    SaveSessionDataPtr save_session_data) {
  OpStatus op_status(kSucceeded);
  if (!return_code) {
    op_status = kFailed;
    DLOG(INFO) << "Authentication::ProcessingSaveSession - pt: "
               << DebugStr(packet_type) << ", result: " << return_code;
  }

  boost::mutex::scoped_lock lock(mutex_);
  switch (packet_type) {
    case passport::kMid:
      save_session_data->process_mid = op_status;
      break;
    case passport::kSmid:
      save_session_data->process_smid = op_status;
      break;
    case passport::kTmid:
      save_session_data->process_tmid = op_status;
      break;
    case passport::kStmid:
      save_session_data->process_stmid = op_status;
      break;
    default:
      break;
  }
  if ((save_session_data->process_mid == kPending) ||
      (save_session_data->process_smid == kPending) ||
      (save_session_data->process_tmid == kPending) ||
      (save_session_data->process_stmid == kPending)) {
    return;
  }

  if ((save_session_data->process_mid == kFailed) ||
      (save_session_data->process_smid == kFailed) ||
      (save_session_data->process_tmid == kFailed) ||
      (save_session_data->process_stmid == kFailed)) {
    DLOG(ERROR) << "Failed one operation.";
    lock.unlock();
//    if (save_session_data->op_type == kRegular ||
//        save_session_data->op_type == kSaveNew ||
//        save_session_data->op_type == kUpdate) {
//      session_->passport_->RevertMasterDataUpdate();
//    }
    return save_session_data->functor(kAuthenticationError);
  }
  lock.unlock();
  if (save_session_data->op_type == kRegular ||
      save_session_data->op_type == kSaveNew ||
      save_session_data->op_type == kUpdate) {
    if (session_->passport_->ConfirmIdentityPackets() != kSuccess) {
      DLOG(ERROR) << "Failed to confirm ID packets.";
      return save_session_data->functor(kAuthenticationError);
    }
    session_->set_serialised_data_atlas(
        save_session_data->serialised_data_atlas);  
  }
  save_session_data->functor(kSuccess);
}

int Authentication::SaveSession(const std::string &serialised_data_atlas) {
  int result(kPendingResult);
  VoidFunctionOneInt functor(std::bind(&Authentication::SaveSessionCallback,
                                       this, args::_1, &result));
  SaveSession(serialised_data_atlas, functor);
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(
                  lock,
                  kSingleOpTimeout_ * 4,
                  std::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
    DLOG(WARNING) << "Authentication::SaveSession: " << e.what();
    success = false;
  }
  if (!success) {
    DLOG(ERROR) << "Authentication::SaveSession: timed out.";
    return kAuthenticationError;
  }
  return result;
}

void Authentication::GetMasterDataMap(
    const std::string &password,
    std::string *serialised_data_atlas,
    std::string *surrogate_serialised_data_atlas) {
  serialised_data_atlas->clear();
  surrogate_serialised_data_atlas->clear();

  *serialised_data_atlas = passport::DecryptMasterData(session_->username(),
                                                       session_->pin(),
                                                       password,
                                                       /*encrypted_tmid_*/
                                                       session_->encrypted_tmid());
  *surrogate_serialised_data_atlas =
      passport::DecryptMasterData(session_->username(),
                                  session_->pin(),
                                  password,
                                  /*encrypted_stmid_*/
                                  session_->encrypted_stmid());

  if (!serialised_data_atlas->empty()) {
    session_->set_serialised_data_atlas(*serialised_data_atlas);
    return;
  }

  if (!surrogate_serialised_data_atlas->empty()) {
    session_->set_serialised_data_atlas(*surrogate_serialised_data_atlas);
    return;
  }
}

int Authentication::SetLoggedInData(const std::string &ser_da,
                                    const std::string &surrogate_ser_da) {
  int n(session_->passport_->SetIdentityPackets(session_->username(),
                                                session_->pin(),
                                                session_->password(),
                                                ser_da,
                                                surrogate_ser_da));
  if (n != kSuccess) {
    DLOG(ERROR) << "Failed SetIdentityPackets: " << n;
    return -9003;
  }
  n = session_->passport_->ConfirmIdentityPackets();
  if (n != kSuccess) {
    DLOG(ERROR) << "Failed ConfirmIdentityPackets: " << n;
    return -9003;
  }

  return kSuccess;
}

int Authentication::ChangeUsername(const std::string &serialised_data_atlas,
                                   const std::string &new_username) {
  return ChangeUserData(serialised_data_atlas, new_username, session_->pin());
}

int Authentication::ChangePin(const std::string &serialised_data_atlas,
                              const std::string &new_pin) {
  return ChangeUserData(serialised_data_atlas, session_->username(), new_pin);
}

int Authentication::ChangeUserData(const std::string &serialised_data_atlas,
                                   const std::string &new_username,
                                   const std::string &new_pin) {
  int result = session_->passport_->SetIdentityPackets(new_username,
                                                       new_pin,
                                                       session_->password(),
                                                       serialised_data_atlas,
                                                       /*serialised_data_atlas_*/
                                                       session_->serialised_data_atlas());
  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::ChangeUserData: failed SetIdentityPackets.";
    return kAuthenticationError;
  }

  PacketData old_mid(passport::kMid, session_->passport_, true),
             old_smid(passport::kSmid, session_->passport_, true),
             old_tmid(passport::kTmid, session_->passport_, true),
             old_stmid(passport::kStmid, session_->passport_, true),
             mid(passport::kMid, session_->passport_, false),
             smid(passport::kSmid, session_->passport_, false),
             tmid(passport::kTmid, session_->passport_, false),
             stmid(passport::kStmid, session_->passport_, false);

  pcs::RemoteChunkStore::ValidationData validation_data_mid;
  KeysAndProof(passport::kAnmid, &validation_data_mid, true);
  pcs::RemoteChunkStore::ValidationData validation_data_smid;
  KeysAndProof(passport::kAnsmid, &validation_data_smid, true);
  pcs::RemoteChunkStore::ValidationData validation_data_tmid;
  KeysAndProof(passport::kAntmid, &validation_data_tmid, true);

  VoidFunctionOneInt int_callback(
      std::bind(&Authentication::ChangeUserDataCallback, this,
                args::_1, &result));
  SaveSessionDataPtr save_session_data(
      new SaveSessionData(int_callback, kIsUnique, serialised_data_atlas));
  result = kPendingResult;
  save_session_data->process_mid = kPending;
  save_session_data->process_smid = kPending;
  save_session_data->process_tmid = kPending;
  save_session_data->process_stmid = kPending;
  save_session_data->op_type = kSaveNew;

  std::string mid_name, serialised_mid, mid_signing_id;
  std::string smid_name, serialised_smid, smid_signing_id;
  std::string tmid_name, serialised_tmid, tmid_signing_id;
  std::string stmid_name, serialised_stmid, stmid_signing_id;
  CreateSignedData(mid, true, &mid_name, &serialised_mid, &mid_signing_id);
  CreateSignedData(smid, true, &smid_name, &serialised_smid, &smid_signing_id);
  CreateSignedData(tmid, true, &tmid_name, &serialised_tmid, &tmid_signing_id);
  CreateSignedData(stmid,
                   true,
                   &stmid_name,
                   &serialised_stmid,
                   &stmid_signing_id);

  // Store new MID
  VoidFunctionOneBool bool_callback =
      std::bind(&Authentication::ProcessingSaveSession, this, args::_1,
                passport::kMid, save_session_data);
  remote_chunk_store_->Store(mid_name,
                             serialised_mid,
                             bool_callback,
                             validation_data_mid);

  // Store new SMID
  bool_callback = std::bind(&Authentication::ProcessingSaveSession, this,
                            args::_1, passport::kSmid, save_session_data);
  remote_chunk_store_->Store(smid_name,
                             serialised_smid,
                             bool_callback,
                             validation_data_smid);

  // Store new TMID
  bool_callback = std::bind(&Authentication::ProcessingSaveSession, this,
                            args::_1, passport::kTmid, save_session_data);
  remote_chunk_store_->Store(tmid_name,
                             serialised_tmid,
                             bool_callback,
                             validation_data_tmid);

  // Store new STMID
  bool_callback = std::bind(&Authentication::ProcessingSaveSession, this,
                            args::_1, passport::kStmid, save_session_data);
  remote_chunk_store_->Store(stmid_name,
                             serialised_stmid,
                             bool_callback,
                             validation_data_tmid);

  // Wait for storing to complete
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(
                  lock,
                  kSingleOpTimeout_ * 4,
                  std::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::ChangeUserData: storing: " << e.what();
    success = false;
  }
  if (result != kSuccess || !success) {
    DLOG(ERROR) << "Authentication::ChangeUserData: storing packets failed.";
    return kAuthenticationError;
  }

  // Prepare to delete old packets
  result = kPendingResult;
  save_session_data->process_mid = kPending;
  save_session_data->process_smid = kPending;
  save_session_data->process_tmid = kPending;
  save_session_data->process_stmid = kPending;
  save_session_data->functor =
      std::bind(&Authentication::ChangeUserDataCallback,
                this, args::_1, &result);
  save_session_data->op_type = kDeleteOld;

  // Delete old MID
  bool_callback = std::bind(&Authentication::ProcessingSaveSession, this,
                            args::_1, passport::kMid, save_session_data);
  std::string old_packet_name(pca::ApplyTypeToName(old_mid.name,
                                                   pca::kModifiableByOwner));
  remote_chunk_store_->Delete(old_packet_name,
                              bool_callback,
                              validation_data_mid);

  // Delete old SMID
  bool_callback = std::bind(&Authentication::ProcessingSaveSession, this,
                            args::_1, passport::kSmid, save_session_data);
  old_packet_name = pca::ApplyTypeToName(old_smid.name,
                                         pca::kModifiableByOwner);
  remote_chunk_store_->Delete(old_packet_name,
                              bool_callback,
                              validation_data_smid);

  // Delete old TMID
  bool_callback = std::bind(&Authentication::ProcessingSaveSession, this,
                            args::_1, passport::kTmid, save_session_data);
  old_packet_name = pca::ApplyTypeToName(old_tmid.name,
                                         pca::kModifiableByOwner);
  remote_chunk_store_->Delete(old_packet_name,
                              bool_callback,
                              validation_data_tmid);

  // Delete old STMID
  bool_callback = std::bind(&Authentication::ProcessingSaveSession, this,
                            args::_1, passport::kStmid, save_session_data);
  old_packet_name = pca::ApplyTypeToName(old_stmid.name,
                                         pca::kModifiableByOwner);
  remote_chunk_store_->Delete(old_packet_name,
                              bool_callback,
                              validation_data_tmid);

  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(
                  lock,
                  kSingleOpTimeout_ * 4,
                  std::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::ChangeUserData - deleting: " << e.what();
    success = false;
  }
#ifdef DEBUG
  if (!success)
    DLOG(INFO) << "Authentication::ChangeUserData: timed out deleting.";
#endif
  // Result of deletions not considered here.
  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::ChangeUserData: failed to confirm change.";
    return kAuthenticationError;
  }

  session_->set_username(new_username);
  session_->set_pin(new_pin);

  return kSuccess;
}

int Authentication::ChangePassword(const std::string &serialised_data_atlas,
                                   const std::string &new_password) {
  int result = session_->passport_->SetIdentityPackets(session_->username(),
                                                       session_->pin(),
                                                       new_password,
                                                       serialised_data_atlas,
                                                       /*serialised_data_atlas_*/
                                                       session_->serialised_data_atlas());
  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::ChangePassword: failed SetIdentityPackets.";
    return kAuthenticationError;
  }

  PacketData mid(passport::kMid, session_->passport_, false),
             smid(passport::kSmid, session_->passport_, false),
             tmid(passport::kTmid, session_->passport_, false),
             stmid(passport::kStmid, session_->passport_, false),
             old_tmid(passport::kTmid, session_->passport_, true),
             old_stmid(passport::kStmid, session_->passport_, true);
  std::string mid_name, serialised_mid, mid_signing_id;
  std::string smid_name, serialised_smid, smid_signing_id;
  std::string tmid_name, serialised_tmid, tmid_signing_id;
  std::string stmid_name, serialised_stmid, stmid_signing_id;
  CreateSignedData(mid, true, &mid_name, &serialised_mid, &mid_signing_id);
  CreateSignedData(smid, true, &smid_name, &serialised_smid, &smid_signing_id);
  CreateSignedData(tmid, true, &tmid_name, &serialised_tmid, &tmid_signing_id);
  CreateSignedData(stmid,
                   true,
                   &stmid_name,
                   &serialised_stmid,
                   &stmid_signing_id);

  pcs::RemoteChunkStore::ValidationData validation_data_mid;
  KeysAndProof(passport::kAnmid, &validation_data_mid, true);
  pcs::RemoteChunkStore::ValidationData validation_data_smid;
  KeysAndProof(passport::kAnsmid, &validation_data_smid, true);
  pcs::RemoteChunkStore::ValidationData validation_data_tmid;
  KeysAndProof(passport::kAntmid, &validation_data_tmid, true);

  result = kPendingResult;
  SaveSessionDataPtr save_session_data(new SaveSessionData(
      std::bind(&Authentication::ChangeUserDataCallback, this, args::_1,
                &result),
      kUpdate,
      serialised_data_atlas));

  // Update MID
  VoidFunctionOneBool callback(std::bind(&Authentication::ProcessingSaveSession,
                                         this, args::_1, passport::kMid,
                                         save_session_data));
  remote_chunk_store_->Modify(mid_name,
                              serialised_mid,
                              callback,
                              validation_data_mid);

  // Update SMID
  callback = std::bind(&Authentication::ProcessingSaveSession, this, args::_1,
                       passport::kSmid, save_session_data);
  remote_chunk_store_->Modify(smid_name,
                              serialised_smid,
                              callback,
                              validation_data_smid);

  // Store new TMID
  callback = std::bind(&Authentication::ProcessingSaveSession, this, args::_1,
                       passport::kTmid, save_session_data);
  remote_chunk_store_->Store(tmid_name,
                             serialised_tmid,
                             callback,
                             validation_data_tmid);

  // Store new STMID
  callback = std::bind(&Authentication::ProcessingSaveSession, this, args::_1,
                       passport::kStmid, save_session_data);
  remote_chunk_store_->Store(stmid_name,
                             serialised_stmid,
                             callback,
                             validation_data_tmid);

  // Wait for storing/updating to complete
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(
                  lock,
                  kSingleOpTimeout_ * 4,
                  std::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::ChangePassword: storing: " << e.what();
    success = false;
  }
  if (result != kSuccess || !success) {
    DLOG(ERROR) << "Authentication::ChangePassword: storing packets failed.";
//    session_->passport_->RevertUserDataChange();
    return kAuthenticationError;
  }

  // Prepare to delete old packets
  result = kPendingResult;
  save_session_data->process_tmid = kPending;
  save_session_data->process_stmid = kPending;
  save_session_data->functor =
      std::bind(&Authentication::ChangeUserDataCallback,
                this, args::_1, &result);
  save_session_data->op_type = kDeleteOld;

  // Delete old TMID
  callback = std::bind(&Authentication::ProcessingSaveSession, this, args::_1,
                       passport::kTmid, save_session_data);
  std::string old_packet_name(pca::ApplyTypeToName(old_tmid.name,
                                                   pca::kModifiableByOwner));
  remote_chunk_store_->Delete(old_packet_name, callback, validation_data_tmid);

  // Delete old STMID
  callback = std::bind(&Authentication::ProcessingSaveSession, this, args::_1,
                       passport::kStmid, save_session_data);
  old_packet_name = pca::ApplyTypeToName(old_stmid.name,
                                         pca::kModifiableByOwner);
  remote_chunk_store_->Delete(old_packet_name, callback, validation_data_tmid);

  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(
                  lock,
                  kSingleOpTimeout_ * 2,
                  std::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::ChangePassword - deleting: " << e.what();
    success = false;
  }
#ifdef DEBUG
  if (!success)
    DLOG(INFO) << "Authentication::ChangePassword: timed out deleting.";
#endif
  // Result of deletions not considered here.
  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::ChangePassword: failed to confirm change.";
//    session_->passport_->RevertUserDataChange();
    return kAuthenticationError;
  }
  session_->set_password(new_password);
  return kSuccess;
}

int Authentication::StorePacket(
    const PacketData &packet,
    const pcs::RemoteChunkStore::ValidationData &validation_data) {
  int result(kPendingResult);
  std::string packet_name, serialised_packet, signing_id;
  bool confirmed(packet.type != passport::kMaid &&
                 packet.type != passport::kPmid);
  CreateSignedData(packet,
                   confirmed,
                   &packet_name,
                   &serialised_packet,
                   &signing_id);
  VoidFunctionOneBool functor = std::bind(&Authentication::PacketOpCallback,
                                          this, args::_1, &result);
  remote_chunk_store_->Store(packet_name,
                             serialised_packet,
                             functor,
                             validation_data);

  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(
                  lock,
                  kSingleOpTimeout_,
                  std::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::StorePacket: " << e.what();
    success = false;
  }
  if (!success) {
    DLOG(ERROR) << "Authentication::StorePacket: timed out.";
    return kAuthenticationError;
  }

  DLOG(INFO) << "Authentication::StorePacket: result=" << result << " - "
              << Base32Substr(packet.name);

  return result;
}

int Authentication::DeletePacket(const PacketData &packet) {
  int result(kPendingResult);
  VoidFunctionOneBool functor = std::bind(&Authentication::PacketOpCallback,
                                          this, args::_1, &result);
  std::string packet_name, signing_id;
  GetPacketNameAndKeyId(packet.name,
                        packet.type,
                        true,
                        &packet_name,
                        &signing_id);
  pcs::RemoteChunkStore::ValidationData validation_data;
  KeysAndProof(SigningPacket(packet.type), &validation_data, true);
  remote_chunk_store_->Delete(packet_name, functor, validation_data);

  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(
                  lock,
                  kSingleOpTimeout_,
                  std::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
    DLOG(WARNING) << "Authentication::DeletePacket: " << e.what();
    success = false;
  }
  if (!success) {
    DLOG(ERROR) << "Authentication::DeletePacket: Timed out.";
    return kAuthenticationError;
  }
#ifdef DEBUG
  if (result != kSuccess)
    DLOG(INFO) << "Authentication::DeletePacket result = " << result;
#endif
  return result;
}

void Authentication::PacketOpCallback(bool return_code, int *op_result) {
  boost::mutex::scoped_lock lock(mutex_);
  if (return_code)
    *op_result = kSuccess;
  else
    *op_result = kAuthenticationError;
  cond_var_.notify_all();
}

void Authentication::CreateSignedData(const PacketData &packet,
                                      bool signing_packet_confirmed,
                                      std::string *signed_data_name,
                                      std::string *serialised_signed_data,
                                      asymm::Identity *signing_id) {
  pca::SignedData signed_data;
  BOOST_ASSERT(!packet.name.empty());
  BOOST_ASSERT(!packet.signature.empty());
  if (packet.value.empty()) {
    std::string encoded_public_key;
    asymm::EncodePublicKey(packet.public_key, &encoded_public_key);
    BOOST_ASSERT(!encoded_public_key.empty());
    signed_data.set_data(encoded_public_key);
  } else {
    BOOST_ASSERT(!packet.value.empty());
    signed_data.set_data(packet.value);
  }
  signed_data.set_signature(packet.signature);
  *serialised_signed_data = signed_data.SerializeAsString();
  GetPacketNameAndKeyId(packet.name,
                        packet.type,
                        signing_packet_confirmed,
                        signed_data_name,
                        signing_id);
}

void Authentication::GetPacketNameAndKeyId(const std::string &packet_name_raw,
                                           const passport::PacketType &type,
                                           bool signing_packet_confirmed,
                                           std::string *packet_name,
                                           std::string *signing_id) {
  switch (type) {
    case passport::kAnmid:
    case passport::kAnsmid:
    case passport::kAntmid:
    case passport::kAnmpid:
    case passport::kAnmaid:
      *packet_name = pca::ApplyTypeToName(packet_name_raw,
                                          pca::kSignaturePacket);
      *signing_id = packet_name_raw;
      break;
    case passport::kMid:
      *packet_name = pca::ApplyTypeToName(packet_name_raw,
                                          pca::kModifiableByOwner);
      *signing_id = session_->passport_->PacketName(passport::kAnmid,
                                                    signing_packet_confirmed);
      break;
    case passport::kSmid:
      *packet_name = pca::ApplyTypeToName(packet_name_raw,
                                          pca::kModifiableByOwner);
      *signing_id = session_->passport_->PacketName(passport::kAnsmid,
                            signing_packet_confirmed);
      break;
    case passport::kTmid:
    case passport::kStmid:
      *packet_name = pca::ApplyTypeToName(packet_name_raw,
                                          pca::kModifiableByOwner);
      *signing_id = session_->passport_->PacketName(passport::kAntmid,
                            signing_packet_confirmed);
      break;
    case passport::kMpid:
      *packet_name = pca::ApplyTypeToName(packet_name_raw,
                                          pca::kSignaturePacket);
      *signing_id = session_->passport_->PacketName(passport::kAnmpid,
                            signing_packet_confirmed);
      break;
    case passport::kMaid:
      *packet_name = pca::ApplyTypeToName(packet_name_raw,
                                          pca::kSignaturePacket);
      *signing_id = session_->passport_->PacketName(passport::kAnmaid,
                            signing_packet_confirmed);
      break;
    case passport::kPmid:
      *packet_name = pca::ApplyTypeToName(packet_name_raw,
                                          pca::kSignaturePacket);
      *signing_id = session_->passport_->PacketName(passport::kMaid,
                            signing_packet_confirmed);
      break;
    default:
      packet_name->clear();
      signing_id->clear();
      break;
  }
  BOOST_ASSERT(!signing_id->empty());
}

std::string Authentication::DebugStr(const passport::PacketType &packet_type) {
  return passport::PacketDebugString(packet_type);
}

void Authentication::KeysAndProof(
    passport::PacketType pt,
    pcs::RemoteChunkStore::ValidationData *validation_data,
    bool confirmed) {
  if (!IsSignature(pt)) {
    DLOG(ERROR) << "Not signature packet, what'r'u playing at?";
    return;
  }

  validation_data->key_pair.identity =
      session_->passport_->PacketName(pt, confirmed);
  validation_data->key_pair.public_key =
      session_->passport_->SignaturePacketValue(pt, confirmed);
  validation_data->key_pair.private_key =
      session_->passport_->PacketPrivateKey(pt, confirmed);
  validation_data->key_pair.validation_token =
      session_->passport_->PacketSignature(pt, confirmed);
  pca::SignedData signed_data;
  signed_data.set_data(RandomString(64));
  asymm::Sign(signed_data.data(),
              validation_data->key_pair.private_key,
              &validation_data->ownership_proof);
  signed_data.set_signature(validation_data->ownership_proof);
  validation_data->ownership_proof = signed_data.SerializeAsString();
}

bool Authentication::TmidOpDone() {
  return (tmid_op_status_ == kSucceeded ||
          tmid_op_status_ == kNoUser ||
          tmid_op_status_ == kFailed);
}

bool Authentication::StmidOpDone() {
  return (stmid_op_status_ == kSucceeded ||
          stmid_op_status_ == kNoUser ||
          stmid_op_status_ == kFailed);
}

bool Authentication::SignerDone(OpStatus *op_status) {
  return *op_status != kPending;
}

bool Authentication::TwoSystemPacketsOpDone(OpStatus *op_status1,
                                            OpStatus *op_status2) {
  return (*op_status1 != kPending) && (*op_status2 != kPending);
}

bool Authentication::ThreeSystemPacketsOpDone(OpStatus *op_status1,
                                              OpStatus *op_status2,
                                              OpStatus *op_status3) {
  return TwoSystemPacketsOpDone(op_status1, op_status2) &&
         (*op_status3 != kPending);
}

bool Authentication::FourSystemPacketsOpDone(OpStatus *op_status1,
                                             OpStatus *op_status2,
                                             OpStatus *op_status3,
                                             OpStatus *op_status4) {
  return TwoSystemPacketsOpDone(op_status1, op_status2) &&
         TwoSystemPacketsOpDone(op_status3, op_status4);
}

bool Authentication::PacketOpDone(int *return_code) {
  return *return_code != kPendingResult;
}

void Authentication::SaveSessionCallback(const int& return_code, int* result) {
  boost::mutex::scoped_lock lock(mutex_);
  *result = return_code;
  cond_var_.notify_one();
}

void Authentication::ChangeUserDataCallback(const int& return_code,
                                            int* result) {
  boost::mutex::scoped_lock lock(mutex_);
  *result = return_code;
  cond_var_.notify_one();
}

}  // namespace lifestuff

}  // namespace maidsafe
