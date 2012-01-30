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

#include "maidsafe/pd/client/remote_chunk_store.h"

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

}  // unnamed namespace

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


Authentication::Authentication(std::shared_ptr<Session> session)
    : remote_chunk_store_(),
      session_(session),
      mutex_(),
      mid_mutex_(),
      smid_mutex_(),
      cond_var_(),
      tmid_op_status_(kPendingMid),
      stmid_op_status_(kPendingMid),
      encrypted_tmid_(),
      encrypted_stmid_(),
      serialised_data_atlas_(),
      kSingleOpTimeout_(5000) {}

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
      DLOG(WARNING) << "Authentication dtor: " << e.what();
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

void Authentication::Init(
    std::shared_ptr<pd::RemoteChunkStore> remote_chunk_store) {
  remote_chunk_store_ = remote_chunk_store;
  tmid_op_status_ = kNoUser;
  stmid_op_status_ = kNoUser;
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
//  packet_manager_->GetPacket(pca::ApplyTypeToName(mid_name,
//                                                  pca::kModifiableByOwner),
//                             "",
//                             std::bind(&Authentication::GetMidCallback, this,
//                                       args::_1, args::_2));
//  packet_manager_->GetPacket(pca::ApplyTypeToName(smid_name,
//                                                  pca::kModifiableByOwner),
//                             "",
//                             std::bind(&Authentication::GetSmidCallback, this,
//                                       args::_1, args::_2));

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
  if (tmid_op_status_ == kSucceeded || stmid_op_status_ == kSucceeded) {
    return kUserExists;
  }
  session_->set_username("");
  session_->set_pin("");
  tmid_op_status_ = kNoUser;
  stmid_op_status_ = kNoUser;
  return kUserDoesntExist;
}

void Authentication::GetMidCallback(const std::string &value, int return_code) {
  if (return_code != kSuccess) {
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
//  packet_manager_->GetPacket(pca::ApplyTypeToName(tmid_name,
//                                                  pca::kModifiableByOwner),
//                             "",
//                             std::bind(&Authentication::GetTmidCallback,
//                                       this, args::_1, args::_2));
}

void Authentication::GetSmidCallback(const std::string &value,
                                     int return_code) {
  if (return_code != kSuccess) {
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

//  packet_manager_->GetPacket(pca::ApplyTypeToName(stmid_name,
//                                                  pca::kModifiableByOwner),
//                             "",
//                             std::bind(&Authentication::GetStmidCallback,
//                                       this, args::_1, args::_2));
}

void Authentication::GetTmidCallback(const std::string &value,
                                     int return_code) {
  if (return_code != kSuccess) {
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

  encrypted_tmid_ = packet.data();
  tmid_op_status_ = kSucceeded;
}

void Authentication::GetStmidCallback(const std::string &value,
                                      int return_code) {
  if (return_code != kSuccess) {
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

  encrypted_stmid_ = packet.data();
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
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(
                  lock,
                  kSingleOpTimeout_ * 10,
                  std::bind(&Authentication::ThreeSystemPacketsOpDone, this,
                            &pmid_status, &anmid_status, &antmid_status));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::CreateUserSysPackets: " << e.what();
    success = false;
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
  std::string packet_name(session_->passport_->PacketName(packet_type, false));
  if (packet_name.empty()) {
    DLOG(ERROR) << DebugStr(packet_type) << ": failed init";
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kFailed;
    cond_var_.notify_all();
    return;
  }

  // Check packet name is not already a key on the DHT
//  DLOG(INFO) << "Authentication::StoreSignaturePacket - " << packet_type
//             << " - " << Base32Substr(sig_packet->name());
  VoidFuncOneInt functor =
      std::bind(&Authentication::SignaturePacketUniqueCallback,
                this, args::_1, packet_type, op_status);
//  packet_manager_->KeyUnique(packet_name, "", functor);
}

void Authentication::SignaturePacketUniqueCallback(
    int return_code,
    passport::PacketType packet_type,
    OpStatus *op_status) {
  if (return_code != kKeyUnique) {
    boost::mutex::scoped_lock lock(mutex_);
    DLOG(ERROR) << DebugStr(packet_type) << ": Not unique.";
    *op_status = kNotUnique;
//    session_->passport_->RevertSignaturePacket(packet_type);
    cond_var_.notify_all();
    return;
  }

  // Store packet
  VoidFuncOneInt functor =
      std::bind(&Authentication::SignaturePacketStoreCallback,
                this, args::_1, packet_type, op_status);
  PacketData packet(packet_type, session_->passport_, false);
  bool confirmed(packet_type != passport::kMaid &&
                 packet_type != passport::kPmid);
  std::string signed_data_name, serialised_signed_data, signing_id;
  CreateSignedData(packet, confirmed, &signed_data_name,
                   &serialised_signed_data, &signing_id);
//  packet_manager_->StorePacket(signed_data_name, serialised_signed_data,
//                               signing_id, functor);
}

void Authentication::SignaturePacketStoreCallback(
    int return_code,
    passport::PacketType packet_type,
    OpStatus *op_status) {
  boost::mutex::scoped_lock lock(mutex_);
  if (return_code == kSuccess) {
    *op_status = kSucceeded;
//    if (packet_type == passport::kPmid)
//      packet_manager_->SetPmid(packet->name());
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
  const boost::uint8_t kMaxAttempts(3);
  boost::uint8_t attempt(0);
  PacketData mid, smid, tmid, stmid;
  while ((result != kSuccess) && (attempt < kMaxAttempts)) {
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
    mid = PacketData(passport::kMid, session_->passport_, false);
    smid = PacketData(passport::kSmid, session_->passport_, false);
    tmid = PacketData(passport::kTmid, session_->passport_, false);
    stmid = PacketData(passport::kStmid, session_->passport_, false);
    bool unique((PacketUnique(mid) == kKeyUnique) &&
                (PacketUnique(smid) == kKeyUnique) &&
                (PacketUnique(tmid) == kKeyUnique) &&
                (PacketUnique(stmid) == kKeyUnique));
    if (!unique) {
      DLOG(ERROR) << "Authentication::CreateTmidPacket: MID/SMID/TMID/STMID "
                     "exists.";
      ++attempt;
      result = kKeyNotUnique;
      continue;
    }
  }
  result = StorePacket(mid, false);
  if (result == kSuccess) {
    result = StorePacket(smid, false);
    if (result == kSuccess) {
      result = StorePacket(tmid, false);
      if (result == kSuccess) {
        result = StorePacket(stmid, false);
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
  serialised_data_atlas_ = serialised_data_atlas;
  return kSuccess;
}

void Authentication::SaveSession(const std::string &serialised_data_atlas,
                                 const VoidFuncOneInt &functor) {
  int result(session_->passport_->SetIdentityPackets(session_->username(),
                                                     session_->pin(),
                                                     session_->password(),
                                                     serialised_data_atlas,
                                                     serialised_data_atlas_));
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

  SaveSessionDataPtr save_session_data(
      new SaveSessionData(functor, kRegular, serialised_data_atlas));
  // Update SMID
  VoidFuncOneInt callback = std::bind(&Authentication::SaveSessionCallback,
                                      this, args::_1, passport::kSmid,
                                      save_session_data);
//  packet_manager_->ModifyPacket(smid_name,
//                                serialised_smid,
//                                smid_signing_id,
//                                callback);

  // Update MID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kMid, save_session_data);
//  packet_manager_->ModifyPacket(mid_name,
//                                serialised_mid,
//                                mid_signing_id,
//                                callback);

  // Store new TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kTmid, save_session_data);
//  packet_manager_->StorePacket(tmid_name,
//                               serialised_tmid,
//                               tmid_signing_id,
//                               callback);
  // Delete old STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kStmid, save_session_data);
  std::string old_stmid_name(pca::ApplyTypeToName(old_stmid.name,
                                                  pca::kModifiableByOwner));
//  packet_manager_->DeletePacket(old_stmid_name, tmid_signing_id, callback);
}

void Authentication::SaveSessionCallback(int return_code,
                                         passport::PacketType packet_type,
                                         SaveSessionDataPtr save_session_data) {
  OpStatus op_status(kSucceeded);
  if ((save_session_data->op_type == kIsUnique && return_code != kKeyUnique) ||
      (save_session_data->op_type != kIsUnique && return_code != kSuccess)) {
    op_status = kFailed;
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
//    DLOG(ERROR) << "Failed one operation.";
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
    serialised_data_atlas_ = save_session_data->serialised_data_atlas;
  }
  save_session_data->functor(kSuccess);
}

int Authentication::SaveSession(const std::string &serialised_data_atlas) {
  int result(kPendingResult);
  VoidFuncOneInt functor = std::bind(&Authentication::PacketOpCallback, this,
                                     args::_1, &result);
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

int Authentication::GetMasterDataMap(
    const std::string &password,
    std::string *serialised_data_atlas,
    std::string *surrogate_serialised_data_atlas) {
  serialised_data_atlas->clear();
  surrogate_serialised_data_atlas->clear();

  *serialised_data_atlas = passport::DecryptMasterData(session_->username(),
                                                       session_->pin(),
                                                       password,
                                                       encrypted_tmid_);
  *surrogate_serialised_data_atlas =
      passport::DecryptMasterData(session_->username(),
                                  session_->pin(),
                                  password,
                                  encrypted_stmid_);
  if (serialised_data_atlas->empty()) {
    DLOG(ERROR) << "TMID error.";
    if (surrogate_serialised_data_atlas->empty()) {
      DLOG(ERROR) << "STMID error.  Found neither.";
      return kPasswordFailure;
    }
    serialised_data_atlas_ = *surrogate_serialised_data_atlas;
  } else {
    serialised_data_atlas_ = *serialised_data_atlas;
  }
  session_->set_password(password);

  return kSuccess;
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

int Authentication::RemoveMe() {
  OpStatus pmid_status(kSucceeded);
  DeletePacket(passport::kPmid, &pmid_status, NULL);
  OpStatus maid_status(kPending);
  DeletePacket(passport::kMaid, &maid_status, &pmid_status);
  OpStatus anmaid_status(kPending);
  DeletePacket(passport::kAnmaid, &anmaid_status, &maid_status);
  OpStatus tmid_status(kPending);
  DeletePacket(passport::kTmid, &tmid_status, NULL);
  OpStatus stmid_status(kPending);
  DeletePacket(passport::kStmid, &stmid_status, &tmid_status);
  OpStatus antmid_status(kPending);
  DeletePacket(passport::kAntmid, &antmid_status, &stmid_status);
  OpStatus mid_status(kPending);
  DeletePacket(passport::kMid, &mid_status, NULL);
  OpStatus anmid_status(kPending);
  DeletePacket(passport::kAnmid, &anmid_status, &mid_status);
  OpStatus smid_status(kPending);
  DeletePacket(passport::kSmid, &smid_status, NULL);
  OpStatus ansmid_status(kPending);
  DeletePacket(passport::kAnsmid, &ansmid_status, &smid_status);
//  OpStatus mpid_status(kPending);
//  DeletePacket(passport::kMpid, &mpid_status, NULL);
//  OpStatus anmpid_status(kPending);
//  DeletePacket(passport::kAnmpid, &anmpid_status, &mpid_status);
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(
                  lock,
                  kSingleOpTimeout_ * 12,
                  std::bind(&Authentication::FourSystemPacketsOpDone, this,
                            &anmaid_status, &antmid_status, &anmid_status,
                            &ansmid_status));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::RemoveMe: " << e.what();
    success = false;
  }
#ifdef DEBUG
  if (!success)
    DLOG(INFO) << "Authentication::RemoveMe: timed out.";
#endif
  // Really only need these to be deleted
  if (pmid_status == kSucceeded && maid_status == kSucceeded &&
      tmid_status == kSucceeded && stmid_status == kSucceeded) {
    return kSuccess;
  }
  return kAuthenticationError;
}

void Authentication::DeletePacket(const passport::PacketType &packet_type,
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
      DLOG(ERROR) << "Authentication::DeletePacket (" << packet_type << "): "
                 << e.what();
      success = false;
    }
    success = (*dependent_op_status == kSucceeded);
  }
  if (!success) {
    DLOG(ERROR) << "Authentication::DeletePacket (" << packet_type
               << "): Failed wait";
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kFailed;
    cond_var_.notify_all();
    return;
  }

  // Retrieve packet
  PacketData packet(packet_type, session_->passport_, true);
//  if (!packet) {
//    boost::mutex::scoped_lock lock(mutex_);
//    *op_status = kSucceeded;
//    cond_var_.notify_all();
//    return;
//  }
  // Delete packet
  VoidFuncOneInt functor = std::bind(&Authentication::DeletePacketCallback,
                                     this, args::_1, packet_type, op_status);
  std::string packet_name, signing_id;
  GetPacketNameAndKeyId(packet.name,
                        packet.type,
                        true,
                        &packet_name,
                        &signing_id);
//  packet_manager_->DeletePacket(packet_name, signing_id, functor);
}

void Authentication::DeletePacketCallback(
    int return_code,
    const passport::PacketType &packet_type,
    OpStatus *op_status) {
  boost::mutex::scoped_lock lock(mutex_);
  if (return_code == kSuccess) {
    *op_status = kSucceeded;
//    session_->passport_->DeletePacket(packet_type);
  } else {
    DLOG(ERROR) << "Authentication::DeletePacketCallback (" << packet_type
                  << "): Failed to delete";
    *op_status = kFailed;
  }
  cond_var_.notify_all();
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
                                                       serialised_data_atlas_);
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

  result = kPendingResult;
  VoidFuncOneInt uniqueness_functor =
      std::bind(&Authentication::PacketOpCallback, this, args::_1, &result);

  SaveSessionDataPtr save_session_data(new SaveSessionData(
      uniqueness_functor, kIsUnique, serialised_data_atlas));
  VoidFuncOneInt callback;
  // Check uniqueness of new MID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kMid, save_session_data);
//  packet_manager_->KeyUnique(pca::ApplyTypeToName(mid.name,
//                                                  pca::kModifiableByOwner),
//                             "",
//                             callback);
  // Check uniqueness of new SMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kSmid, save_session_data);
//  packet_manager_->KeyUnique(pca::ApplyTypeToName(smid.name,
//                                                  pca::kModifiableByOwner),
//                             "",
//                             callback);
  // Check uniqueness of new TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kTmid, save_session_data);
//  packet_manager_->KeyUnique(pca::ApplyTypeToName(tmid.name,
//                                                  pca::kModifiableByOwner),
//                             "",
//                             callback);
  // Check uniqueness of new STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kStmid, save_session_data);
//  packet_manager_->KeyUnique(pca::ApplyTypeToName(stmid.name,
//                                                  pca::kModifiableByOwner),
//                             "",
//                             callback);
  // Wait for checking to complete
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(
                  lock,
                  kSingleOpTimeout_ * 4,
                  std::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::ChangeUserData: checking  - " << e.what();
    success = false;
  }
  if (!success) {
    DLOG(ERROR) << "Authentication::ChangeUserData: timed out checking.";
//    session_->passport_->RevertUserDataChange();
    return kAuthenticationError;
  }
  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::ChangeUserData: non-unique packets.";
//    session_->passport_->RevertUserDataChange();
    return kUserExists;
  }

  result = kPendingResult;
  save_session_data->process_mid = kPending;
  save_session_data->process_smid = kPending;
  save_session_data->process_tmid = kPending;
  save_session_data->process_stmid = kPending;
  save_session_data->functor =
      std::bind(&Authentication::PacketOpCallback, this, args::_1, &result);
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
  callback = std::bind(&Authentication::SaveSessionCallback,
                       this, args::_1, passport::kMid, save_session_data);
//  packet_manager_->StorePacket(mid_name,
//                               serialised_mid,
//                               mid_signing_id,
//                               callback);
  // Store new SMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kSmid, save_session_data);
//  packet_manager_->StorePacket(smid_name,
//                               serialised_smid,
//                               smid_signing_id,
//                               callback);
  // Store new TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kTmid, save_session_data);
//  packet_manager_->StorePacket(tmid_name,
//                               serialised_tmid,
//                               tmid_signing_id,
//                               callback);
  // Store new STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kStmid, save_session_data);
//  packet_manager_->StorePacket(stmid_name,
//                               serialised_stmid,
//                               stmid_signing_id,
//                               callback);
  // Wait for storing to complete
  success = true;
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
//    session_->passport_->RevertUserDataChange();
    return kAuthenticationError;
  }

  // Prepare to delete old packets
  result = kPendingResult;
  save_session_data->process_mid = kPending;
  save_session_data->process_smid = kPending;
  save_session_data->process_tmid = kPending;
  save_session_data->process_stmid = kPending;
  save_session_data->functor =
      std::bind(&Authentication::PacketOpCallback, this, args::_1, &result);
  save_session_data->op_type = kDeleteOld;
  // Delete old MID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                        passport::kMid, save_session_data);
//  packet_manager_->DeletePacket(pca::ApplyTypeToName(old_mid.name,
//                                                     pca::kModifiableByOwner),
//                                mid_signing_id,
//                                callback);
  // Delete old SMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                        passport::kSmid, save_session_data);
//  packet_manager_->DeletePacket(pca::ApplyTypeToName(old_smid.name,
//                                                     pca::kModifiableByOwner),
//                                smid_signing_id,
//                                callback);
  // Delete old TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kTmid, save_session_data);
//  packet_manager_->DeletePacket(pca::ApplyTypeToName(old_tmid.name,
//                                                     pca::kModifiableByOwner),
//                                tmid_signing_id,
//                                callback);
  // Delete old STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kStmid, save_session_data);
//  packet_manager_->DeletePacket(pca::ApplyTypeToName(old_stmid.name,
//                                                     pca::kModifiableByOwner),
//                                stmid_signing_id,
//                                callback);
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
//    session_->passport_->RevertUserDataChange();
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
                                                       serialised_data_atlas_);
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

  result = kPendingResult;
  SaveSessionDataPtr save_session_data(new SaveSessionData(
      std::bind(&Authentication::PacketOpCallback, this, args::_1, &result),
      kUpdate,
      serialised_data_atlas));

  // Update MID
  VoidFuncOneInt callback = std::bind(&Authentication::SaveSessionCallback,
                                      this, args::_1, passport::kMid,
                                      save_session_data);
//  packet_manager_->ModifyPacket(mid_name,
//                                serialised_mid,
//                                mid_signing_id,
//                                callback);
  // Update SMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kSmid, save_session_data);
//  packet_manager_->ModifyPacket(smid_name,
//                                serialised_smid,
//                                smid_signing_id,
//                                callback);
  // Store new TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kTmid, save_session_data);
//  packet_manager_->StorePacket(tmid_name,
//                               serialised_tmid,
//                               tmid_signing_id,
//                               callback);
  // Store new STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kStmid, save_session_data);
//  packet_manager_->StorePacket(stmid_name,
//                               serialised_stmid,
//                               stmid_signing_id,
//                               callback);
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
      std::bind(&Authentication::PacketOpCallback, this, args::_1, &result);
  save_session_data->op_type = kDeleteOld;
  // Delete old TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kTmid, save_session_data);
//  packet_manager_->DeletePacket(pca::ApplyTypeToName(old_tmid.name,
//                                                     pca::kModifiableByOwner),
//                                tmid_signing_id,
//                                callback);
  // Delete old STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, args::_1,
                       passport::kStmid, save_session_data);
//  packet_manager_->DeletePacket(pca::ApplyTypeToName(old_stmid.name,
//                                                     pca::kModifiableByOwner),
//                                stmid_signing_id,
//                                callback);

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

int Authentication::StorePacket(const PacketData &packet,
                                bool check_uniqueness) {
  int result(kPendingResult);
  if (check_uniqueness) {
    result = PacketUnique(packet);
    if (result != kKeyUnique) {
      DLOG(ERROR) << "Authentication::StorePacket: key already exists.";
      return result;
    }
  }
  result = kPendingResult;
  VoidFuncOneInt functor = std::bind(&Authentication::PacketOpCallback, this,
                                     args::_1, &result);
  bool confirmed(packet.type != passport::kMaid &&
                 packet.type != passport::kPmid);
  std::string packet_name, serialised_packet, signing_id;
  CreateSignedData(packet,
                   confirmed,
                   &packet_name,
                   &serialised_packet,
                   &signing_id);
//  packet_manager_->StorePacket(packet_name,
//                               serialised_packet,
//                               signing_id,
//                               functor);
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
  VoidFuncOneInt functor = std::bind(&Authentication::PacketOpCallback, this,
                                     args::_1, &result);
  std::string packet_name, signing_id;
  GetPacketNameAndKeyId(packet.name,
                        packet.type,
                        true,
                        &packet_name,
                        &signing_id);
//  packet_manager_->DeletePacket(packet_name, signing_id, functor);
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

int Authentication::PacketUnique(const PacketData &packet) {
  int result(kPendingResult);
  VoidFuncOneInt functor = std::bind(&Authentication::PacketOpCallback, this,
                                     args::_1, &result);
  std::string packet_name, signing_id;
  GetPacketNameAndKeyId(packet.name,
                        packet.type,
                        true,
                        &packet_name,
                        &signing_id);
//  packet_manager_->KeyUnique(packet_name, signing_id, functor);
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(
                  lock,
                  kSingleOpTimeout_,
                  std::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
    DLOG(WARNING) << "Authentication::PacketUnique: " << e.what();
    success = false;
  }
  if (!success) {
    DLOG(ERROR) << "Authentication::PacketUnique: timed out.";
    return kAuthenticationError;
  }
  return result;
}

void Authentication::PacketOpCallback(int return_code, int *op_result) {
  boost::mutex::scoped_lock lock(mutex_);
  *op_result = return_code;
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

}  // namespace lifestuff

}  // namespace maidsafe
