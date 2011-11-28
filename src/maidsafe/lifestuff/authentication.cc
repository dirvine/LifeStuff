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

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/store_components/packet_manager.h"
#include "maidsafe/lifestuff/lifestuff_messages_pb.h"

namespace arg = std::placeholders;

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

}

Authentication::SerialisedPacket::SerialisedPacket()
    : type(passport::kUnknown),
      name(),
      value(),
      signature(),
      public_key() {}

Authentication::SerialisedPacket::SerialisedPacket(
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
    BOOST_ASSERT(rsa::ValidateKey(public_key));
  } else {
    value = passport->IdentityPacketValue(packet_type, confirmed);
    BOOST_ASSERT(!value.empty());
  }
  BOOST_ASSERT(!name.empty());
  BOOST_ASSERT(!signature.empty());
}


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

void Authentication::Init(std::shared_ptr<PacketManager> packet_manager) {
  packet_manager_ = packet_manager;
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
  packet_manager_->GetPacket(mid_name,
                             std::bind(&Authentication::GetMidCallback, this,
                                       arg::_1, arg::_2));
  packet_manager_->GetPacket(smid_name,
                             std::bind(&Authentication::GetSmidCallback, this,
                                       arg::_1, arg::_2));

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

void Authentication::GetMidCallback(const std::vector<std::string> &values,
                                    int return_code) {
  if (return_code != kSuccess || values.empty()) {
    DLOG(WARNING) << "Auth::GetMidCallback: No MID";
    {
      boost::mutex::scoped_lock loch_chapala(mid_mutex_);
      tmid_op_status_ = kFailed;
    }
    return;
  }

#ifdef DEBUG
  if (values.size() != 1)
    DLOG(WARNING) << "Auth::GetMidCallback - Values: " << values.size();
#endif

  GenericPacket packet;
  if (!packet.ParseFromString(values.at(0)) || packet.data().empty()) {
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

  DLOG(WARNING) << "Auth::GetMidCallback: TMID - (" << Base32Substr(tmid_name)
                << ", " << Base32Substr(values.at(0)) << ")";
  packet_manager_->GetPacket(tmid_name,
                             std::bind(&Authentication::GetTmidCallback,
                                       this, arg::_1, arg::_2));
}

void Authentication::GetSmidCallback(const std::vector<std::string> &values,
                                     int return_code) {
  if (return_code != kSuccess || values.empty()) {
    DLOG(WARNING) << "Auth::GetSmidCallback: No SMID";
    {
      boost::mutex::scoped_lock loch_chapala(smid_mutex_);
      stmid_op_status_ = kFailed;
    }
    return;
  }

#ifdef DEBUG
  if (values.size() != 1)
    DLOG(WARNING) << "Auth::GetSmidCallback - Values: " << values.size();
#endif

  GenericPacket packet;
  if (!packet.ParseFromString(values.at(0)) || packet.data().empty()) {
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

  packet_manager_->GetPacket(stmid_name,
                             std::bind(&Authentication::GetStmidCallback,
                                       this, arg::_1, arg::_2));}

void Authentication::GetTmidCallback(const std::vector<std::string> &values,
                                     int return_code) {
  if (return_code != kSuccess || values.empty()) {
    DLOG(WARNING) << "Auth::GetTmidCallback: No TMID";
    {
      boost::mutex::scoped_lock loch_chapala(mid_mutex_);
      tmid_op_status_ = kFailed;
    }
    return;
  }
#ifdef DEBUG
  if (values.size() != 1)
    DLOG(WARNING) << "Auth::GetTmidCallback - Values: " << values.size();
#endif

  GenericPacket packet;
  if (!packet.ParseFromString(values.at(0)) || packet.data().empty()) {
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

void Authentication::GetStmidCallback(const std::vector<std::string> &values,
                                      int return_code) {
  if (return_code != kSuccess || values.empty()) {
    DLOG(WARNING) << "Auth::GetStmidCallback: No TMID";
    {
      boost::mutex::scoped_lock loch_chapala(smid_mutex_);
      stmid_op_status_ = kFailed;
    }
    return;
  }
#ifdef DEBUG
  if (values.size() != 1)
    DLOG(WARNING) << "Auth::GetStmidCallback - Values: " << values.size();
#endif

  GenericPacket packet;
  if (!packet.ParseFromString(values.at(0)) || packet.data().empty()) {
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
    DLOG(WARNING) << "Authentication::CreateUserSysPackets - NOT INTIALISED";
    return kAuthenticationError;
  }
  session_->set_username(username);
  session_->set_pin(pin);

  if (session_->passport_->CreateSigningPackets() != kSuccess) {
    DLOG(WARNING) << "Authentication::CreateUserSysPackets - Not initialised";
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
                  kSingleOpTimeout_ * 6,
                  std::bind(&Authentication::ThreeSystemPacketsOpDone, this,
                            &pmid_status, &anmid_status, &antmid_status));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::CreateUserSysPackets: " << e.what();
    success = false;
  }
#ifdef DEBUG
  if (!success)
    DLOG(WARNING) << "Authentication::CreateUserSysPackets: timed out.";
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
      DLOG(WARNING) << DebugStr(packet_type) << ": " << e.what();
      success = false;
    }
    success = (*dependent_op_status == kSucceeded);
  }
  if (!success) {
    DLOG(WARNING) << DebugStr(packet_type) << ": failed wait for dependent op";
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kFailed;
    cond_var_.notify_all();
    return;
  }

  // Get packet
  std::string packet_name(session_->passport_->PacketName(packet_type, false));
  if (packet_name.empty()) {
    DLOG(WARNING) << DebugStr(packet_type) << ": failed init";
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kFailed;
    cond_var_.notify_all();
    return;
  }

  // Check packet name is not already a key on the DHT
//  DLOG(INFO) << "Authentication::StoreSignaturePacket - " << packet_type
//             << " - " << Base32Substr(sig_packet->name());
  VoidFuncOneInt f = std::bind(&Authentication::SignaturePacketUniqueCallback,
                               this, arg::_1, packet_type, op_status);
  packet_manager_->KeyUnique(packet_name, f);
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
                this, arg::_1, packet_type, op_status);
  SerialisedPacket packet(packet_type, session_->passport_, false);
  bool confirmed(packet_type != passport::kMaid &&
                 packet_type != passport::kPmid);
  packet_manager_->StorePacket(packet.name,
                               CreateGenericPacket(packet, confirmed),
                               functor);
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
    DLOG(WARNING) << DebugStr(packet_type) << ": Failed to store.";
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
  SerialisedPacket mid, smid, tmid, stmid;
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
    mid = SerialisedPacket(passport::kMid, session_->passport_, false);
    smid = SerialisedPacket(passport::kSmid, session_->passport_, false);
    tmid = SerialisedPacket(passport::kTmid, session_->passport_, false);
    stmid = SerialisedPacket(passport::kStmid, session_->passport_, false);
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
      if (result == kSuccess)
        result = StorePacket(stmid, false);
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

  SerialisedPacket old_mid(passport::kMid, session_->passport_, true),
                   old_smid(passport::kSmid, session_->passport_, true),
                   old_stmid(passport::kStmid, session_->passport_, true),
                   mid(passport::kMid, session_->passport_, false),
                   smid(passport::kSmid, session_->passport_, false),
                   tmid(passport::kTmid, session_->passport_, false);
  std::string old_mid_gp(CreateGenericPacket(old_mid)),
              old_smid_gp(CreateGenericPacket(old_smid)),
              old_stmid_gp(CreateGenericPacket(old_stmid)),
              mid_gp(CreateGenericPacket(mid)),
              smid_gp(CreateGenericPacket(smid)),
              tmid_gp(CreateGenericPacket(tmid));

  SaveSessionDataPtr save_session_data(
      new SaveSessionData(functor, kRegular, serialised_data_atlas));
  // Update SMID
  VoidFuncOneInt callback = std::bind(&Authentication::SaveSessionCallback,
                                      this, arg::_1, passport::kSmid,
                                      save_session_data);
  packet_manager_->UpdatePacket(smid.name, old_smid_gp, smid_gp, callback);

  // Update MID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kMid, save_session_data);
  packet_manager_->UpdatePacket(mid.name, old_mid_gp, mid_gp, callback);

  // Store new TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kTmid, save_session_data);
  packet_manager_->StorePacket(tmid.name, tmid_gp, callback);
  // Delete old STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kStmid, save_session_data);
  packet_manager_->DeletePacket(old_stmid.name, old_stmid_gp, callback);
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
                                     arg::_1, &result);
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
  if (serialised_data_atlas->empty()) {
    DLOG(ERROR) << "TMID error.";
    *surrogate_serialised_data_atlas =
        passport::DecryptMasterData(session_->username(),
                                    session_->pin(),
                                    password,
                                    encrypted_stmid_);
    if (surrogate_serialised_data_atlas->empty()) {
      DLOG(ERROR) << "STMID error.  Found neither.";
      return kPasswordFailure;
    }
  }
  session_->set_password(password);
  return kSuccess;
}

int Authentication::CreateMsidPacket(std::string *msid_name,
                                     std::string *msid_public_key,
                                     std::string *msid_private_key) {
  if (!msid_name || !msid_public_key || !msid_private_key)
    return kAuthenticationError;
//  msid_name->clear();
//  msid_public_key->clear();
//  msid_private_key->clear();
//
//  std::shared_ptr<pki::SignaturePacket>
//      msid(new pki::SignaturePacket);
//  std::vector<boost::uint32_t> share_stats(2, 0);
//  int result = session_->passport_->InitialiseSignaturePacket(passport::MSID,
//                                                              msid);
//  if (result != kSuccess) {
//    DLOG(ERROR) << "Authentication::CreateMsidPacket: failed init";
//    return kAuthenticationError;
//  }
//  // Add the share to the session to allow store_manager to retrieve the keys.
//  std::vector<std::string> attributes;
//  attributes.push_back(msid->name());
//  attributes.push_back(msid->name());
//  attributes.push_back(msid->value());  // msid->value == msid->public_key
//  attributes.push_back(msid->private_key());
//  result = session_->private_share_handler()->AddPrivateShare(
//              attributes, share_stats, NULL);
//  if (result != kSuccess) {
//  DLOG(ERROR) << "Authentication::CreateMsidPacket: failed adding to session";
//    session_->private_share_handler()->DeletePrivateShare(
//        msid->name(), 0);
    return kAuthenticationError;
//  }
//  result = StorePacket(msid, true, passport::MSID);
// #ifdef DEBUG
//  if (result != kSuccess)
//    DLOG(ERROR) << "Authentication::CreateMsidPacket: Failed storing MSID";
// #endif
//  // Remove the share from the session again to allow CC to add it fully.
//  session_->private_share_handler()->DeletePrivateShare(
//      msid->name(), 0);
//
//  if (result != kSuccess) {
//    DLOG(ERROR) << "Authentication::CreateMsidPacket: Failed.";
//    return kAuthenticationError;
//  } else {
//    *msid_name = msid->name();
//    *msid_public_key = msid->value();
//    *msid_private_key = msid->private_key();
//    return kSuccess;
//  }
}

int Authentication::CreatePublicName(const std::string &/*public_name*/) {
  if (!session_->public_username().empty()) {
    DLOG(ERROR) << "Authentication::CreatePublicName: Already set";
    return kPublicUsernameAlreadySet;
  }

  OpStatus anmpid_status(kSucceeded);
  if (session_->passport_->PacketName(passport::kAnmpid, true).empty()) {
    anmpid_status = kPending;
    StoreSignaturePacket(passport::kAnmpid, &anmpid_status, NULL);
  }

  OpStatus mpid_status(kPending);
  StoreSignaturePacket(passport::kMpid, &mpid_status, &anmpid_status);
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(
                  lock,
                  kSingleOpTimeout_ * 2,
                  std::bind(&Authentication::TwoSystemPacketsOpDone, this,
                  &mpid_status, &anmpid_status));
  }
  catch(const std::exception &e) {
    DLOG(WARNING) << "Authentication::CreatePublicName: " << e.what();
    success = false;
  }
#ifdef DEBUG
  if (!success)
    DLOG(INFO) << "Authentication::CreatePublicName: timed out";
#endif
  if ((anmpid_status == kSucceeded) && (mpid_status == kSucceeded)) {
    return kSuccess;
  } else if (mpid_status == kNotUnique) {
    return kPublicUsernameExists;
  } else {
    return kAuthenticationError;
  }
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
    DLOG(WARNING) << "Authentication::RemoveMe: " << e.what();
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
      DLOG(WARNING) << "Authentication::DeletePacket (" << packet_type << "): "
                 << e.what();
      success = false;
    }
    success = (*dependent_op_status == kSucceeded);
  }
  if (!success) {
    DLOG(WARNING) << "Authentication::DeletePacket (" << packet_type
               << "): Failed wait";
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kFailed;
    cond_var_.notify_all();
    return;
  }

  // Retrieve packet
  SerialisedPacket packet(packet_type, session_->passport_, true);
//  if (!packet) {
//    boost::mutex::scoped_lock lock(mutex_);
//    *op_status = kSucceeded;
//    cond_var_.notify_all();
//    return;
//  }
  // Delete packet
  VoidFuncOneInt functor = std::bind(&Authentication::DeletePacketCallback,
                                     this, arg::_1, packet_type, op_status);
  packet_manager_->DeletePacket(packet.name, CreateGenericPacket(packet),
                                functor);
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
    DLOG(WARNING) << "Authentication::DeletePacketCallback (" << packet_type
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

  SerialisedPacket old_mid(passport::kMid, session_->passport_, true),
                   old_smid(passport::kSmid, session_->passport_, true),
                   old_tmid(passport::kTmid, session_->passport_, true),
                   old_stmid(passport::kStmid, session_->passport_, true),
                   mid(passport::kMid, session_->passport_, false),
                   smid(passport::kSmid, session_->passport_, false),
                   tmid(passport::kTmid, session_->passport_, false),
                   stmid(passport::kStmid, session_->passport_, false);

  result = kPendingResult;
  VoidFuncOneInt uniqueness_functor =
      std::bind(&Authentication::PacketOpCallback, this, arg::_1, &result);

  SaveSessionDataPtr save_session_data(new SaveSessionData(
      uniqueness_functor, kIsUnique, serialised_data_atlas));
  VoidFuncOneInt callback;
  // Check uniqueness of new MID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kMid, save_session_data);
  packet_manager_->KeyUnique(mid.name, callback);
  // Check uniqueness of new SMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kSmid, save_session_data);
  packet_manager_->KeyUnique(smid.name, callback);
  // Check uniqueness of new TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kTmid, save_session_data);
  packet_manager_->KeyUnique(tmid.name, callback);
  // Check uniqueness of new STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kStmid, save_session_data);
  packet_manager_->KeyUnique(stmid.name, callback);
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
      std::bind(&Authentication::PacketOpCallback, this, arg::_1, &result);
  save_session_data->op_type = kSaveNew;
  // Store new MID
  callback = std::bind(&Authentication::SaveSessionCallback,
                       this, arg::_1, passport::kMid, save_session_data);
  packet_manager_->StorePacket(mid.name, CreateGenericPacket(mid), callback);
  // Store new SMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kSmid, save_session_data);
  packet_manager_->StorePacket(smid.name, CreateGenericPacket(smid), callback);
  // Store new TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kTmid, save_session_data);
  packet_manager_->StorePacket(tmid.name, CreateGenericPacket(tmid), callback);
  // Store new STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kStmid, save_session_data);
  packet_manager_->StorePacket(stmid.name, CreateGenericPacket(stmid),
                               callback);
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
      std::bind(&Authentication::PacketOpCallback, this, arg::_1, &result);
  save_session_data->op_type = kDeleteOld;  // Delete old MID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                        passport::kMid, save_session_data);
  packet_manager_->DeletePacket(old_mid.name, CreateGenericPacket(old_mid),
                                callback);
  // Delete old SMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                        passport::kSmid, save_session_data);
  packet_manager_->DeletePacket(old_smid.name, CreateGenericPacket(old_smid),
                                callback);
  // Delete old TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kTmid, save_session_data);
  packet_manager_->DeletePacket(old_tmid.name, CreateGenericPacket(old_tmid),
                                callback);
  // Delete old STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kStmid, save_session_data);
  packet_manager_->DeletePacket(old_stmid.name, CreateGenericPacket(old_stmid),
                                callback);

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
    DLOG(ERROR) << "Authentication::ChangeUserData: timed out deleting.";
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

  SerialisedPacket old_mid(passport::kMid, session_->passport_, true),
                   old_smid(passport::kSmid, session_->passport_, true),
                   old_tmid(passport::kTmid, session_->passport_, true),
                   old_stmid(passport::kStmid, session_->passport_, true),
                   mid(passport::kMid, session_->passport_, false),
                   smid(passport::kSmid, session_->passport_, false),
                   tmid(passport::kTmid, session_->passport_, false),
                   stmid(passport::kStmid, session_->passport_, false);
  result = kPendingResult;
  SaveSessionDataPtr save_session_data(new SaveSessionData(
      std::bind(&Authentication::PacketOpCallback, this, arg::_1, &result),
      kUpdate,
      serialised_data_atlas));

  // Update MID
  VoidFuncOneInt callback = std::bind(&Authentication::SaveSessionCallback,
                                      this, arg::_1, passport::kMid,
                                      save_session_data);
  packet_manager_->UpdatePacket(mid.name,
                                CreateGenericPacket(old_mid),
                                CreateGenericPacket(mid),
                                callback);
  // Update SMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kSmid, save_session_data);
  packet_manager_->UpdatePacket(smid.name,
                                CreateGenericPacket(old_smid),
                                CreateGenericPacket(smid),
                                callback);
  // Store new TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kTmid, save_session_data);
  packet_manager_->StorePacket(tmid.name, CreateGenericPacket(tmid), callback);
  // Store new STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kStmid, save_session_data);
  packet_manager_->StorePacket(stmid.name, CreateGenericPacket(stmid),
                               callback);
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
      std::bind(&Authentication::PacketOpCallback, this, arg::_1, &result);
  save_session_data->op_type = kDeleteOld;
  // Delete old TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kTmid, save_session_data);
  packet_manager_->DeletePacket(old_tmid.name, CreateGenericPacket(old_tmid),
                                callback);
  // Delete old STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       passport::kStmid, save_session_data);
  packet_manager_->DeletePacket(old_stmid.name, CreateGenericPacket(old_stmid),
                                callback);

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
    DLOG(ERROR) << "Authentication::ChangePassword: timed out deleting.";
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

int Authentication::PublicUsernamePublicKey(const std::string &public_username,
                                            std::string *public_key) {
  std::string packet_name = crypto::Hash<crypto::SHA512>(public_username);
  std::vector<std::string> packet_content;
  int result = packet_manager_->GetPacket(packet_name, &packet_content);
  if (result != kSuccess || packet_content.empty())
    return kUserDoesntExist;
  GenericPacket packet;
  if (!packet.ParseFromString(packet_content.at(0)) || !public_key)
    return kAuthenticationError;
  *public_key = packet.data();
  return kSuccess;
}

int Authentication::StorePacket(const SerialisedPacket &packet,
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
                                     arg::_1, &result);
  bool confirmed(packet.type != passport::kMaid &&
                 packet.type != passport::kPmid);
  packet_manager_->StorePacket(packet.name,
                               CreateGenericPacket(packet, confirmed),
                               functor);
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

  DLOG(ERROR) << "Authentication::StorePacket: result=" << result << " - "
              << Base32Substr(packet.name);

  return result;
}

int Authentication::DeletePacket(const SerialisedPacket &packet) {
  int result(kPendingResult);
  VoidFuncOneInt functor = std::bind(&Authentication::PacketOpCallback, this,
                                     arg::_1, &result);
  packet_manager_->DeletePacket(packet.name,
                                CreateGenericPacket(packet),
                                functor);
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
    DLOG(WARNING) << "Authentication::DeletePacket: Timed out.";
    return kAuthenticationError;
  }
#ifdef DEBUG
  if (result != kSuccess)
    DLOG(INFO) << "Authentication::DeletePacket result = " << result;
#endif
  return result;
}

int Authentication::PacketUnique(const SerialisedPacket &packet) {
  int result(kPendingResult);
  VoidFuncOneInt functor = std::bind(&Authentication::PacketOpCallback, this,
                                     arg::_1, &result);
  packet_manager_->KeyUnique(packet.name, functor);
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

std::string Authentication::CreateGenericPacket(
    const SerialisedPacket &packet,
    bool signing_packet_confirmed) {
  GenericPacket generic_packet;
  BOOST_ASSERT(!packet.name.empty());
  BOOST_ASSERT(!packet.signature.empty());
  if (packet.value.empty()) {
    std::string encoded_public_key;
    rsa::EncodePublicKey(packet.public_key, &encoded_public_key);
    BOOST_ASSERT(!encoded_public_key.empty());
    generic_packet.set_data(encoded_public_key);
  } else {
    BOOST_ASSERT(!packet.value.empty());
    generic_packet.set_data(packet.value);
  }
  generic_packet.set_signature(packet.signature);
  generic_packet.set_hashable(true);
  switch (packet.type) {
    case passport::kAnmid:
      generic_packet.set_signing_id(packet.name);
      break;
    case passport::kMid:
      generic_packet.set_signing_id(
          session_->passport_->PacketName(passport::kAnmid,
                                          signing_packet_confirmed));
      generic_packet.set_hashable(false);
      break;
    case passport::kAnsmid:
      generic_packet.set_signing_id(packet.name);
      break;
    case passport::kSmid:
      generic_packet.set_signing_id(
          session_->passport_->PacketName(passport::kAnsmid,
                                          signing_packet_confirmed));
      generic_packet.set_hashable(false);
      break;
    case passport::kAntmid:
      generic_packet.set_signing_id(packet.name);
      break;
    case passport::kTmid:
    case passport::kStmid:
      generic_packet.set_signing_id(
          session_->passport_->PacketName(passport::kAntmid,
                                          signing_packet_confirmed));
      generic_packet.set_hashable(false);
      break;
    case passport::kAnmpid:
      generic_packet.set_signing_id(packet.name);
      break;
    case passport::kMpid:
      generic_packet.set_signing_id(
          session_->passport_->PacketName(passport::kAnmpid,
                                          signing_packet_confirmed));
      generic_packet.set_hashable(false);
      break;
    case passport::kAnmaid:
      generic_packet.set_signing_id(packet.name);
      break;
    case passport::kMaid:
      generic_packet.set_signing_id(
          session_->passport_->PacketName(passport::kAnmaid,
                                          signing_packet_confirmed));
      break;
    case passport::kPmid:
      generic_packet.set_signing_id(
          session_->passport_->PacketName(passport::kMaid,
                                          signing_packet_confirmed));
      break;
    default:
      break;
  }
  BOOST_ASSERT(!generic_packet.signing_id().empty());
  return generic_packet.SerializeAsString();
}

std::string Authentication::DebugStr(const passport::PacketType &packet_type) {
  return passport::PacketDebugString(packet_type);
}

}  // namespace lifestuff

}  // namespace maidsafe
