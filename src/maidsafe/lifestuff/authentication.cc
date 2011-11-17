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

#include "boost/regex.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/packet_manager.h"

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/lifestuff/lifestuff_messages.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif


namespace arg = std::placeholders;

namespace maidsafe {

namespace lifestuff {

Authentication::~Authentication() {
  if (tmid_op_status_ != kPendingMid || stmid_op_status_ != kPendingMid) {
    bool tmid_success(false), stmid_success(false);
    try {
      boost::mutex::scoped_lock lock(mutex_);
      tmid_success = cond_var_.timed_wait(
                         lock,
                         4 * kSingleOpTimeout_.total_milliseconds(),
                         std::bind(&Authentication::TmidOpDone, this));
      stmid_success =
          cond_var_.timed_wait(
              lock,
              2 * kSingleOpTimeout_.total_milliseconds(),
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
                                             packet.data(),
                                             false));
  if (tmid_name.empty()) {
    DLOG(WARNING) << "Failed to decrypt rid";
    {
      boost::mutex::scoped_lock loch_chapala(mid_mutex_);
      tmid_op_status_ = kFailed;
    }
    return;
  }

  DLOG(WARNING) << "Auth::GetMidCallback: TMID - (" << HexSubstr(tmid_name)
                << ", " << HexSubstr(values.at(0)) << ")";
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
                                              packet.data(),
                                              true));
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
                                       this, arg::_1, arg::_2));
}

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
  StoreSignaturePacket(passport::kAnmaid, "", &anmaid_status, NULL);

  OpStatus anmid_status(kPending);
  StoreSignaturePacket(passport::kAnmid, "", &anmid_status, NULL);

  OpStatus ansmid_status(kPending);
  StoreSignaturePacket(passport::kAnsmid, "", &ansmid_status, NULL);

  OpStatus antmid_status(kPending);
  StoreSignaturePacket(passport::kAntmid, "", &antmid_status, NULL);

  // TODO(Fraser#5#): 2010-10-18 - Thread these next two?
  OpStatus maid_status(kPending);
  StoreSignaturePacket(passport::kMaid, "", &maid_status, &anmaid_status);

  OpStatus pmid_status(kPending);
  StoreSignaturePacket(passport::kPmid, "", &pmid_status, &maid_status);

  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(
                  lock,
                  6 * kSingleOpTimeout_.total_milliseconds(),
                  std::bind(&Authentication::ThreeSystemPacketsOpDone, this,
                            &pmid_status, &anmid_status, &antmid_status));
  }
  catch(const std::exception &e) {
    DLOG(WARNING) << "Authentication::CreateUserSysPackets: " << e.what();
    success = false;
  }
#ifdef DEBUG
  if (!success)
    DLOG(WARNING) << "Authentication::CreateUserSysPackets: timed out.";
#endif
  if ((anmaid_status == kSucceeded) && (anmid_status == kSucceeded) &&
      (ansmid_status == kSucceeded) && (antmid_status == kSucceeded) &&
      (maid_status == kSucceeded) && (pmid_status == kSucceeded)) {
    return kSuccess;
  }
  session_->set_username("");
  session_->set_pin("");
  return kAuthenticationError;
}

void Authentication::StoreSignaturePacket(const passport::PacketType &packet_t,
                                          const std::string &public_name,
                                          OpStatus *op_status,
                                          OpStatus *dependent_op_status) {
  // Wait for dependent op or timeout.
  bool success(true);
  if (dependent_op_status) {
    boost::mutex::scoped_lock lock(mutex_);
    try {
      success = cond_var_.timed_wait(lock,
                kSingleOpTimeout_,
                std::bind(&Authentication::SignerDone, this,
                          dependent_op_status));
    }
    catch(const std::exception &e) {
      DLOG(WARNING) << passport::PacketDebugString(packet_t) << " " << e.what();
      success = false;
    }
    success = (*dependent_op_status == kSucceeded);
  }
  if (!success) {
    DLOG(WARNING) << "Authentication::CreateSigPkt ("
                  << passport::PacketDebugString(packet_t) << "): failed wait.";
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kFailed;
    cond_var_.notify_all();
    return;
  }

  // Create packet
  std::shared_ptr<pki::SignaturePacket> sig_packet(new pki::SignaturePacket);
  int result(kPendingResult);
  if (packet_t == passport::MPID)
    result = session_->passport_->InitialiseMpid(public_name, sig_packet);
  else
    result = session_->passport_->InitialiseSignaturePacket(packet_t, sig_packet);
  if (result != kSuccess) {
    DLOG(WARNING) << "Authentication::CreateSigPkt ("
                  << passport::PacketDebugString(packet_t) << "): failed init.";
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kFailed;
    cond_var_.notify_all();
    return;
  }

  // Check packet name is not already a key on the DHT
//  DLOG(INFO) << "Authentication::StoreSignaturePacket - " << packet_type
//             << " - " << HexSubstr(sig_packet->name());
  VoidFuncOneInt f = std::bind(&Authentication::SignaturePacketUniqueCallback,
                               this, arg::_1, sig_packet, op_status);
  packet_manager_->KeyUnique(sig_packet->name(), f);
}

void Authentication::SignaturePacketUniqueCallback(
    int return_code,
    std::shared_ptr<pki::SignaturePacket> packet,
    OpStatus *op_status) {
  passport::PacketType packet_type =
      static_cast<passport::PacketType>(packet->packet_type());
  if (return_code != kKeyUnique) {
    boost::mutex::scoped_lock lock(mutex_);
    DLOG(ERROR) << "Authentication::SignaturePacketUniqueCbk (" << packet_type
                << "): Failed to store.";
    *op_status = kNotUnique;
    session_->passport_->RevertSignaturePacket(packet_type);
    cond_var_.notify_all();
    return;
  }

  // Store packet
  VoidFuncOneInt functor =
      std::bind(&Authentication::SignaturePacketStoreCallback,
                this, arg::_1, packet, op_status);

  packet_manager_->StorePacket(packet->name(),
                               CreateGenericPacket(packet->value(),
                                                   packet->signature(),
                                                   packet_type),
                               functor);
}

void Authentication::SignaturePacketStoreCallback(
    int return_code,
    std::shared_ptr<pki::SignaturePacket> packet,
    OpStatus *op_status) {
  passport::PacketType packet_type =
      static_cast<passport::PacketType>(packet->packet_type());
  boost::mutex::scoped_lock lock(mutex_);
  if (return_code == kSuccess) {
    *op_status = kSucceeded;
    session_->passport_->ConfirmSignaturePacket(packet);
//    if (packet_type == passport::kPmid)
//      packet_manager_->SetPmid(packet->name());
  } else {
    DLOG(WARNING) << "Authentication::SignaturePacketStoreCbk ("
                  << passport::PacketDebugString(packet_type)
                  << "): Failed to store.";
    *op_status = kFailed;
    session_->passport_->RevertSignaturePacket(packet_type);
  }
  cond_var_.notify_all();
}

int Authentication::CreateTmidPacket(const std::string &username,
                                     const std::string &pin,
                                     const std::string &password,
                                     const std::string &serialised_datamap,
                                     const std::string &s_serialised_datamap) {
  if ((username != session_->username()) ||
      (pin != session_->pin())) {
    DLOG(ERROR) << "Authentication::CreateTmidPacket: username/pin error.";
    return kAuthenticationError;
  }

  std::shared_ptr<passport::MidPacket> mid(new passport::MidPacket);
  std::shared_ptr<passport::MidPacket> smid(new passport::MidPacket);
  std::shared_ptr<passport::TmidPacket> tmid(new passport::TmidPacket);
  std::shared_ptr<passport::TmidPacket> stmid(new passport::TmidPacket);
  int result(kPendingResult);
  const boost::uint8_t kMaxAttempts(3);
  boost::uint8_t attempt(0);
  while ((result != kSuccess) && (attempt < kMaxAttempts)) {
    result = session_->passport_->SetNewUserData(password,
                                       serialised_datamap,
                                       s_serialised_datamap,
                                       mid, smid,
                                       tmid, stmid);
    if (result != kSuccess) {
      DLOG(ERROR) << "Authentication::CreateTmidPacket: Failed init.";
      return kAuthenticationError;
    }
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
  result = StorePacket(mid, false, passport::MID);
  if (result == kSuccess) {
    result = StorePacket(smid, false, passport::SMID);
    if (result == kSuccess) {
      result = StorePacket(tmid, false, passport::TMID);
      if (result == kSuccess)
        result = StorePacket(stmid, false, passport::STMID);
    }
  }
  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::CreateTmidPacket: Failed.";
    return kAuthenticationError;
  } else {
    session_->passport_->ConfirmNewUserData(mid, smid, tmid, stmid);
    session_->set_password(password);
    return kSuccess;
  }
}

void Authentication::SaveSession(const std::string &serialised_master_datamap,
                                 const VoidFuncOneInt &functor) {
  std::shared_ptr<SaveSessionData>
      save_session_data(new SaveSessionData(functor, kRegular));

  std::string mid_old_value, smid_old_value;
  int result(session_->passport_->UpdateMasterData(serialised_master_datamap,
                                         &mid_old_value,
                                         &smid_old_value,
                                         save_session_data->mid,
                                         save_session_data->smid,
                                         save_session_data->tmid,
                                         save_session_data->stmid));
  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::SaveSession: failed UpdateUserData.";
    functor(kAuthenticationError);
    return;
  }
//  save_session_data->stmid->SetToSurrogate();

  // Update or store SMID
  VoidFuncOneInt callback = std::bind(&Authentication::SaveSessionCallback,
                                      this, arg::_1, save_session_data->smid,
                                      save_session_data);
                                                FLAGS_ms_logging_lifestuff = google::INFO;
                                                DLOG(ERROR) << "Update " << passport::PacketDebugString(passport::SMID) << "\t" << HexSubstr(save_session_data->smid->name()) << "\t" << HexSubstr(save_session_data->smid->value());
                                                FLAGS_ms_logging_lifestuff = google::FATAL;
  packet_manager_->UpdatePacket(save_session_data->smid->name(),
                                CreateGenericPacket(smid_old_value,
                                                    "",
                                                    passport::SMID),
                                CreateGenericPacket(
                                    save_session_data->smid->value(),
                                    "",
                                    passport::SMID),
                                callback);

  // Update MID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       save_session_data->mid, save_session_data);
                                                FLAGS_ms_logging_lifestuff = google::INFO;
                                                DLOG(ERROR) << "Update " << passport::PacketDebugString(passport::MID) << "\t" << HexSubstr(save_session_data->mid->name()) << "\t" << HexSubstr(save_session_data->mid->value());
                                                FLAGS_ms_logging_lifestuff = google::FATAL;
  packet_manager_->UpdatePacket(save_session_data->mid->name(),
                                CreateGenericPacket(mid_old_value,
                                                    "",
                                                    passport::MID),
                                CreateGenericPacket(
                                    save_session_data->mid->value(),
                                    "",
                                    passport::MID),
                                callback);

  // Store new TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       save_session_data->tmid, save_session_data);
                                                FLAGS_ms_logging_lifestuff = google::INFO;
                                                DLOG(ERROR) << "Store " << passport::PacketDebugString(passport::TMID) << "\t" << HexSubstr(save_session_data->tmid->name()) << "\t" << HexSubstr(save_session_data->tmid->value());
                                                FLAGS_ms_logging_lifestuff = google::FATAL;
  packet_manager_->StorePacket(save_session_data->tmid->name(),
                               CreateGenericPacket(
                                   save_session_data->tmid->value(),
                                   "",
                                   passport::TMID),
                               callback);

  // Delete old STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       save_session_data->stmid, save_session_data);
                                                FLAGS_ms_logging_lifestuff = google::INFO;
                                                DLOG(ERROR) << "Delete " << passport::PacketDebugString(passport::STMID) << "\t" << HexSubstr(save_session_data->stmid->name()) << "\t" << HexSubstr(save_session_data->stmid->value());
                                                FLAGS_ms_logging_lifestuff = google::FATAL;
  packet_manager_->DeletePacket(save_session_data->stmid->name(),
                                CreateGenericPacket(
                                    save_session_data->stmid->value(),
                                    "",
                                    passport::STMID),
                                callback);
}

void Authentication::SaveSessionCallback(
    int return_code,
    std::shared_ptr<pki::Packet> packet,
    std::shared_ptr<SaveSessionData> save_session_data) {
  OpStatus op_status(kSucceeded);
  if ((save_session_data->op_type == kIsUnique && return_code != kKeyUnique) ||
      (save_session_data->op_type != kIsUnique && return_code != kSuccess)) {
    op_status = kFailed;
  }

  boost::mutex::scoped_lock lock(mutex_);
  switch (packet->packet_type()) {
    case passport::MID:
//      DLOG(WARNING) << "Authentication::SaveSessionCallback MID: Return Code "
//                    << return_code << " - " << HexSubstr(packet->name());
      save_session_data->process_mid = op_status;
      break;
    case passport::SMID:
//      DLOG(WARNING) << "Authentication::SaveSessionCallback SMID: Return Code "
//                    << return_code << " - " << HexSubstr(packet->name());
      save_session_data->process_smid = op_status;
      break;
    case passport::TMID:
//      DLOG(WARNING) << "Authentication::SaveSessionCallback TMID: Return Code "
//                    << return_code << " - " << HexSubstr(packet->name());
      save_session_data->process_tmid = op_status;
      break;
    case passport::STMID:
//      DLOG(WARNING) << "Authentication::SaveSessionCallback STMID: Return Code "
//                    << return_code << " - " << HexSubstr(packet->name());
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
    session_->passport_->RevertMasterDataUpdate();
    save_session_data->functor(kAuthenticationError);
    return;
  }
  lock.unlock();
  session_->passport_->ConfirmMasterDataUpdate(save_session_data->mid,
                                     save_session_data->smid,
                                     save_session_data->tmid);
  save_session_data->functor(kSuccess);
}

void Authentication::NewSaveSessionCallback(
    const ReturnCode &return_code,
    std::shared_ptr<pki::Packet> packet,
    std::shared_ptr<SaveSessionData> save_session_data) {
  OpStatus op_status(kSucceeded);
  if (return_code != kSuccess)
    op_status = kFailed;

  boost::mutex::scoped_lock lock(mutex_);
  switch (packet->packet_type()) {
    case passport::MID:
      DLOG(WARNING) << "Authentication::SaveSessionCallback MID: Return Code "
                    << return_code;
      save_session_data->process_mid = op_status;
      break;
    case passport::SMID:
      DLOG(WARNING) << "Authentication::SaveSessionCallback SMID: Return Code "
                    << return_code;
      save_session_data->process_smid = op_status;
      break;
    case passport::TMID:
      DLOG(WARNING) << "Authentication::SaveSessionCallback TMID: Return Code "
                    << return_code;
      save_session_data->process_tmid = op_status;
      break;
    case passport::STMID:
      DLOG(WARNING) << "Authentication::SaveSessionCallback STMID: Return Code "
                    << return_code;
      save_session_data->process_stmid = op_status;
      break;
    default:
      break;
  }

  // If anything is still pending, we're not done
  if ((save_session_data->process_mid == kPending) ||
      (save_session_data->process_smid == kPending) ||
      (save_session_data->process_tmid == kPending) ||
      (save_session_data->process_stmid == kPending))
    return;

  // All ops have finished, check if any have failed
  if ((save_session_data->process_mid == kFailed) ||
      (save_session_data->process_smid == kFailed) ||
      (save_session_data->process_tmid == kFailed) ||
      (save_session_data->process_stmid == kFailed)) {
    lock.unlock();
    session_->passport_->RevertMasterDataUpdate();
    DLOG(WARNING) << "Authentication::SaveSessionCallback - One op failed";
    save_session_data->functor(kAuthenticationError);
    return;
  }
  lock.unlock();

  // It's all good, confirm to passport
  session_->passport_->ConfirmMasterDataUpdate(save_session_data->mid,
                                     save_session_data->smid,
                                     save_session_data->tmid);
  save_session_data->functor(kSuccess);
}

int Authentication::SaveSession(const std::string &serialised_master_datamap) {
  int result(kPendingResult);
  VoidFuncOneInt functor = std::bind(&Authentication::PacketOpCallback, this,
                                     arg::_1, &result);
  SaveSession(serialised_master_datamap, functor);
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(4 * kSingleOpTimeout_),
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
    std::shared_ptr<std::string> serialised_master_datamap,
    std::shared_ptr<std::string> surrogate_serialised_master_datamap) {
  serialised_master_datamap->clear();
  surrogate_serialised_master_datamap->clear();
  // Still have not recovered the TMID
  int res = session_->passport_->GetUserData(password, false, encrypted_tmid_,
                                   serialised_master_datamap.get());
  if (res == kSuccess) {
    session_->set_password(password);
    session_->passport_->GetUserData(password, true, encrypted_stmid_,
                           surrogate_serialised_master_datamap.get());
    return res;
  } else {
    DLOG(WARNING) << "Authentication::GetMasterDataMap - TMID error " << res;
  }

  res = session_->passport_->GetUserData(password, true, encrypted_stmid_,
                               surrogate_serialised_master_datamap.get());
  if (res == kSuccess) {
    session_->set_password(password);
    return res;
  } else {
    DLOG(WARNING) << "Authentication::GetMasterDataMap - STMID error " << res;
    return kPasswordFailure;
  }
}

int Authentication::CreateMsidPacket(std::string *msid_name,
                                     std::string *msid_public_key,
                                     std::string *msid_private_key) {
  if (!msid_name || !msid_public_key || !msid_private_key)
    return kAuthenticationError;
  msid_name->clear();
  msid_public_key->clear();
  msid_private_key->clear();

  std::shared_ptr<pki::SignaturePacket>
      msid(new pki::SignaturePacket);
  std::vector<boost::uint32_t> share_stats(2, 0);
  int result = session_->passport_->InitialiseSignaturePacket(passport::MSID, msid);
  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::CreateMsidPacket: failed init";
    return kAuthenticationError;
  }
  // Add the share to the session to allow store_manager to retrieve the keys.
  std::vector<std::string> attributes;
  attributes.push_back(msid->name());
  attributes.push_back(msid->name());
  attributes.push_back(msid->value());  // msid->value == msid->public_key
  attributes.push_back(msid->private_key());
  result = session_->private_share_handler()->AddPrivateShare(
              attributes, share_stats, NULL);
  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::CreateMsidPacket: failed adding to session";
    session_->private_share_handler()->DeletePrivateShare(
        msid->name(), 0);
    return kAuthenticationError;
  }
  result = StorePacket(msid, true, passport::MSID);
#ifdef DEBUG
  if (result != kSuccess)
    DLOG(ERROR) << "Authentication::CreateMsidPacket: Failed storing MSID";
#endif
  // Remove the share from the session again to allow CC to add it fully.
  session_->private_share_handler()->DeletePrivateShare(
      msid->name(), 0);

  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::CreateMsidPacket: Failed.";
    return kAuthenticationError;
  } else {
    *msid_name = msid->name();
    *msid_public_key = msid->value();
    *msid_private_key = msid->private_key();
    return kSuccess;
  }
}

int Authentication::CreatePublicName(const std::string &public_name) {
  if (!session_->public_username().empty()) {
    DLOG(ERROR) << "Authentication::CreatePublicName: Already set";
    return kPublicUsernameAlreadySet;
  }

  OpStatus anmpid_status(kSucceeded);
  if (!session_->passport_->GetPacket(passport::ANMPID, true)) {
    anmpid_status = kPending;
    StoreSignaturePacket(passport::ANMPID, "", &anmpid_status, NULL);
  }

  // TODO(Fraser#5#): 2010-10-18 - Thread this?
  OpStatus mpid_status(kPending);
  StoreSignaturePacket(passport::MPID, public_name, &mpid_status,
                        &anmpid_status);

  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(2 * kSingleOpTimeout_),
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
// TODO(Fraser#5#): 2010-10-18 - Thread these?
  OpStatus pmid_status(kSucceeded);
  DeletePacket(passport::kPmid, &pmid_status, NULL);
  OpStatus maid_status(kPending);
  DeletePacket(passport::kMaid, &maid_status, &pmid_status);
  OpStatus anmaid_status(kPending);
  DeletePacket(passport::kAnmaid, &anmaid_status, &maid_status);

  OpStatus tmid_status(kPending);
  DeletePacket(passport::TMID, &tmid_status, NULL);
  OpStatus stmid_status(kPending);
  DeletePacket(passport::STMID, &stmid_status, &tmid_status);
  OpStatus antmid_status(kPending);
  DeletePacket(passport::kAntmid, &antmid_status, &stmid_status);

  OpStatus mid_status(kPending);
  DeletePacket(passport::MID, &mid_status, NULL);
  OpStatus anmid_status(kPending);
  DeletePacket(passport::kAnmid, &anmid_status, &mid_status);

  OpStatus smid_status(kPending);
  DeletePacket(passport::SMID, &smid_status, NULL);
  OpStatus ansmid_status(kPending);
  DeletePacket(passport::kAnsmid, &ansmid_status, &smid_status);

  OpStatus mpid_status(kPending);
  DeletePacket(passport::MPID, &mpid_status, NULL);
  OpStatus anmpid_status(kPending);
  DeletePacket(passport::ANMPID, &anmpid_status, &mpid_status);

  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(12 * kSingleOpTimeout_),
              std::bind(&Authentication::FiveSystemPacketsOpDone, this,
                        &anmaid_status, &antmid_status, &anmid_status,
                        &ansmid_status, &anmpid_status));
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
  if ((pmid_status == kSucceeded) && (maid_status == kSucceeded) &&
      (tmid_status == kSucceeded) && (stmid_status == kSucceeded) &&
      (mpid_status == kSucceeded)) {
    return kSuccess;
  } else {
    return kAuthenticationError;
  }
}

void Authentication::DeletePacket(const passport::PacketType &packet_type,
                                  OpStatus *op_status,
                                  OpStatus *dependent_op_status) {
  // Wait for dependent op or timeout.
  bool success(true);
  if (dependent_op_status) {
    boost::mutex::scoped_lock lock(mutex_);
    try {
      success = cond_var_.timed_wait(lock,
                boost::posix_time::milliseconds(kSingleOpTimeout_),
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
  std::shared_ptr<pki::Packet> packet(session_->passport_->GetPacket(packet_type, true));
  if (!packet) {
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kSucceeded;
    cond_var_.notify_all();
    return;
  }

  // Delete packet
  VoidFuncOneInt functor = std::bind(&Authentication::DeletePacketCallback,
                                     this, arg::_1, packet_type, op_status);
  packet_manager_->DeletePacket(packet->name(),
                                CreateGenericPacket(packet->value(),
                                                    "",
                                                    packet_type),
                                functor);
}

void Authentication::DeletePacketCallback(
    int return_code,
    const passport::PacketType &packet_type,
    OpStatus *op_status) {
  boost::mutex::scoped_lock lock(mutex_);
  if (return_code == kSuccess) {
    *op_status = kSucceeded;
    session_->passport_->DeletePacket(packet_type);
  } else {
    DLOG(WARNING) << "Authentication::DeletePacketCallback (" << packet_type
                  << "): Failed to delete";
    *op_status = kFailed;
  }
  cond_var_.notify_all();
}

int Authentication::ChangeUsername(const std::string &serialised_master_datamap,
                                   const std::string &new_username) {
  return ChangeUserData(serialised_master_datamap,
                        new_username,
                        session_->pin());
}

int Authentication::ChangePin(const std::string &serialised_master_datamap,
                              const std::string &new_pin) {
  return ChangeUserData(serialised_master_datamap,
                        session_->username(),
                        new_pin);
}

int Authentication::ChangeUserData(const std::string &serialised_master_datamap,
                                   const std::string &new_username,
                                   const std::string &new_pin) {
  // Get updated packets
  int uniqueness_result(kPendingResult);
  VoidFuncOneInt uniqueness_functor = std::bind(
      &Authentication::PacketOpCallback, this, arg::_1, &uniqueness_result);
  std::shared_ptr<SaveSessionData>
      save_new_packets(new SaveSessionData(uniqueness_functor,
                                           kIsUnique,
                                           2));

  int delete_result(kPendingResult);
  VoidFuncOneInt delete_functor = std::bind(&Authentication::PacketOpCallback,
                                            this, arg::_1, &delete_result);
  std::shared_ptr<SaveSessionData>
      delete_old_packets(new SaveSessionData(delete_functor, kDeleteOld));

  int result = session_->passport_->ChangeUserData(new_username,
                                         new_pin,
                                         serialised_master_datamap,
                                         delete_old_packets->mid,
                                         delete_old_packets->smid,
                                         delete_old_packets->tmid,
                                         delete_old_packets->stmid,
                                         save_new_packets->mid,
                                         save_new_packets->smid,
                                         save_new_packets->tmid,
                                         save_new_packets->stmid);
  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::ChangeUserData: failed ChangeUserData";
    session_->passport_->RevertUserDataChange();
    return kAuthenticationError;
  }

  // Check new MID
  VoidFuncOneInt callback = std::bind(&Authentication::SaveSessionCallback,
                                      this, arg::_1, save_new_packets->mid,
                                      save_new_packets);
  packet_manager_->KeyUnique(save_new_packets->mid->name(), callback);
  // Check new SMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       save_new_packets->smid, save_new_packets);
  packet_manager_->KeyUnique(save_new_packets->smid->name(), callback);
  // Check new TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       save_new_packets->tmid, save_new_packets);
  packet_manager_->KeyUnique(save_new_packets->tmid->name(), callback);

  // Wait for checking to complete
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(3 * kSingleOpTimeout_),
              std::bind(&Authentication::PacketOpDone, this,
                        &uniqueness_result));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::ChangeUserData: checking  - " << e.what();
    success = false;
  }
  if (!success) {
    DLOG(ERROR) << "Authentication::ChangeUserData: timed out checking.";
    session_->passport_->RevertUserDataChange();
    return kAuthenticationError;
  }
  if (uniqueness_result != kSuccess) {
    DLOG(ERROR) << "Authentication::ChangeUserData: non-unique packets.";
    session_->passport_->RevertUserDataChange();
    return kUserExists;
  }

  int store_result(kPendingResult);
  VoidFuncOneInt store_functor = std::bind(&Authentication::PacketOpCallback,
                                           this, arg::_1, &store_result);
  save_new_packets->process_mid = kPending;
  save_new_packets->process_smid = kPending;
  save_new_packets->process_tmid = kPending;
  save_new_packets->process_stmid = kSucceeded;
  save_new_packets->functor = store_functor;
  save_new_packets->op_type = kSaveNew;

  // Store new MID
  callback = std::bind(&Authentication::SaveSessionCallback,
                       this, arg::_1, save_new_packets->mid, save_new_packets);
                                                FLAGS_ms_logging_lifestuff = google::INFO;
                                                DLOG(ERROR) << "Store " << passport::PacketDebugString(passport::MID) << "\t" << HexSubstr(save_new_packets->mid->name()) << "\t" << HexSubstr(save_new_packets->mid->value());
                                                FLAGS_ms_logging_lifestuff = google::FATAL;
  packet_manager_->StorePacket(save_new_packets->mid->name(),
                               CreateGenericPacket(
                                   save_new_packets->mid->value(),
                                   "",
                                   passport::MID),
                               callback);
  // Store new SMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       save_new_packets->smid, save_new_packets);
                                                FLAGS_ms_logging_lifestuff = google::INFO;
                                                DLOG(ERROR) << "Store " << passport::PacketDebugString(passport::SMID) << "\t" << HexSubstr(save_new_packets->smid->name()) << "\t" << HexSubstr(save_new_packets->smid->value());
                                                FLAGS_ms_logging_lifestuff = google::FATAL;
  packet_manager_->StorePacket(save_new_packets->smid->name(),
                               CreateGenericPacket(
                                   save_new_packets->smid->value(),
                                   "",
                                   passport::SMID),
                               callback);
  // Store new TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       save_new_packets->tmid, save_new_packets);
                                                FLAGS_ms_logging_lifestuff = google::INFO;
                                                DLOG(ERROR) << "Store " << passport::PacketDebugString(passport::TMID) << "\t" << HexSubstr(save_new_packets->tmid->name()) << "\t" << HexSubstr(save_new_packets->tmid->value());
                                                FLAGS_ms_logging_lifestuff = google::FATAL;
  packet_manager_->StorePacket(save_new_packets->tmid->name(),
                               CreateGenericPacket(
                                   save_new_packets->tmid->value(),
                                   "",
                                   passport::TMID),
                               callback);

  // Wait for storing to complete
  success = true;
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(3 * kSingleOpTimeout_),
              std::bind(&Authentication::PacketOpDone, this,
                        &store_result));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::ChangeUserData: storing: " << e.what();
    success = false;
  }
  if (store_result != kSuccess || !success) {
    DLOG(ERROR) << "Authentication::ChangeUserData: storing packets failed.";
    session_->passport_->RevertUserDataChange();
    return kAuthenticationError;
  }

  // Prepare to delete old packets
  // Delete old MID
  delete_old_packets->process_tmid = kSucceeded;
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       delete_old_packets->mid, delete_old_packets);
                                                FLAGS_ms_logging_lifestuff = google::INFO;
                                                DLOG(ERROR) << "Delete TMID " << HexSubstr(delete_old_packets->tmid->name()) << "\t" << HexSubstr(delete_old_packets->tmid->value());
                                                FLAGS_ms_logging_lifestuff = google::FATAL;
  packet_manager_->DeletePacket(delete_old_packets->mid->name(),
                                CreateGenericPacket(
                                    delete_old_packets->mid->value(),
                                    "",
                                    passport::MID),
                                callback);
  // Delete old SMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       delete_old_packets->smid, delete_old_packets);
                                                FLAGS_ms_logging_lifestuff = google::INFO;
                                                DLOG(ERROR) << "Delete SMID " << HexSubstr(delete_old_packets->smid->name()) << "\t" << HexSubstr(delete_old_packets->smid->value());
                                                FLAGS_ms_logging_lifestuff = google::FATAL;
  packet_manager_->DeletePacket(delete_old_packets->smid->name(),
                                CreateGenericPacket(
                                    delete_old_packets->smid->value(),
                                    "",
                                    passport::SMID),
                                callback);
  // Delete old STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       delete_old_packets->stmid, delete_old_packets);
                                                FLAGS_ms_logging_lifestuff = google::INFO;
                                                DLOG(ERROR) << "Delete STMID " << HexSubstr(delete_old_packets->stmid->name()) << "\t" << HexSubstr(delete_old_packets->stmid->value());
                                                FLAGS_ms_logging_lifestuff = google::FATAL;
  packet_manager_->DeletePacket(delete_old_packets->stmid->name(),
                                CreateGenericPacket(
                                    delete_old_packets->stmid->value(),
                                    "",
                                    passport::STMID),
                                callback);

  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(
                  lock,
                  boost::posix_time::milliseconds(3 * kSingleOpTimeout_),
                  std::bind(&Authentication::PacketOpDone, this,
                            &delete_result));
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
  if (session_->passport_->ConfirmUserDataChange(save_new_packets->mid,
                                       save_new_packets->smid,
                                       save_new_packets->tmid,
                                       save_new_packets->stmid) != kSuccess) {
    DLOG(ERROR) << "Authentication::ChangeUserData: failed to confirm change.";
    session_->passport_->RevertUserDataChange();
    return kAuthenticationError;
  }
  session_->set_username(new_username);
  session_->set_pin(new_pin);
  return kSuccess;
}

int Authentication::ChangePassword(const std::string &serialised_master_datamap,
                                   const std::string &new_password) {
  // Get updated packets
  int result(kPendingResult);
  VoidFuncOneInt functor = std::bind(&Authentication::PacketOpCallback, this,
                                     arg::_1, &result);
  std::shared_ptr<SaveSessionData>
      update_packets(new SaveSessionData(functor, kUpdate));
  std::shared_ptr<SaveSessionData>
      delete_packets(new SaveSessionData(functor, kDeleteOld));
  update_packets->process_mid = kSucceeded;
  update_packets->process_smid = kSucceeded;
  std::string tmid_old_value, stmid_old_value;
  int res = session_->passport_->ChangePassword(new_password,
                                      serialised_master_datamap,
                                      update_packets->mid,
                                      update_packets->smid,
                                      delete_packets->tmid,
                                      delete_packets->stmid,
                                      update_packets->tmid,
                                      update_packets->stmid);
  if (res != kSuccess) {
    DLOG(ERROR) << "Authentication::ChangePassword: failed ChangePassword.";
    session_->passport_->RevertPasswordChange();
    return kAuthenticationError;
  }

  // Update MID & SMID
  VoidFuncOneInt callback =
      std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                update_packets->mid, update_packets);
  packet_manager_->UpdatePacket(update_packets->mid->name(),
                                CreateGenericPacket(
                                    delete_packets->tmid->name(),
                                    "",
                                    passport::MID),
                                CreateGenericPacket(
                                    update_packets->mid->value(),
                                    "",
                                    passport::MID),
                                callback);
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       update_packets->mid, update_packets);
  packet_manager_->UpdatePacket(update_packets->smid->name(),
                                CreateGenericPacket(
                                    delete_packets->stmid->name(),
                                    "",
                                    passport::SMID),
                                CreateGenericPacket(
                                    update_packets->smid->value(),
                                    "",
                                    passport::SMID),
                                callback);

  // Store new TMID & STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       update_packets->tmid, update_packets);
  packet_manager_->StorePacket(update_packets->tmid->name(),
                               CreateGenericPacket(
                                   update_packets->tmid->value(),
                                   "",
                                   passport::TMID),
                               callback);
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       update_packets->stmid, update_packets);
  packet_manager_->StorePacket(update_packets->stmid->name(),
                               CreateGenericPacket(
                                   update_packets->stmid->value(),
                                   "",
                                   passport::STMID),
                               callback);

  // Wait for update to complete
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(4 * kSingleOpTimeout_),
              std::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::ChangePassword: updating: " << e.what();
    success = false;
  }
  if (result != kSuccess || !success) {
    DLOG(ERROR) << "Authentication::ChangePassword: timed out updating - "
                << (result != kSuccess) << " - " << (!success);
    session_->passport_->RevertPasswordChange();
    return kAuthenticationError;
  }

  // Delete old TMID & STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       delete_packets->tmid, delete_packets);
  packet_manager_->DeletePacket(delete_packets->tmid->name(),
                                CreateGenericPacket(
                                    update_packets->tmid->value(),
                                    "",
                                    passport::TMID),
                                callback);
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       delete_packets->stmid, delete_packets);
  packet_manager_->DeletePacket(delete_packets->stmid->name(),
                                CreateGenericPacket(
                                    delete_packets->stmid->value(),
                                    "",
                                    passport::STMID),
                                callback);

  // Wait for deletion to complete
  success = true;
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(4 * kSingleOpTimeout_),
              std::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::ChangePassword: deleting: " << e.what();
    success = false;
  }
  if (result != kSuccess || !success) {
    DLOG(ERROR) << "Authentication::ChangePassword: timed out deleting - "
                << (result != kSuccess) << " - " << (!success);
    session_->passport_->RevertPasswordChange();
    return kAuthenticationError;
  }

  if (session_->passport_->ConfirmUserDataChange(update_packets->mid,
                                       update_packets->smid,
                                       update_packets->tmid,
                                       update_packets->stmid) != kSuccess) {
    DLOG(ERROR) << "Authentication::ChangePassword: failed to confirm change.";
    session_->passport_->RevertPasswordChange();
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

int Authentication::StorePacket(std::shared_ptr<pki::Packet> packet,
                                bool check_uniqueness,
                                passport::PacketType packet_type) {
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
  DirType dir_type(PRIVATE);
  std::string msid;
  if (packet->packet_type() == passport::MSID) {
    dir_type = PRIVATE_SHARE;
    msid = packet->name();
  }

                                                FLAGS_ms_logging_lifestuff = google::INFO;
   DLOG(ERROR) << "Store " << passport::PacketDebugString(packet_type) << "\t" << HexSubstr(packet->name()) << "\t" << HexSubstr(packet->value());
                                                FLAGS_ms_logging_lifestuff = google::FATAL;
  packet_manager_->StorePacket(packet->name(),
                               CreateGenericPacket(packet->value(),
                                                   "",
                                                   packet_type),
                               functor);
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(kSingleOpTimeout_),
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
              << HexSubstr(packet->name());

  return result;
}

int Authentication::DeletePacket(std::shared_ptr<pki::Packet> packet,
                                 passport::PacketType packet_type) {
  int result(kPendingResult);
  VoidFuncOneInt functor = std::bind(&Authentication::PacketOpCallback, this,
                                     arg::_1, &result);
  DirType dir_type(PRIVATE);
  std::string msid;
  if (packet->packet_type() == passport::MSID) {
    dir_type = PRIVATE_SHARE;
    msid = packet->name();
  }

  packet_manager_->DeletePacket(packet->name(),
                                CreateGenericPacket(packet->value(),
                                                    "",
                                                    packet_type),
                                functor);
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(kSingleOpTimeout_),
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

int Authentication::PacketUnique(std::shared_ptr<pki::Packet> packet) {
  int result(kPendingResult);
  VoidFuncOneInt functor = std::bind(&Authentication::PacketOpCallback, this,
                                     arg::_1, &result);
  DirType dir_type(PRIVATE);
  std::string msid;
  if (packet->packet_type() == passport::MSID) {
    dir_type = PRIVATE_SHARE;
    msid = packet->name();
  }
  packet_manager_->KeyUnique(packet->name(), functor);
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(kSingleOpTimeout_),
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
    const std::string &value,
    const std::string &signature,
    passport::PacketType packet_type) {
  GenericPacket gp;
  gp.set_data(value);
  gp.set_signature(signature);
  gp.set_hashable(true);
  switch (packet_type) {
    case passport::kAnmid:
        gp.set_signing_id(session_->Id(passport::kAnmid, false));
        if (signature.empty())
          gp.set_signature(
              session_->PublicKeySignature(passport::kAnmid, false));
        break;
    case passport::MID:
        gp.set_signing_id(session_->Id(passport::kAnmid, true));
        gp.set_hashable(false);
        if (signature.empty())
          gp.set_signature(
              crypto::AsymSign(gp.data(),
                               session_->PrivateKey(passport::kAnmid, true)));
        break;
    case passport::kAnsmid:
        gp.set_signing_id(session_->Id(passport::kAnsmid, false));
        if (signature.empty())
          gp.set_signature(
              session_->PublicKeySignature(passport::kAnsmid, false));
        break;
    case passport::SMID:
        gp.set_signing_id(session_->Id(passport::kAnsmid, true));
        gp.set_hashable(false);
        if (signature.empty())
          gp.set_signature(
              crypto::AsymSign(gp.data(),
                               session_->PrivateKey(passport::kAnsmid, true)));
        break;
    case passport::kAntmid:
        gp.set_signing_id(session_->Id(passport::kAntmid, false));
        if (signature.empty())
          gp.set_signature(
              session_->PublicKeySignature(passport::kAntmid, false));
        break;
    case passport::TMID:
    case passport::STMID:
        gp.set_signing_id(session_->Id(passport::kAntmid, true));
        gp.set_hashable(false);
        if (signature.empty())
          gp.set_signature(
              crypto::AsymSign(gp.data(),
                               session_->PrivateKey(passport::kAntmid, true)));
        break;
    case passport::ANMPID:
        gp.set_signing_id(session_->Id(passport::ANMPID, false));
        if (signature.empty())
          gp.set_signature(
              session_->PublicKeySignature(passport::ANMPID, false));
        break;
    case passport::MPID:
        gp.set_signing_id(session_->Id(passport::ANMPID, true));
        gp.set_hashable(false);
        break;
    case passport::kAnmaid:
        gp.set_signing_id(session_->Id(passport::kAnmaid, false));
        if (signature.empty())
          gp.set_signature(
              session_->PublicKeySignature(passport::kAnmaid, false));
        break;
    case passport::kMaid:
        gp.set_signing_id(session_->Id(passport::kAnmaid, true));
        if (signature.empty()) {
          gp.set_signature(
              session_->PublicKeySignature(passport::kMaid, true));
        }
        break;
    case passport::kPmid:
        gp.set_signing_id(session_->Id(passport::kMaid, true));
        if (signature.empty())
          gp.set_signature(
              session_->PublicKeySignature(passport::kPmid, true));
        break;
    default: break;
  }
  return gp.SerializeAsString();
}

}  // namespace lifestuff

}  // namespace maidsafe
