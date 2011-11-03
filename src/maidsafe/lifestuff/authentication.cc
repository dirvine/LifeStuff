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
                         boost::posix_time::milliseconds(4 * kSingleOpTimeout_),
                         std::bind(&Authentication::TmidOpDone, this));
      stmid_success =
          cond_var_.timed_wait(
              lock,
              boost::posix_time::milliseconds(2 * kSingleOpTimeout_),
              std::bind(&Authentication::StmidOpDone, this));
    }
    catch(const std::exception &e) {
      DLOG(WARNING) << "Authentication dtor: " << e.what() << std::endl;
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
  passport_ = session_singleton_->passport_;
}

int Authentication::GetUserInfo(const std::string &username,
                                const std::string &pin) {
  std::string mid_name, smid_name;
  int result = passport_->SetInitialDetails(username,
                                            pin,
                                            &mid_name,
                                            &smid_name);

  if (result != kSuccess) {
    tmid_op_status_ = kFailed;
    stmid_op_status_ = kFailed;
    DLOG(ERROR) << "Auth::GetUserInfo: SetInitialDetails=" << result
                << std::endl;
    return kAuthenticationError;
  } else {
    tmid_op_status_ = kPending;
    stmid_op_status_ = kPending;
  }

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
    session_singleton_->set_username(username);
    session_singleton_->set_pin(pin);
    return kUserExists;
  }
  return kUserDoesntExist;
}

void Authentication::GetMidCallback(const std::vector<std::string> &values,
                                    int return_code) {
  if (return_code != kSuccess || values.empty()) {
    DLOG(INFO) << "Auth::GetMidCallback: No MID" << std::endl;
    {
      boost::mutex::scoped_lock loch_chapala(mid_mutex_);
      tmid_op_status_ = kFailed;
    }
    return;
  }

#ifdef DEBUG
  if (values.size() != 1)
    DLOG(WARNING) << "Auth::GetMidCallback - Values: " << values.size()
                  << std::endl;
#endif

  GenericPacket packet;
  if (!packet.ParseFromString(values.at(0)) || packet.data().empty()) {
    DLOG(INFO) << "Auth::GetMidCallback: Failed to parse" << std::endl;
    {
      boost::mutex::scoped_lock loch_chapala(mid_mutex_);
      tmid_op_status_ = kFailed;
    }
    return;
  }

  std::string tmid_name;
  int result = passport_->InitialiseTmid(false, packet.data(), &tmid_name);
  if (result != kSuccess) {
    DLOG(INFO) << "Auth::GetMidCallback: Failed InitialiseTmid" << std::endl;
    {
      boost::mutex::scoped_lock loch_chapala(mid_mutex_);
      tmid_op_status_ = kFailed;
    }
    return;
  }

  packet_manager_->GetPacket(tmid_name,
                             std::bind(&Authentication::GetTmidCallback,
                                       this, arg::_1, arg::_2));
}

void Authentication::GetSmidCallback(const std::vector<std::string> &values,
                                     int return_code) {
  if (return_code != kSuccess || values.empty()) {
    DLOG(INFO) << "Auth::GetSmidCallback: No SMID" << std::endl;
    {
      boost::mutex::scoped_lock loch_chapala(smid_mutex_);
      stmid_op_status_ = kFailed;
    }
    return;
  }

#ifdef DEBUG
  if (values.size() != 1)
    DLOG(WARNING) << "Auth::GetSmidCallback - Values: " << values.size()
                  << std::endl;
#endif

  GenericPacket packet;
  if (!packet.ParseFromString(values.at(0)) || packet.data().empty()) {
    DLOG(INFO) << "Auth::GetSmidCallback: Failed to parse" << std::endl;
    {
      boost::mutex::scoped_lock loch_chapala(smid_mutex_);
      stmid_op_status_ = kFailed;
    }
    return;
  }

  std::string stmid_name;
  int result = passport_->InitialiseTmid(true, packet.data(), &stmid_name);
  if (result != kSuccess) {
    DLOG(INFO) << "Auth::GetSmidCallback: Failed InitialiseStmid" << std::endl;
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
    DLOG(INFO) << "Auth::GetTmidCallback: No TMID" << std::endl;
    {
      boost::mutex::scoped_lock loch_chapala(mid_mutex_);
      tmid_op_status_ = kFailed;
    }
    return;
  }
#ifdef DEBUG
  if (values.size() != 1)
    DLOG(WARNING) << "Auth::GetTmidCallback - Values: " << values.size()
                  << std::endl;
#endif

  GenericPacket packet;
  if (!packet.ParseFromString(values.at(0)) || packet.data().empty()) {
    DLOG(INFO) << "Auth::GetTmidCallback: Failed to parse" << std::endl;
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
    DLOG(INFO) << "Auth::GetStmidCallback: No TMID" << std::endl;
    {
      boost::mutex::scoped_lock loch_chapala(smid_mutex_);
      stmid_op_status_ = kFailed;
    }
    return;
  }
#ifdef DEBUG
  if (values.size() != 1)
    DLOG(WARNING) << "Auth::GetStmidCallback - Values: " << values.size()
                  << std::endl;
#endif

  GenericPacket packet;
  if (!packet.ParseFromString(values.at(0)) || packet.data().empty()) {
    DLOG(INFO) << "Auth::GetStmidCallback: Failed to parse" << std::endl;
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
    DLOG(WARNING) << "Authentication::CreateUserSysPackets - NOT INTIALISED"
                  << std::endl;
    return kAuthenticationError;
  }
  session_singleton_->set_username(username);
  session_singleton_->set_pin(pin);

  OpStatus anmaid_status(kPending);
  CreateSignaturePacket(passport::ANMAID, "", &anmaid_status, NULL);

  OpStatus anmid_status(kPending);
  CreateSignaturePacket(passport::ANMID, "", &anmid_status, NULL);

  OpStatus ansmid_status(kPending);
  CreateSignaturePacket(passport::ANSMID, "", &ansmid_status, NULL);

  OpStatus antmid_status(kPending);
  CreateSignaturePacket(passport::ANTMID, "", &antmid_status, NULL);

  // TODO(Fraser#5#): 2010-10-18 - Thread these next two?
  OpStatus maid_status(kPending);
  CreateSignaturePacket(passport::MAID, "", &maid_status, &anmaid_status);

  OpStatus pmid_status(kPending);
  CreateSignaturePacket(passport::PMID, "", &pmid_status, &maid_status);

  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
                boost::posix_time::milliseconds(5 * kSingleOpTimeout_),
                std::bind(&Authentication::ThreeSystemPacketsOpDone, this,
                          &pmid_status, &anmid_status, &antmid_status));
  }
  catch(const std::exception &e) {
    DLOG(WARNING) << "Authentication::CreateUserSysPackets: " << e.what()
                  << std::endl;
    success = false;
  }
#ifdef DEBUG
  if (!success)
    DLOG(WARNING) << "Authentication::CreateUserSysPackets: timed out."
                  << std::endl;
#endif
  if ((anmaid_status == kSucceeded) && (anmid_status == kSucceeded) &&
      (antmid_status == kSucceeded) && (maid_status == kSucceeded) &&
      (pmid_status == kSucceeded)) {
    return kSuccess;
  } else {
    return kAuthenticationError;
  }
}

void Authentication::CreateSignaturePacket(
    const passport::PacketType &packet_type,
    const std::string &public_name,
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
      DLOG(WARNING) << "Authentication::CreateSigPkt (" << packet_type << "): "
                    << e.what() << std::endl;
      success = false;
    }
    success = (*dependent_op_status == kSucceeded);
  }
  if (!success) {
    DLOG(WARNING) << "Authentication::CreateSigPkt (" << packet_type
                  << "): failed wait." << std::endl;
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kFailed;
    cond_var_.notify_all();
    return;
  }

  // Create packet
  std::shared_ptr<passport::SignaturePacket>
      sig_packet(new passport::SignaturePacket);
  int result(kPendingResult);
  if (packet_type == passport::MPID)
    result = passport_->InitialiseMpid(public_name, sig_packet);
  else
    result = passport_->InitialiseSignaturePacket(packet_type, sig_packet);
  if (result != kSuccess) {
    DLOG(WARNING) << "Authentication::CreateSigPkt (" << packet_type
                  << "): failed init." << std::endl;
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kFailed;
    cond_var_.notify_all();
    return;
  }

  // Check packet name is not already a key on the DHT
//  DLOG(INFO) << "Authentication::CreateSignaturePacket - " << packet_type
//             << " - " << HexSubstr(sig_packet->name());
  VoidFuncOneInt f = std::bind(&Authentication::SignaturePacketUniqueCallback,
                               this, arg::_1, sig_packet, op_status);
  packet_manager_->KeyUnique(sig_packet->name(), f);
}

void Authentication::SignaturePacketUniqueCallback(
    int return_code,
    std::shared_ptr<passport::SignaturePacket> packet,
    OpStatus *op_status) {
  passport::PacketType packet_type =
      static_cast<passport::PacketType>(packet->packet_type());
  if (return_code != kKeyUnique) {
    boost::mutex::scoped_lock lock(mutex_);
    DLOG(ERROR) << "Authentication::SignaturePacketUniqueCbk (" << packet_type
                << "): Failed to store." << std::endl;
    *op_status = kNotUnique;
    passport_->RevertSignaturePacket(packet_type);
    cond_var_.notify_all();
    return;
  }

  // Store packet
  VoidFuncOneInt functor =
      std::bind(&Authentication::SignaturePacketStoreCallback,
                this, arg::_1, packet, op_status);

  packet_manager_->StorePacket(packet->name(),
                               CreateGenericPacket(
                                   packet->value(),
                                   packet->public_key_signature(),
                                   packet_type),
                               functor);
}

void Authentication::SignaturePacketStoreCallback(
    int return_code,
    std::shared_ptr<passport::SignaturePacket> packet,
    OpStatus *op_status) {
  passport::PacketType packet_type =
      static_cast<passport::PacketType>(packet->packet_type());
  boost::mutex::scoped_lock lock(mutex_);
  if (return_code == kSuccess) {
    *op_status = kSucceeded;
    passport_->ConfirmSignaturePacket(packet);
//    if (packet_type == passport::PMID)
//      packet_manager_->SetPmid(packet->name());
  } else {
    DLOG(WARNING) << "Authentication::SignaturePacketStoreCbk (" << packet_type
                  << "): Failed to store." << std::endl;
    *op_status = kFailed;
    passport_->RevertSignaturePacket(packet_type);
  }
  cond_var_.notify_all();
}

int Authentication::CreateTmidPacket(const std::string &username,
                                     const std::string &pin,
                                     const std::string &password,
                                     const std::string &serialised_datamap) {
  if ((username != session_singleton_->username()) ||
      (pin != session_singleton_->pin())) {
    DLOG(ERROR) << "Authentication::CreateTmidPacket: username/pin error."
                << std::endl;
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
    result = passport_->SetNewUserData(password, serialised_datamap, mid, smid,
                                       tmid, stmid);
    if (result != kSuccess) {
      DLOG(ERROR) << "Authentication::CreateTmidPacket: Failed init."
                  << std::endl;
      return kAuthenticationError;
    }
    bool unique((PacketUnique(mid) == kKeyUnique) &&
                (PacketUnique(smid) == kKeyUnique) &&
                (PacketUnique(tmid) == kKeyUnique) &&
                (PacketUnique(stmid) == kKeyUnique));
    if (!unique) {
      DLOG(ERROR) << "Authentication::CreateTmidPacket: MID/SMID/TMID/STMID "
                     "exists." << std::endl;
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
    DLOG(ERROR) << "Authentication::CreateTmidPacket: Failed." << std::endl;
    return kAuthenticationError;
  } else {
    passport_->ConfirmNewUserData(mid, smid, tmid, stmid);
    session_singleton_->set_password(password);
    return kSuccess;
  }
}

void Authentication::SaveSession(const std::string &serialised_master_datamap,
                                 const VoidFuncOneInt &functor) {
  std::shared_ptr<SaveSessionData>
      save_session_data(new SaveSessionData(functor, kRegular));
  save_session_data->stmid->SetToSurrogate();

  std::string mid_old_value, smid_old_value;
  int result(passport_->UpdateMasterData(serialised_master_datamap,
                                         &mid_old_value,
                                         &smid_old_value,
                                         save_session_data->mid,
                                         save_session_data->smid,
                                         save_session_data->tmid,
                                         save_session_data->stmid));
  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::SaveSession: failed UpdateUserData."
                << std::endl;
    functor(kAuthenticationError);
    return;
  }

  // Update or store SMID
  VoidFuncOneInt callback = std::bind(&Authentication::SaveSessionCallback,
                                      this, arg::_1, save_session_data->smid,
                                      save_session_data);
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
  packet_manager_->StorePacket(save_session_data->tmid->name(),
                               CreateGenericPacket(
                                   save_session_data->tmid->value(),
                                   "",
                                   passport::TMID),
                               callback);

  // Delete old STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       save_session_data->stmid, save_session_data);
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
      DLOG(WARNING) << "Authentication::SaveSessionCallback MID: Return Code "
                    << return_code << std::endl;
      save_session_data->process_mid = op_status;
      break;
    case passport::SMID:
      DLOG(WARNING) << "Authentication::SaveSessionCallback SMID: Return Code "
                    << return_code << std::endl;
      save_session_data->process_smid = op_status;
      break;
    case passport::TMID:
      DLOG(WARNING) << "Authentication::SaveSessionCallback TMID: Return Code "
                    << return_code << std::endl;
      save_session_data->process_tmid = op_status;
      break;
    case passport::STMID:
      DLOG(WARNING) << "Authentication::SaveSessionCallback STMID: Return Code "
                    << return_code << std::endl;
      save_session_data->process_stmid = op_status;
      break;
    default:
      break;
  }
  if ((save_session_data->process_mid == kPending) ||
      (save_session_data->process_smid == kPending) ||
      (save_session_data->process_tmid == kPending) ||
      (save_session_data->process_stmid == kPending))
    return;
  if ((save_session_data->process_mid == kFailed) ||
      (save_session_data->process_smid == kFailed) ||
      (save_session_data->process_tmid == kFailed) ||
      (save_session_data->process_stmid == kFailed)) {
    lock.unlock();
    passport_->RevertMasterDataUpdate();
    save_session_data->functor(kAuthenticationError);
    return;
  }
  lock.unlock();
  passport_->ConfirmMasterDataUpdate(save_session_data->mid,
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
                    << return_code << std::endl;
      save_session_data->process_mid = op_status;
      break;
    case passport::SMID:
      DLOG(WARNING) << "Authentication::SaveSessionCallback SMID: Return Code "
                    << return_code << std::endl;
      save_session_data->process_smid = op_status;
      break;
    case passport::TMID:
      DLOG(WARNING) << "Authentication::SaveSessionCallback TMID: Return Code "
                    << return_code << std::endl;
      save_session_data->process_tmid = op_status;
      break;
    case passport::STMID:
      DLOG(WARNING) << "Authentication::SaveSessionCallback STMID: Return Code "
                    << return_code << std::endl;
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
    passport_->RevertMasterDataUpdate();
    DLOG(WARNING) << "Authentication::SaveSessionCallback - One op failed"
                  << std::endl;
    save_session_data->functor(kAuthenticationError);
    return;
  }
  lock.unlock();

  // It's all good, confirm to passport
  passport_->ConfirmMasterDataUpdate(save_session_data->mid,
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
    DLOG(WARNING) << "Authentication::SaveSession: " << e.what() << std::endl;
    success = false;
  }
  if (!success) {
    DLOG(ERROR) << "Authentication::SaveSession: timed out." << std::endl;
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
  int res = passport_->GetUserData(password, false, encrypted_tmid_,
                                   serialised_master_datamap.get());
  if (res == kSuccess) {
    session_singleton_->set_password(password);
    passport_->GetUserData(password, true, encrypted_stmid_,
                           surrogate_serialised_master_datamap.get());
    return res;
  } else {
    DLOG(WARNING) << "Authentication::GetMasterDataMap - TMID error "
                  << res << std::endl;
  }

  res = passport_->GetUserData(password, true, encrypted_stmid_,
                               surrogate_serialised_master_datamap.get());
  if (res == kSuccess) {
    session_singleton_->set_password(password);
    return res;
  } else {
    DLOG(WARNING) << "Authentication::GetMasterDataMap - STMID error "
                  << res << std::endl;
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

  std::shared_ptr<passport::SignaturePacket>
      msid(new passport::SignaturePacket);
  std::vector<boost::uint32_t> share_stats(2, 0);
  int result = passport_->InitialiseSignaturePacket(passport::MSID, msid);
  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::CreateMsidPacket: failed init" << std::endl;
    return kAuthenticationError;
  }
  // Add the share to the session to allow store_manager to retrieve the keys.
  std::vector<std::string> attributes;
  attributes.push_back(msid->name());
  attributes.push_back(msid->name());
  attributes.push_back(msid->value());  // msid->value == msid->public_key
  attributes.push_back(msid->private_key());
  result = session_singleton_->AddPrivateShare(attributes, share_stats, NULL);
  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::CreateMsidPacket: failed adding to session"
                << std::endl;
    session_singleton_->DeletePrivateShare(msid->name(), 0);
    return kAuthenticationError;
  }
  result = StorePacket(msid, true, passport::MSID);
#ifdef DEBUG
  if (result != kSuccess)
    DLOG(ERROR) << "Authentication::CreateMsidPacket: Failed storing MSID"
                << std::endl;
#endif
  // Remove the share from the session again to allow CC to add it fully.
  session_singleton_->DeletePrivateShare(msid->name(), 0);

  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::CreateMsidPacket: Failed." << std::endl;
    return kAuthenticationError;
  } else {
    *msid_name = msid->name();
    *msid_public_key = msid->value();
    *msid_private_key = msid->private_key();
    return kSuccess;
  }
}

int Authentication::CreatePublicName(const std::string &public_name) {
  if (!session_singleton_->public_username().empty()) {
    DLOG(ERROR) << "Authentication::CreatePublicName: Already set" << std::endl;
    return kPublicUsernameAlreadySet;
  }

  OpStatus anmpid_status(kSucceeded);
  if (!passport_->GetPacket(passport::ANMPID, true)) {
    anmpid_status = kPending;
    CreateSignaturePacket(passport::ANMPID, "", &anmpid_status, NULL);
  }

  // TODO(Fraser#5#): 2010-10-18 - Thread this?
  OpStatus mpid_status(kPending);
  CreateSignaturePacket(passport::MPID, public_name, &mpid_status,
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
    DLOG(WARNING) << "Authentication::CreatePublicName: " << e.what()
                  << std::endl;
    success = false;
  }
#ifdef DEBUG
  if (!success)
    DLOG(INFO) << "Authentication::CreatePublicName: timed out" << std::endl;
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
  DeletePacket(passport::PMID, &pmid_status, NULL);
  OpStatus maid_status(kPending);
  DeletePacket(passport::MAID, &maid_status, &pmid_status);
  OpStatus anmaid_status(kPending);
  DeletePacket(passport::ANMAID, &anmaid_status, &maid_status);

  OpStatus tmid_status(kPending);
  DeletePacket(passport::TMID, &tmid_status, NULL);
  OpStatus stmid_status(kPending);
  DeletePacket(passport::STMID, &stmid_status, &tmid_status);
  OpStatus antmid_status(kPending);
  DeletePacket(passport::ANTMID, &antmid_status, &stmid_status);

  OpStatus mid_status(kPending);
  DeletePacket(passport::MID, &mid_status, NULL);
  OpStatus anmid_status(kPending);
  DeletePacket(passport::ANMID, &anmid_status, &mid_status);

  OpStatus smid_status(kPending);
  DeletePacket(passport::SMID, &smid_status, NULL);
  OpStatus ansmid_status(kPending);
  DeletePacket(passport::ANSMID, &ansmid_status, &smid_status);

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
    DLOG(INFO) << "Authentication::RemoveMe: " << e.what() << std::endl;
    success = false;
  }
#ifdef DEBUG
  if (!success)
    DLOG(INFO) << "Authentication::RemoveMe: timed out." << std::endl;
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
      DLOG(INFO) << "Authentication::DeletePacket (" << packet_type << "): "
                 << e.what() << std::endl;
      success = false;
    }
    success = (*dependent_op_status == kSucceeded);
  }
  if (!success) {
    DLOG(INFO) << "Authentication::DeletePacket (" << packet_type
               << "): Failed wait" << std::endl;
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kFailed;
    cond_var_.notify_all();
    return;
  }

  // Retrieve packet
  std::shared_ptr<pki::Packet> packet(passport_->GetPacket(packet_type, true));
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
    passport_->DeletePacket(packet_type);
  } else {
    DLOG(INFO) << "Authentication::DeletePacketCallback (" << packet_type
               << "): Failed to delete" << std::endl;
    *op_status = kFailed;
  }
  cond_var_.notify_all();
}

int Authentication::ChangeUsername(const std::string &serialised_master_datamap,
                                   const std::string &new_username) {
  return ChangeUserData(serialised_master_datamap,
                        new_username,
                        session_singleton_->pin());
}

int Authentication::ChangePin(const std::string &serialised_master_datamap,
                              const std::string &new_pin) {
  return ChangeUserData(serialised_master_datamap,
                        session_singleton_->username(),
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
      save_new_packets(new SaveSessionData(uniqueness_functor, kIsUnique));

  int delete_result(kPendingResult);
  VoidFuncOneInt delete_functor = std::bind(&Authentication::PacketOpCallback,
                                            this, arg::_1, &delete_result);
  std::shared_ptr<SaveSessionData>
      delete_old_packets(new SaveSessionData(delete_functor, kDeleteOld));

  int result = passport_->ChangeUserData(new_username, new_pin,
               serialised_master_datamap, delete_old_packets->mid,
               delete_old_packets->smid, delete_old_packets->tmid,
               delete_old_packets->stmid, save_new_packets->mid,
               save_new_packets->smid, save_new_packets->tmid,
               save_new_packets->stmid);
  if (result != kSuccess) {
    DLOG(ERROR) << "Authentication::ChangeUserData: failed ChangeUserData"
                << std::endl;
    passport_->RevertUserDataChange();
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
  // Check new STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       save_new_packets->stmid, save_new_packets);
  packet_manager_->KeyUnique(save_new_packets->stmid->name(), callback);

  // Wait for checking to complete
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(4 * kSingleOpTimeout_),
              std::bind(&Authentication::PacketOpDone, this,
                        &uniqueness_result));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::ChangeUserData: checking  - " << e.what()
                << std::endl;
    success = false;
  }
  if (!success) {
    DLOG(ERROR) << "Authentication::ChangeUserData: timed out storing."
                << std::endl;
    passport_->RevertUserDataChange();
    return kAuthenticationError;
  }
  if (uniqueness_result != kSuccess) {
    DLOG(ERROR) << "Authentication::ChangeUserData: non-unique packets."
                << std::endl;
    passport_->RevertUserDataChange();
    return kUserExists;
  }

  int store_result(kPendingResult);
  VoidFuncOneInt store_functor = std::bind(&Authentication::PacketOpCallback,
                                           this, arg::_1, &store_result);
  save_new_packets->process_mid = kPending;
  save_new_packets->process_smid = kPending;
  save_new_packets->process_tmid = kPending;
  save_new_packets->process_stmid = kPending;
  save_new_packets->functor = store_functor;
  save_new_packets->op_type = kSaveNew;

  // Store new MID
  callback = std::bind(&Authentication::SaveSessionCallback,
                       this, arg::_1, save_new_packets->mid, save_new_packets);
  packet_manager_->StorePacket(save_new_packets->mid->name(),
                               CreateGenericPacket(
                                   save_new_packets->mid->value(),
                                   "",
                                   passport::MID),
                               callback);
  // Store new SMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       save_new_packets->smid, save_new_packets);
  packet_manager_->StorePacket(save_new_packets->smid->name(),
                               CreateGenericPacket(
                                   save_new_packets->smid->value(),
                                   "",
                                   passport::SMID),
                               callback);
  // Store new TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       save_new_packets->tmid, save_new_packets);
  packet_manager_->StorePacket(save_new_packets->tmid->name(),
                               CreateGenericPacket(
                                   save_new_packets->tmid->value(),
                                   "",
                                   passport::TMID),
                               callback);
  // Store new STMID
  if (save_new_packets->stmid->name() == save_new_packets->tmid->name()) {
    // This should only be the case for a new user where only one SaveSession
    // has been done.
    save_new_packets->process_stmid = kSucceeded;
  } else {
    callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                         save_new_packets->stmid, save_new_packets);
    packet_manager_->StorePacket(save_new_packets->stmid->name(),
                                 CreateGenericPacket(
                                     save_new_packets->stmid->value(),
                                     "",
                                     passport::STMID),
                                 callback);
  }

  // Wait for storing to complete
  success = true;
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(4 * kSingleOpTimeout_),
              std::bind(&Authentication::PacketOpDone, this,
                        &store_result));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::ChangeUserData: storing: " << e.what()
                << std::endl;
    success = false;
  }
  if (store_result != kSuccess || !success) {
    DLOG(ERROR) << "Authentication::ChangeUserData: storing packets failed."
                << std::endl;
    passport_->RevertUserDataChange();
    return kAuthenticationError;
  }

  // Prepare to delete old packets
  // Delete old MID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       delete_old_packets->mid, delete_old_packets);
  packet_manager_->DeletePacket(delete_old_packets->mid->name(),
                                CreateGenericPacket(
                                    delete_old_packets->mid->value(),
                                    "",
                                    passport::MID),
                                callback);
  // Delete old SMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       delete_old_packets->smid, delete_old_packets);
  packet_manager_->DeletePacket(delete_old_packets->smid->name(),
                                CreateGenericPacket(
                                    delete_old_packets->smid->value(),
                                    "",
                                    passport::SMID),
                                callback);
  // Delete old TMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       delete_old_packets->tmid, delete_old_packets);
  packet_manager_->DeletePacket(delete_old_packets->tmid->name(),
                                CreateGenericPacket(
                                    delete_old_packets->tmid->value(),
                                    "",
                                    passport::TMID),
                                callback);
  // Delete old STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       delete_old_packets->stmid, delete_old_packets);
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
                  boost::posix_time::milliseconds(4 * kSingleOpTimeout_),
                  std::bind(&Authentication::PacketOpDone, this,
                            &delete_result));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::ChangeUserData - deleting: " << e.what()
                << std::endl;
    success = false;
  }
#ifdef DEBUG
  if (!success)
    DLOG(ERROR) << "Authentication::ChangeUserData: timed out deleting."
                << std::endl;
#endif
  // Result of deletions not considered here.
  if (passport_->ConfirmUserDataChange(save_new_packets->mid,
                                       save_new_packets->smid,
                                       save_new_packets->tmid,
                                       save_new_packets->stmid) != kSuccess) {
    DLOG(ERROR) << "Authentication::ChangeUserData: failed to confirm change."
                << std::endl;
    passport_->RevertUserDataChange();
    return kAuthenticationError;
  }
  session_singleton_->set_username(new_username);
  session_singleton_->set_pin(new_pin);
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
  update_packets->process_mid = kSucceeded;
  update_packets->process_smid = kSucceeded;
  std::string tmid_old_value, stmid_old_value;
  int res = passport_->ChangePassword(new_password,
                                      serialised_master_datamap,
                                      &tmid_old_value,
                                      &stmid_old_value,
                                      update_packets->tmid,
                                      update_packets->stmid);
  if (res != kSuccess) {
    DLOG(ERROR) << "Authentication::ChangePassword: failed ChangePassword."
                << std::endl;
    passport_->RevertPasswordChange();
    return kAuthenticationError;
  }

  // Update TMID
  VoidFuncOneInt callback =
      std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                update_packets->tmid, update_packets);
  packet_manager_->UpdatePacket(update_packets->tmid->name(),
                                CreateGenericPacket(tmid_old_value,
                                                    "",
                                                    passport::TMID),
                                CreateGenericPacket(
                                    update_packets->tmid->value(),
                                    "",
                                    passport::STMID),
                                callback);
  // Update STMID
  callback = std::bind(&Authentication::SaveSessionCallback, this, arg::_1,
                       update_packets->stmid, update_packets);
  packet_manager_->UpdatePacket(update_packets->stmid->name(),
                                CreateGenericPacket(stmid_old_value,
                                                    "",
                                                    passport::STMID),
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
              boost::posix_time::milliseconds(2 * kSingleOpTimeout_),
              std::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Authentication::ChangePassword: updating: " << e.what()
                << std::endl;
    success = false;
  }
  if (result != kSuccess || !success) {
    DLOG(ERROR) << "Authentication::ChangePassword: timed out updating - "
                << (result != kSuccess) << " - " << (!success) << std::endl;
    passport_->RevertPasswordChange();
    return kAuthenticationError;
  }
  if (passport_->ConfirmPasswordChange(update_packets->tmid,
                                       update_packets->stmid) != kSuccess) {
    DLOG(ERROR) << "Authentication::ChangePassword: failed to confirm change."
                << std::endl;
    passport_->RevertPasswordChange();
    return kAuthenticationError;
  }
  session_singleton_->set_password(new_password);
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
      DLOG(ERROR) << "Authentication::StorePacket: key already exists."
                  << std::endl;
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
    DLOG(ERROR) << "Authentication::StorePacket: " << e.what() << std::endl;
    success = false;
  }
  if (!success) {
    DLOG(ERROR) << "Authentication::StorePacket: timed out." << std::endl;
    return kAuthenticationError;
  }
#ifdef DEBUG
  if (result != kSuccess)
    DLOG(INFO) << "Authentication::StorePacket: result=" << result << std::endl;
#endif
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
    DLOG(WARNING) << "Authentication::DeletePacket: " << e.what() << std::endl;
    success = false;
  }
  if (!success) {
    DLOG(WARNING) << "Authentication::DeletePacket: Timed out." << std::endl;
    return kAuthenticationError;
  }
#ifdef DEBUG
  if (result != kSuccess)
    DLOG(INFO) << "Authentication::DeletePacket result=" << result << std::endl;
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
    DLOG(WARNING) << "Authentication::PacketUnique: " << e.what() << std::endl;
    success = false;
  }
  if (!success) {
    DLOG(ERROR) << "Authentication::PacketUnique: timed out." << std::endl;
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
    case passport::ANMID:
        gp.set_signing_id(session_singleton_->Id(passport::ANMID, false));
        if (signature.empty())
          gp.set_signature(
              session_singleton_->PublicKeySignature(passport::ANMID, false));
        break;
    case passport::MID:
        gp.set_signing_id(session_singleton_->Id(passport::ANMID, true));
        gp.set_hashable(false);
        if (signature.empty())
          gp.set_signature(
              crypto::AsymSign(gp.data(),
                               session_singleton_->PrivateKey(passport::ANMID,
                                                              true)));
        break;
    case passport::ANSMID:
        gp.set_signing_id(session_singleton_->Id(passport::ANSMID, false));
        if (signature.empty())
          gp.set_signature(
              session_singleton_->PublicKeySignature(passport::ANSMID, false));
        break;
    case passport::SMID:
        gp.set_signing_id(session_singleton_->Id(passport::ANSMID, true));
        gp.set_hashable(false);
        if (signature.empty())
          gp.set_signature(
              crypto::AsymSign(gp.data(),
                               session_singleton_->PrivateKey(passport::ANSMID,
                                                              true)));
        break;
    case passport::ANTMID:
        gp.set_signing_id(session_singleton_->Id(passport::ANTMID, false));
        if (signature.empty())
          gp.set_signature(
              session_singleton_->PublicKeySignature(passport::ANTMID, false));
        break;
    case passport::TMID:
    case passport::STMID:
        gp.set_signing_id(session_singleton_->Id(passport::ANTMID, true));
        gp.set_hashable(false);
        if (signature.empty())
          gp.set_signature(
              crypto::AsymSign(gp.data(),
                               session_singleton_->PrivateKey(passport::ANTMID,
                                                              true)));
        break;
    case passport::ANMPID:
        gp.set_signing_id(session_singleton_->Id(passport::ANMPID, false));
        if (signature.empty())
          gp.set_signature(
              session_singleton_->PublicKeySignature(passport::ANMPID, false));
        break;
    case passport::MPID:
        gp.set_signing_id(session_singleton_->Id(passport::ANMPID, true));
        gp.set_hashable(false);
        break;
    case passport::ANMAID:
        gp.set_signing_id(session_singleton_->Id(passport::ANMAID, false));
        if (signature.empty())
          gp.set_signature(
              session_singleton_->PublicKeySignature(passport::ANMAID, false));
        break;
    case passport::MAID:
        gp.set_signing_id(session_singleton_->Id(passport::ANMAID, true));
        if (signature.empty())
          gp.set_signature(
              session_singleton_->PublicKeySignature(passport::MAID, true));
        break;
    case passport::PMID:
        gp.set_signing_id(session_singleton_->Id(passport::MAID, true));
        if (signature.empty())
          gp.set_signature(
              session_singleton_->PublicKeySignature(passport::PMID, true));
        break;
    default: break;
  }
  return gp.SerializeAsString();
}

}  // namespace lifestuff

}  // namespace maidsafe
