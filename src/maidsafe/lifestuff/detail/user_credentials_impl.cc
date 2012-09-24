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

#include "maidsafe/lifestuff/detail/user_credentials_impl.h"

#include <memory>
#include <vector>

#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/thread/thread.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"
#include "maidsafe/private/utils/utilities.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/detail/account_locking.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"


namespace args = std::placeholders;
namespace pca = maidsafe::priv::chunk_actions;
namespace bptime = boost::posix_time;
namespace lid = maidsafe::lifestuff::account_locking;
namespace utils = maidsafe::priv::utilities;

namespace maidsafe {

namespace lifestuff {

namespace {

int CreateSignaturePacketInfo(std::shared_ptr<asymm::Keys> packet,
                              std::string* packet_name,
                              std::string* packet_content) {
  BOOST_ASSERT(packet && packet_name && packet_content);
  *packet_name = pca::ApplyTypeToName(packet->identity, pca::kSignaturePacket);

  pca::SignedData signed_data;
  std::string public_key;
  asymm::EncodePublicKey(packet->public_key, &public_key);
  if (public_key.empty()) {
    LOG(kError) << "Public key not properly encoded.";
    return kCreateSignaturePacketInfoFailure;
  }

  signed_data.set_data(public_key);
  signed_data.set_signature(packet->validation_token);
  if (!signed_data.SerializeToString(packet_content) || packet_content->empty()) {
    LOG(kError) << "SignedData not properly serialised.";
    return kCreateSignaturePacketInfoFailure;
  }

  return kSuccess;
}

}  // namespace

UserCredentialsImpl::UserCredentialsImpl(pcs::RemoteChunkStore& remote_chunk_store,
                                         Session& session,
                                         boost::asio::io_service& service)
    : remote_chunk_store_(remote_chunk_store),
      session_(session),
      passport_(session_.passport()),
      single_threaded_class_mutex_(),
      asio_service_(service),
      session_saver_timer_(asio_service_),
      session_saver_timer_active_(false),
      session_saved_once_(false),
      session_saver_interval_(kSecondsInterval * 3),
      immediate_quit_required_signal_() {}

UserCredentialsImpl::~UserCredentialsImpl() {}

int UserCredentialsImpl::LogIn(const std::string& keyword,
                               const std::string& pin,
                               const std::string& password) {
  int result = AttemptLogInProcess(keyword, pin, password);
  if (result != kSuccess && result != kReadOnlyRestrictedSuccess)
    session_.Reset();
  return result;
}

int UserCredentialsImpl::AttemptLogInProcess(const std::string& keyword,
                                             const std::string& pin,
                                             const std::string& password) {
  std::unique_lock<std::mutex>loch_a_phuill(single_threaded_class_mutex_);

  int result(CheckKeywordValidity(keyword));
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid keyword: " << keyword << "    Return code: " << result << ")";
    return result;
  }
  result = CheckPinValidity(pin);
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid pin: " << pin << "    Return code: " << result << ")";
    return result;
  }
  result = CheckPasswordValidity(password);
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid password: " << password << "    Return code: " << result << ")";
    return result;
  }

//  std::string lid_packet(remote_chunk_store_.Get(pca::ApplyTypeToName(lid::LidName(keyword, pin),
//                                                                      pca::kModifiableByOwner)));
//  LockingPacket locking_packet;
//  int lid_result(lid::ProcessAccountStatus(keyword, pin, password, lid_packet, locking_packet));
//  bool lid_corrupted(false);
//  if (lid_result != kSuccess) {
//    if (lid_result == kCorruptedLidPacket) {
//      lid_corrupted = true;
//    } else {
//      LOG(kError) << "Couldn't get or process LID. Account can't be logged in: " << lid_result;
//      return lid_result;
//    }
//  }


  std::string mid_packet, smid_packet;
  result = GetUserInfo(keyword, pin, password, false, mid_packet, smid_packet);
  if (result != kSuccess) {
    LOG(kInfo) << "UserCredentialsImpl::LogIn - failed to get user info.";
    return result;
  }

//  bool need_to_wait(false);
//  result = GetAndLockLid(keyword, pin, password, lid_packet, locking_packet);
//  if (result == kCorruptedLidPacket && lid_corrupted == true) {
//    LOG(kInfo) << "Trying to fix corrupted packet...";
//    session_.set_keyword(keyword);
//    session_.set_pin(pin);
//    session_.set_password(password);
//    session_.set_session_access_level(kFullAccess);
//    if (!session_.set_session_name()) {
//      LOG(kError) << "Failed to set session.";
//      return kSessionFailure;
//    }
//    locking_packet = lid::CreateLockingPacket(session_.session_name());
//  } else if (result != kSuccess) {
//    LOG(kError) << "Failed to GetAndLock LID.";
//    return result;
//  } else {
    session_.set_keyword(keyword);
    session_.set_pin(pin);
    session_.set_password(password);
    session_.set_session_access_level(kFullAccess);
    if (!session_.set_session_name()) {
      LOG(kError) << "Failed to set session.";
      return kSessionFailure;
    }

//    int i(0);
//    result = kGeneralError;
//    while (i++ < 10 && result != kSuccess) {
//      result = lid::CheckLockingPacketForIdentifier(locking_packet, session_.session_name());
//      if (result != kSuccess) {
//        if (!session_.set_session_name()) {
//          LOG(kError) << "Failed to set session name.";
//          return kSessionFailure;
//        }
//      }
//    }
//    result = lid::AddItemToLockingPacket(locking_packet, session_.session_name(), true);
//    if (result == kLidIdentifierAlreadyInUse) {
//      LOG(kError) << "Failed to add item to locking packet";
//      return result;
//    }
//    if (result == kLidFullAccessUnavailable)
//      need_to_wait = true;
//    lid::OverthrowInstancesUsingLockingPacket(locking_packet, session_.session_name());
//  }

//  result = ModifyLid(keyword, pin, password, locking_packet);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to modify LID.";
//    return result;
//  }

//  if (need_to_wait) {
//    LOG(kInfo) << "Need to wait before logging in.";
//    Sleep(bptime::seconds(15));
//    result = GetUserInfo(keyword, pin, password, true, mid_packet, smid_packet);
//    if (result != kSuccess) {
//      LOG(kError) << "Failed to re-get user credentials.";
//      return result;
//    }
//  }

  session_saved_once_ = false;
//  StartSessionSaver();

  return kSuccess;
}

int UserCredentialsImpl::LogOut() {
  int result(SaveSession(true));
  if (result != kSuccess) {
    LOG(kError) << "Failed to save session on Logout";
    return result;
  }
//  result = AssessAndUpdateLid(true);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to update LID on Logout";
//    return result;
//  }

  session_.Reset();
  return kSuccess;
}

int UserCredentialsImpl::GetUserInfo(const std::string& keyword,
                                     const std::string& pin,
                                     const std::string& password,
                                     const bool& compare_names,
                                     std::string& mid_packet,
                                     std::string& smid_packet) {
  if (compare_names) {
    std::string new_mid_packet;
    std::string new_smid_packet;

    boost::thread get_mid_thread(
          [&] {
            new_mid_packet = remote_chunk_store_.Get(pca::ApplyTypeToName(
                                                       passport::MidName(keyword, pin, false),
                                                       pca::kModifiableByOwner));
          });
    boost::thread get_smid_thread(
        [&] {
          new_smid_packet = remote_chunk_store_.Get(pca::ApplyTypeToName(
                                                     passport::MidName(keyword, pin, true),
                                                     pca::kModifiableByOwner));
        });

    get_mid_thread.join();
    get_smid_thread.join();

    if (new_mid_packet.empty()) {
      LOG(kError) << "No MID found.";
      return kIdPacketNotFound;
    }
    if (new_smid_packet.empty()) {
      LOG(kError) << "No SMID found.";
      return kIdPacketNotFound;
    }

    if (mid_packet == new_mid_packet && smid_packet == new_smid_packet) {
      LOG(kInfo) << "MID and SMID are up to date.";
      return kSuccess;
    }
  }

  // Obtain MID, TMID
  int mid_tmid_result(kSuccess);
  std::string tmid_packet;
  boost::thread mid_tmid_thread([&] {
                                  GetIdAndTemporaryId(keyword,
                                                      pin,
                                                      password,
                                                      false,
                                                      &mid_tmid_result,
                                                      &mid_packet,
                                                      &tmid_packet);
                                });
  // Obtain SMID, STMID
  int smid_stmid_result(kSuccess);
  std::string stmid_packet;
  boost::thread smid_stmid_thread([&] {
                                    GetIdAndTemporaryId(keyword,
                                                        pin,
                                                        password,
                                                        true,
                                                        &smid_stmid_result,
                                                        &smid_packet,
                                                        &stmid_packet);
                                  });

  // Wait for them to finish
  mid_tmid_thread.join();
  smid_stmid_thread.join();

  // Evaluate MID & TMID
  if (mid_tmid_result == kIdPacketNotFound && smid_stmid_result == kIdPacketNotFound) {
    LOG(kInfo) << "User doesn't exist: " << keyword << ", " << pin;
    return kUserDoesntExist;
  }

  if (mid_tmid_result == kCorruptedPacket && smid_stmid_result == kCorruptedPacket) {
    LOG(kError) << "Account corrupted. Should never happen: "
                << keyword << ", " << pin;
    return kAccountCorrupted;
  }

  int result(HandleSerialisedDataMaps(keyword, pin, password, tmid_packet, stmid_packet));
  if (result != kSuccess) {
    if (result == kTryAgainLater) {
      return result;
    } else if (result != kUsingNextToLastSession) {
      LOG(kError) << "Failed to initialise session: " << result;
      result = kAccountCorrupted;
    }
    return result;
  }

  return kSuccess;
}

int UserCredentialsImpl::GetAndLockLid(const std::string& keyword,
                                       const std::string& pin,
                                       const std::string& password,
                                       std::string& lid_packet,
                                       LockingPacket& locking_packet) {
  std::string lid_name(pca::ApplyTypeToName(lid::LidName(keyword, pin), pca::kModifiableByOwner));

  std::shared_ptr<asymm::Keys> keys(
      new asymm::Keys(passport_.SignaturePacketDetails(passport::kAnmid, true)));
  int get_lock_result(remote_chunk_store_.GetAndLock(lid_name, "", keys, &lid_packet));
  if (get_lock_result != kSuccess) {
    LOG(kError) << "Failed to GetAndLock LID: " << get_lock_result;
    return get_lock_result;
  }
  return lid::ProcessAccountStatus(keyword, pin, password, lid_packet, locking_packet);
}

void UserCredentialsImpl::StartSessionSaver() {
  session_saver_timer_active_ = true;
  session_saver_timer_.expires_from_now(bptime::seconds(session_saver_interval_));
  session_saver_timer_.async_wait([=] (const boost::system::error_code &error_code) {
                                    this->SessionSaver(bptime::seconds(session_saver_interval_),
                                                       error_code);
                                  });
}

void UserCredentialsImpl::GetIdAndTemporaryId(const std::string& keyword,
                                              const std::string& pin,
                                              const std::string& password,
                                              bool surrogate,
                                              int* result,
                                              std::string* id_contents,
                                              std::string* temporary_packet) {
  std::string id_name(pca::ApplyTypeToName(passport::MidName(keyword, pin, surrogate),
                                           pca::kModifiableByOwner));
  std::string id_packet(remote_chunk_store_.Get(id_name));
  if (id_packet.empty()) {
    LOG(kError) << "No " << (surrogate ? "SMID" : "MID") << " found.";
    *result = kIdPacketNotFound;
    return;
  }
  *id_contents = id_packet;

  pca::SignedData packet;
  if (!packet.ParseFromString(id_packet) || packet.data().empty()) {
    LOG(kError) << (surrogate ? "SMID" : "MID") << " packet corrupted: Failed parse.";
    *result = kCorruptedPacket;
    return;
  }

  std::string decrypted_rid(passport::DecryptRid(keyword, pin, packet.data()));
  if (decrypted_rid.empty()) {
    LOG(kError) << (surrogate ? "SMID" : "MID") << " packet corrupted: Failed decryption.";
    *result = kCorruptedPacket;
    return;
  }
  decrypted_rid = pca::ApplyTypeToName(decrypted_rid, pca::kModifiableByOwner);

  std::string temporary_id_packet(remote_chunk_store_.Get(decrypted_rid));
  if (temporary_id_packet.empty()) {
    LOG(kError) << "No " << (surrogate ? "STMID" : "TMID") << " found.";
    *result = kTemporaryIdPacketNotFound;
    return;
  }

  packet.Clear();
  if (!packet.ParseFromString(temporary_id_packet) || packet.data().empty()) {
    LOG(kError) << (surrogate ? "STMID" : "TMID") << " packet corrupted: "
                << "Failed parse.";
    *result = kCorruptedPacket;
    return;
  }

  *temporary_packet = passport::DecryptMasterData(keyword, pin, password, packet.data());
  if (temporary_packet->empty()) {
    LOG(kError) << (surrogate ? "STMID" : "TMID") << " packet corrupted: "
                << "Failed decryption.";
    *result = kCorruptedPacket;
    return;
  }
}

int UserCredentialsImpl::HandleSerialisedDataMaps(const std::string& keyword,
                                                  const std::string& pin,
                                                  const std::string& password,
                                                  const std::string& tmid_serialised_data_atlas,
                                                  const std::string& stmid_serialised_data_atlas) {
  int result(kSuccess);
  std::string tmid_da, stmid_da;
  if (!tmid_serialised_data_atlas.empty()) {
    result = session_.ParseDataAtlas(tmid_serialised_data_atlas);
    if (result == kSuccess) {
      session_.set_serialised_data_atlas(tmid_serialised_data_atlas);
      tmid_da = tmid_serialised_data_atlas;
    } else if (result == kTryAgainLater) {
      return kTryAgainLater;
    }
  } else if (!stmid_serialised_data_atlas.empty()) {
    tmid_da = stmid_serialised_data_atlas;
    stmid_da = stmid_serialised_data_atlas;
    result = session_.ParseDataAtlas(stmid_serialised_data_atlas);
    if (result == kSuccess) {
      session_.set_serialised_data_atlas(stmid_serialised_data_atlas);
      result = kUsingNextToLastSession;
    } else if (result == kTryAgainLater) {
      return kTryAgainLater;
    }
  }

  if (stmid_da.empty()) {
    if (tmid_da.empty()) {
      LOG(kError) << "No valid DA.";
      return kSetIdentityPacketsFailure;
    } else if (!stmid_serialised_data_atlas.empty()) {
      stmid_da = stmid_serialised_data_atlas;
    }
  }

  result = passport_.SetIdentityPackets(keyword, pin, password, tmid_da, stmid_da);
  result += passport_.ConfirmIdentityPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failure to set and confirm identity packets.";
    return kSetIdentityPacketsFailure;
  }

  return result;
}

int UserCredentialsImpl::CreateUser(const std::string& keyword,
                                    const std::string& pin,
                                    const std::string& password) {
  std::unique_lock<std::mutex> loch_a_phuill(single_threaded_class_mutex_);

  int result(CheckKeywordValidity(keyword));
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid keyword: " << keyword << "    Return code: " << result << ")";
    return result;
  }
  result = CheckPinValidity(pin);
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid pin: " << pin << "    Return code: " << result << ")";
    return result;
  }
  result = CheckPasswordValidity(password);
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid password: " << password << "    (Return code: " << result << ")";
    return result;
  }

  result = ProcessSigningPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed processing signature packets: " << result;
    return kSessionFailure;
  }

  result = ProcessIdentityPackets(keyword, pin, password);
  if (result != kSuccess) {
    LOG(kError) << "Failed processing identity packets: " << result;
    return kSessionFailure;
  }

  session_.set_keyword(keyword);
  session_.set_pin(pin);
  session_.set_password(password);
  session_.set_session_access_level(kFullAccess);
  if (!session_.set_session_name()) {
    LOG(kError) << "Failed to set session.";
    return kSessionFailure;
  }
  session_.set_changed(true);

//  LockingPacket locking_packet(lid::CreateLockingPacket(session_.session_name()));
//  result = StoreLid(keyword, pin, password, locking_packet);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to create LID.";
//    return result;
//  }

//  StartSessionSaver();

  return kSuccess;
}

int UserCredentialsImpl::ProcessSigningPackets() {
  int result(passport_.CreateSigningPackets());
  if (result != kSuccess) {
    LOG(kError) << "Failed creating signature packets: " << result;
    return kSessionFailure;
  }

  result = StoreAnonymousPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failure to Store Anonymous packets: " << result;
    return result;
  }

  result = passport_.ConfirmSigningPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed confirming signature packets: " << result;
    return kSessionFailure;
  }

  return kSuccess;
}

int UserCredentialsImpl::StoreAnonymousPackets() {
  std::vector<int> individual_results(4, priv::utilities::kPendingResult);
  std::condition_variable condition_variable;
  std::mutex mutex;
  OperationResults results(mutex, condition_variable, individual_results);

  // ANMID path
  StoreAnmid(results);
  // ANSMID path
  StoreAnsmid(results);
  // ANTMID path
  StoreAntmid(results);
  // PMID path: ANMAID, MAID, PMID
  StoreAnmaid(results);

  int result(utils::WaitForResults(mutex, condition_variable, individual_results,
                                   std::chrono::seconds(30)));
  if (result != kSuccess) {
    LOG(kError) << "Wait for results timed out: " << result;
    LOG(kError) << "ANMID: " << individual_results.at(0)
              << ", ANSMID: " << individual_results.at(1)
              << ", ANTMID: " << individual_results.at(2)
              << ", PMID path: " << individual_results.at(3);
    return result;
  }
  LOG(kInfo) << "ANMID: " << individual_results.at(0)
             << ", ANSMID: " << individual_results.at(1)
             << ", ANTMID: " << individual_results.at(2)
             << ", PMID path: " << individual_results.at(3);

  result = AssessJointResult(individual_results);
  if (result != kSuccess) {
    LOG(kError) << "One of the operations for Anonymous Packets failed. "
                << "Turn on INFO for feedback on which one. ";
    return kCreateSignaturePacketsFailure;
  }

  return kSuccess;
}

void UserCredentialsImpl::StoreAnmid(OperationResults& results) {
  std::shared_ptr<asymm::Keys> anmid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kAnmid, false)));
  StoreSignaturePacket(anmid, results, 0);
}

void UserCredentialsImpl::StoreAnsmid(OperationResults& results) {
  std::shared_ptr<asymm::Keys> ansmid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kAnsmid, false)));
  StoreSignaturePacket(ansmid, results, 1);
}

void UserCredentialsImpl::StoreAntmid(OperationResults& results) {
  std::shared_ptr<asymm::Keys> antmid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kAntmid, false)));
  StoreSignaturePacket(antmid, results, 2);
}

void UserCredentialsImpl::StoreSignaturePacket(std::shared_ptr<asymm::Keys> packet,
                                               OperationResults& results,
                                               int index) {
  std::string packet_name, packet_content;

  CreateSignaturePacketInfo(packet, &packet_name, &packet_content);
  if (!remote_chunk_store_.Store(packet_name,
                                 packet_content,
                                 [&, index] (bool result) {
                                   OperationCallback(result, results, index);
                                 },
                                 packet)) {
    LOG(kError) << "Failed to store: " << index;
    OperationCallback(false, results, index);
  }
}

void UserCredentialsImpl::StoreAnmaid(OperationResults& results) {
  std::shared_ptr<asymm::Keys> anmaid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kAnmaid, false)));
  std::string packet_name, packet_content;

  CreateSignaturePacketInfo(anmaid, &packet_name, &packet_content);
  if (!remote_chunk_store_.Store(packet_name,
                                 packet_content,
                                 [&] (bool result) { StoreMaid(result, results); },
                                 anmaid)) {
    LOG(kError) << "Failed to store ANMAID.";
    StoreMaid(false, results);
  }
}

void UserCredentialsImpl::StoreMaid(bool result, OperationResults& results) {
  if (!result) {
    LOG(kError) << "Anmaid failed to store.";
    OperationCallback(false, results, 3);
    return;
  }

  std::shared_ptr<asymm::Keys> maid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kMaid, false)));
  std::shared_ptr<asymm::Keys> anmaid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kAnmaid, false)));

  std::string maid_name(pca::ApplyTypeToName(maid->identity, pca::kSignaturePacket));
  pca::SignedData signed_maid;
  signed_maid.set_signature(maid->validation_token);
  std::string maid_string_public_key;
  asymm::EncodePublicKey(maid->public_key, &maid_string_public_key);
  if (maid_string_public_key.empty()) {
    LOG(kError) << "Failed to procure sign MAID's public key.";
    StorePmid(false, results);
    return;
  }
  signed_maid.set_data(maid_string_public_key);
  if (!remote_chunk_store_.Store(maid_name,
                                 signed_maid.SerializeAsString(),
                                 [&] (bool result) { StorePmid(result, results); },
                                 anmaid)) {
    LOG(kError) << "Failed to store MAID.";
    StorePmid(false, results);
  }
}

void UserCredentialsImpl::StorePmid(bool result, OperationResults& results) {
  if (!result) {
    LOG(kError) << "Maid failed to store.";
    OperationCallback(false, results, 3);
    return;
  }

  std::shared_ptr<asymm::Keys> pmid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kPmid, false)));
  std::shared_ptr<asymm::Keys> maid(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kMaid, false)));

  std::string pmid_name(pca::ApplyTypeToName(pmid->identity, pca::kSignaturePacket));
  pca::SignedData signed_pmid;
  signed_pmid.set_signature(pmid->validation_token);
  std::string pmid_string_public_key;
  asymm::EncodePublicKey(pmid->public_key, &pmid_string_public_key);
  if (pmid_string_public_key.empty()) {
    LOG(kError) << "Failed to procure sign PMID's public key.";
    StorePmid(false, results);
    return;
  }
  signed_pmid.set_data(pmid_string_public_key);

  if (!remote_chunk_store_.Store(pmid_name,
                                 signed_pmid.SerializeAsString(),
                                 [&] (bool result) {
                                   OperationCallback(result, results, 3);
                                 },
                                 maid)) {
    LOG(kError) << "Failed to store PMID.";
    OperationCallback(false, results, 3);
  }
}

int UserCredentialsImpl::ProcessIdentityPackets(const std::string& keyword,
                                                const std::string& pin,
                                                const std::string& password) {
  std::string serialised_data_atlas, surrogate_serialised_data_atlas;
  int result(session_.SerialiseDataAtlas(&serialised_data_atlas));
  Sleep(bptime::milliseconds(1));  // Need different timestamps
  result += session_.SerialiseDataAtlas(&surrogate_serialised_data_atlas);
  if (result != kSuccess ||
      serialised_data_atlas.empty() ||
      surrogate_serialised_data_atlas.empty()) {
    LOG(kError) << "Don't have the appropriate elements to save on ID packets.";
    return kSessionSerialisationFailure;
  }

  result = passport_.SetIdentityPackets(keyword,
                                        pin,
                                        password,
                                        serialised_data_atlas,
                                        surrogate_serialised_data_atlas);
  if (result!= kSuccess) {
    LOG(kError) << "Creation of ID packets failed.";
    return kSessionSerialisationFailure;
  }

  result = StoreIdentityPackets();
  if (result!= kSuccess) {
    LOG(kError) << "Storing of ID packets failed.";
    return result;
  }

  result = passport_.ConfirmIdentityPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed confirming identity packets: " << result;
    return kSessionFailure;
  }

  session_.set_serialised_data_atlas(serialised_data_atlas);

  return kSuccess;
}

int UserCredentialsImpl::StoreIdentityPackets() {
  std::vector<int> individual_results(4, priv::utilities::kPendingResult);
  std::condition_variable condition_variable;
  std::mutex mutex;
  OperationResults results(mutex, condition_variable, individual_results);

  // MID path
  StoreMid(results);
  // SMID path
  StoreSmid(results);
  // TMID path
  StoreTmid(results);
  // STMID
  StoreStmid(results);

  int result(utils::WaitForResults(mutex, condition_variable, individual_results,
                                   std::chrono::seconds(60)));
  if (result != kSuccess) {
    LOG(kError) << "Wait for results timed out.";
    return result;
  }
  LOG(kInfo) << "MID: " << individual_results.at(0)
             << ", SMID: " << individual_results.at(1)
             << ", TMID: " << individual_results.at(2)
             << ", STMID: " << individual_results.at(3);

  result = AssessJointResult(individual_results);
  if (result != kSuccess) {
    LOG(kError) << "One of the operations for Identity Packets failed. "
                << "Turn on INFO for feedback on which one. ";
    return kStoreIdentityPacketsFailure;
  }

  return kSuccess;
}

void UserCredentialsImpl::StoreMid(OperationResults& results) {
  StoreIdentity(results, passport::kMid, passport::kAnmid, 0);
}

void UserCredentialsImpl::StoreSmid(OperationResults& results) {
  StoreIdentity(results, passport::kSmid, passport::kAnsmid, 1);
}

void UserCredentialsImpl::StoreTmid(OperationResults& results) {
  StoreIdentity(results, passport::kTmid, passport::kAntmid, 2);
}

void UserCredentialsImpl::StoreStmid(OperationResults& results) {
  StoreIdentity(results, passport::kStmid, passport::kAntmid, 3);
}

void UserCredentialsImpl::StoreIdentity(OperationResults& results,
                                        int identity_type,
                                        int signer_type,
                                        int index) {
  passport::PacketType id_pt(static_cast<passport::PacketType>(identity_type));
  passport::PacketType sign_pt(static_cast<passport::PacketType>(signer_type));
  std::string packet_name(passport_.IdentityPacketName(id_pt, false)),
              packet_content(passport_.IdentityPacketValue(id_pt, false));
  packet_name = pca::ApplyTypeToName(packet_name, pca::kModifiableByOwner);
  std::shared_ptr<asymm::Keys> signer(new asymm::Keys(
      passport_.SignaturePacketDetails(sign_pt, true)));

  asymm::Signature signature;
  int result(asymm::Sign(packet_content, signer->private_key, &signature));
  if (result != kSuccess) {
    LOG(kError) << "Failed to sign content: " << result;
    OperationCallback(false, results, index);
    return;
  }

  pca::SignedData signed_data;
  signed_data.set_data(packet_content);
  signed_data.set_signature(signature);
  if (!remote_chunk_store_.Store(packet_name,
                                 signed_data.SerializeAsString(),
                                 [&, index] (bool result) {
                                   OperationCallback(result, results, index);
                                 },
                                 signer)) {
    LOG(kError) << "Failed to store: " << index;
    OperationCallback(false, results, index);
  }
}

int UserCredentialsImpl::StoreLid(const std::string keyword,
                                  const std::string pin,
                                  const std::string password,
                                  const LockingPacket& locking_packet) {
  std::string packet_name(pca::ApplyTypeToName(lid::LidName(keyword, pin),
                                               pca::kModifiableByOwner));
  std::string account_status(locking_packet.SerializeAsString());
  std::string encrypted_account_status(lid::EncryptAccountStatus(keyword, pin, password,
                                                                 account_status));

  std::shared_ptr<asymm::Keys> signer(new asymm::Keys(
      passport_.SignaturePacketDetails(passport::kAnmid, true)));
  asymm::Signature signature;
  int result(asymm::Sign(encrypted_account_status, signer->private_key, &signature));
  if (result != kSuccess) {
    LOG(kError) << "Failed to sign content: " << result;
    return result;
  }

  pca::SignedData signed_data;
  signed_data.set_data(encrypted_account_status);
  signed_data.set_signature(signature);

  std::vector<int> individual_result(1, priv::utilities::kPendingResult);
  std::condition_variable condition_variable;
  std::mutex mutex;
  OperationResults operation_result(mutex, condition_variable, individual_result);
  if (!remote_chunk_store_.Store(packet_name,
                                 signed_data.SerializeAsString(),
                                 [&] (bool result) {
                                   OperationCallback(result, operation_result, 0);
                                 },
                                 signer)) {
    LOG(kError) << "Failed to store LID.";
    OperationCallback(false, operation_result, 0);
  }
  result = utils::WaitForResults(mutex, condition_variable, individual_result,
                                 std::chrono::seconds(60));
  if (result != kSuccess) {
    LOG(kError) << "Failed to store LID:" << result;
    return result;
  }
  return individual_result.at(0);
}

int UserCredentialsImpl::SaveSession(bool log_out) {
  std::unique_lock<std::mutex> loch_a_phuill(single_threaded_class_mutex_);

  if (log_out) {
    session_saver_timer_active_ = false;
    session_saver_timer_.cancel();

    if (!session_.changed() && session_saved_once_) {
      LOG(kError) << "Session has not changed.";
      return kSuccess;
    }
  } else if (!session_.changed()) {
    LOG(kError) << "Session has not changed.";
    return kSuccess;
  }

  std::string serialised_data_atlas;
  int result(SerialiseAndSetIdentity("", "", "", &serialised_data_atlas));
  if (result != kSuccess) {
    LOG(kError) << "Failure setting details of new session: " << result;
    return result;
  }

  std::vector<int> individual_results(4, priv::utilities::kPendingResult);
  std::condition_variable condition_variable;
  std::mutex mutex;
  OperationResults results(mutex, condition_variable, individual_results);

  ModifyMid(results);
  ModifySmid(results);
  StoreTmid(results);
  DeleteStmid(results);

  result = utils::WaitForResults(mutex, condition_variable, individual_results,
                                 std::chrono::seconds(30));
  if (result != kSuccess) {
    LOG(kError) << "Failed to store new identity packets: Time out.";
    return kSaveSessionFailure;
  }

  LOG(kInfo) << "MID: " << individual_results.at(0)
             << ", SMID: " << individual_results.at(1)
             << ", TMID: " << individual_results.at(2)
             << ", STMID: " << individual_results.at(3);

  result = AssessJointResult(individual_results);
  if (result != kSuccess) {
    LOG(kError) << "One of the operations for Identity Packets failed. "
                << "Turn on INFO for feedback on which one. ";
    return kSaveSessionFailure;
  }

  session_.set_serialised_data_atlas(serialised_data_atlas);
  session_.set_changed(false);
  session_saved_once_ = true;

  LOG(kSuccess) << "Success in SaveSession.";
  return kSuccess;
}

int UserCredentialsImpl::AssessAndUpdateLid(bool log_out) {
  std::string lid_packet;
  LockingPacket locking_packet;
  int result(GetAndLockLid(session_.keyword(),
                           session_.pin(),
                           session_.password(),
                           lid_packet,
                           locking_packet));
  if (result != kSuccess) {
    LOG(kError) << "Failed to get and lock LID.";
    return result;
  }

  if (log_out) {
    result = lid::RemoveItemFromLockingPacket(locking_packet, session_.session_name());
    if (result != kSuccess) {
      LOG(kError) << "Failed to remove item from locking packet.";
      return result;
    }
  } else {
    int index(0);
    while (index < locking_packet.locking_item_size()) {
      if (locking_packet.locking_item(index).identifier() == session_.session_name())
        break;
      else
        ++index;
    }
    if (session_.session_access_level() == kFullAccess) {
      if (!locking_packet.locking_item(index).full_access()) {
        LOG(kInfo) << "Quit - full access in LID has been changed to false!";
        immediate_quit_required_signal_();
        session_saver_timer_active_ = false;
        session_saver_timer_.cancel();
        session_.set_changed(false);
        session_saved_once_ = true;
        session_.set_session_access_level(kMustDie);
        return kMustDieFailure;
      }
    }
    if (session_.session_access_level() == kReadOnly) {
      if (locking_packet.locking_item(index).full_access()) {
        LOG(kError) << "This should never happen!" <<
                       " session_.state() indicates read only but LID indicates full access!";
        return kGeneralError;
      }
    }

    bptime::ptime current_time = bptime::microsec_clock::universal_time();
    bptime::ptime entry_time;
    bptime::time_duration time_difference;
    LockingItem locking_item;
    std::vector<std::string> identifiers_to_remove;
    for (int i = 0; i < locking_packet.locking_item_size(); ++i) {
      locking_item = locking_packet.locking_item(i);
      if (locking_item.identifier() != session_.session_name()) {
        entry_time = bptime::from_iso_string(locking_item.timestamp());
        if (entry_time > current_time) {
          LOG(kError) << "Entry from LID is more recent than current time!";
        } else {
          time_difference = current_time - entry_time;
          // LOG(kInfo) << "This entry's age is " << time_difference.hours() << " hour(s) and " <<
          // time_difference.minutes() << " mins.";
          if (session_.session_access_level() == kReadOnly &&
              (time_difference.hours() >= 1 || time_difference.minutes() >= 5) &&
              locking_item.full_access()) {
            LOG(kInfo) << "Found outdated full access item - can take full access!";
            // TODO(Alison) - get full access:
            //              - unmount/remount drive; change state; notify GUI?
            //              - change own access level in LID
          }
          if (time_difference.hours() >= 12) {
            // LOG(kInfo) << "This entry is TOO OLD and we should get rid of it";
            identifiers_to_remove.push_back(locking_item.identifier());
          }
        }
      } else {
        LOG(kInfo) << "Found own entry";
      }
    }

    // Clear out old entries
    if (!identifiers_to_remove.empty()) {
      result = lid::RemoveItemsFromLockingPacket(locking_packet, identifiers_to_remove);
      if (result != kSuccess) {
        LOG(kInfo) << "Failed to remove some items.";
      }
    }

    // Update timestamp of own entry
    result = lid::UpdateTimestampInLockingPacket(locking_packet, session_.session_name());
    if (result != kSuccess) {
      LOG(kError) << "Failed to update timestamp locking packet.";
      return result;
    }
  }

  result = ModifyLid(session_.keyword(), session_.pin(), session_.password(), locking_packet);
  if (result != kSuccess) {
    LOG(kError) << "Failed to modify LID.";
    return result;
  }
  return kSuccess;
}

void UserCredentialsImpl::ModifyMid(OperationResults& results) {
  ModifyIdentity(results, passport::kMid, passport::kAnmid, 0);
}

void UserCredentialsImpl::ModifySmid(OperationResults& results) {
  ModifyIdentity(results, passport::kSmid, passport::kAnsmid, 1);
}

void UserCredentialsImpl::ModifyIdentity(OperationResults& results,
                                         int identity_type,
                                         int signer_type,
                                         int index) {
  passport::PacketType id_pt(static_cast<passport::PacketType>(identity_type));
  passport::PacketType sign_pt(static_cast<passport::PacketType>(signer_type));
  std::string name(passport_.IdentityPacketName(id_pt, false)),
              content(passport_.IdentityPacketValue(id_pt, false));
  name = pca::ApplyTypeToName(name, pca::kModifiableByOwner);
  std::shared_ptr<asymm::Keys> signer(new asymm::Keys(passport_.SignaturePacketDetails(sign_pt,
                                                                                       true)));

  asymm::Signature signature;
  int result(asymm::Sign(content, signer->private_key, &signature));
  if (result != kSuccess) {
    LOG(kError) << "Failed to sign content: " << result;
    OperationCallback(false, results, index);
    return;
  }

  pca::SignedData signed_data;
  signed_data.set_data(content);
  signed_data.set_signature(signature);
  if (!remote_chunk_store_.Modify(name,
                                  signed_data.SerializeAsString(),
                                  [&, index] (bool result) {
                                    OperationCallback(result, results, index);
                                  },
                                  signer)) {
    LOG(kError) << "Failed to modify: " << index;
    OperationCallback(false, results, index);
  }
}

int UserCredentialsImpl::ModifyLid(const std::string keyword,
                                   const std::string pin,
                                   const std::string password,
                                   const LockingPacket& locking_packet) {
  std::string packet_name(lid::LidName(keyword, pin));
  packet_name = pca::ApplyTypeToName(packet_name, pca::kModifiableByOwner);

  std::string account_status(locking_packet.SerializeAsString());
  std::string encrypted_account_status(lid::EncryptAccountStatus(keyword, pin, password,
                                                                 account_status));

  std::shared_ptr<asymm::Keys> signer(
      new asymm::Keys(passport_.SignaturePacketDetails(passport::kAnmid, true)));
  asymm::Signature signature;
  int result(asymm::Sign(encrypted_account_status, signer->private_key, &signature));
  if (result != kSuccess) {
    LOG(kError) << "Failed to sign content: " << result;
    return result;
  }

  pca::SignedData signed_data;
  signed_data.set_data(encrypted_account_status);
  signed_data.set_signature(signature);

  std::vector<int> individual_result(1, priv::utilities::kPendingResult);
  std::condition_variable condition_variable;
  std::mutex mutex;
  OperationResults operation_result(mutex, condition_variable, individual_result);
  if (!remote_chunk_store_.Modify(packet_name,
                                  signed_data.SerializeAsString(),
                                  [&] (bool result) {
                                    OperationCallback(result, operation_result, 0);
                                  },
                                  signer)) {
    LOG(kError) << "Failed to modify LID.";
    OperationCallback(false, operation_result, 0);
  }
  result = utils::WaitForResults(mutex, condition_variable, individual_result,
                                 std::chrono::seconds(30));
  if (result != kSuccess) {
    LOG(kError) << "Failed to modify LID:" << result;
    return result;
  }
  return individual_result.at(0);
}

int UserCredentialsImpl::ChangePin(const std::string& new_pin) {
  std::unique_lock<std::mutex> loch_a_phuill(single_threaded_class_mutex_);

  int result(CheckPinValidity(new_pin));
  if (result != kSuccess) {
    LOG(kError) << "Incorrect input.";
    return result;
  }

  std::string keyword(session_.keyword());
  return ChangeKeywordPin(keyword, new_pin);
}

int UserCredentialsImpl::ChangeKeyword(const std::string new_keyword) {
  std::unique_lock<std::mutex> loch_a_phuill(single_threaded_class_mutex_);

  int result(CheckKeywordValidity(new_keyword));
  if (result != kSuccess) {
    LOG(kError) << "Incorrect input.";
    return result;
  }

  std::string pin(session_.pin());
  return ChangeKeywordPin(new_keyword, pin);
}

int UserCredentialsImpl::ChangeKeywordPin(const std::string& new_keyword,
                                           const std::string& new_pin) {
  BOOST_ASSERT(!new_keyword.empty());
  BOOST_ASSERT(!new_pin.empty());
  // TODO(Alison) - check LID and fail if any other instances are logged in

  std::string serialised_data_atlas;
  int result(SerialiseAndSetIdentity(new_keyword, new_pin, "", &serialised_data_atlas));
  if (result != kSuccess) {
    LOG(kError) << "Failure setting details of new session: " << result;
    return result;
  }

  result = StoreIdentityPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed to store new identity packets: " << result;
    return result;
  }

  result = StoreLid(new_keyword,
                    new_pin,
                    session_.password(),
                    lid::CreateLockingPacket(session_.session_name()));
  if (result != kSuccess) {
    LOG(kError) << "Failed to store new LID.";
    return result;
  }

  result = DeleteOldIdentityPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed to delete old identity packets: " << result;
    return result;
  }

  result = DeleteLid(session_.keyword(), session_.pin());
  if (result != kSuccess) {
    LOG(kError) << "Failed to delete old LID.";
    return result;
  }

  result = passport_.ConfirmIdentityPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed to set new identity packets: " << result;
    return kSetIdentityPacketsFailure;
  }

  session_.set_keyword(new_keyword);
  session_.set_pin(new_pin);
  session_.set_serialised_data_atlas(serialised_data_atlas);
  session_.set_changed(false);

  return kSuccess;
}

int UserCredentialsImpl::DeleteOldIdentityPackets() {
  std::vector<int> individual_results(4, priv::utilities::kPendingResult);
  std::condition_variable condition_variable;
  std::mutex mutex;
  OperationResults results(mutex, condition_variable, individual_results);

  DeleteMid(results);
  DeleteSmid(results);
  DeleteTmid(results);
  DeleteStmid(results);

  int result(utils::WaitForResults(mutex, condition_variable, individual_results,
                                   std::chrono::seconds(30)));
  if (result != kSuccess) {
    LOG(kError) << "Wait for results timed out.";
    return result;
  }
  LOG(kInfo) << "MID: " << individual_results.at(0)
             << ", SMID: " << individual_results.at(1)
             << ", TMID: " << individual_results.at(2)
             << ", STMID: " << individual_results.at(3);

  result = AssessJointResult(individual_results);
  if (result != kSuccess) {
    LOG(kError) << "One of the operations for Identity Packets failed. "
                << "Turn on INFO for feedback on which one. ";
    return kDeleteIdentityPacketsFailure;
  }

  return kSuccess;
}

void UserCredentialsImpl::DeleteMid(OperationResults& results) {
  DeleteIdentity(results, passport::kMid, passport::kAnmid, 0);
}

void UserCredentialsImpl::DeleteSmid(OperationResults& results) {
  DeleteIdentity(results, passport::kSmid, passport::kAnsmid, 1);
}

void UserCredentialsImpl::DeleteTmid(OperationResults& results) {
  DeleteIdentity(results, passport::kTmid, passport::kAntmid, 2);
}

void UserCredentialsImpl::DeleteStmid(OperationResults& results) {
  DeleteIdentity(results, passport::kStmid, passport::kAntmid, 3);
}

void UserCredentialsImpl::DeleteIdentity(OperationResults& results,
                                         int packet_type,
                                         int signer_type,
                                         int index) {
  passport::PacketType id_type(static_cast<passport::PacketType>(packet_type));
  passport::PacketType sig_type(static_cast<passport::PacketType>(signer_type));
  std::string name(passport_.IdentityPacketName(id_type, true));
  if (name.empty()) {
    LOG(kError) << "Failed to get packet name: " << index;
    OperationCallback(false, results, index);
    return;
  }
  name = pca::ApplyTypeToName(name, pca::kModifiableByOwner);

  std::shared_ptr<asymm::Keys> signer(new asymm::Keys(passport_.SignaturePacketDetails(sig_type,
                                                                                       true)));
  if (!remote_chunk_store_.Delete(name,
                                  [&, index] (bool result) {
                                    OperationCallback(result, results, index);
                                  },
                                  signer)) {
    LOG(kError) << "Failed to delete: " << index;
    OperationCallback(false, results, index);
  }
}

int UserCredentialsImpl::DeleteLid(const std::string& keyword,
                                   const std::string& pin) {
  std::string packet_name(pca::ApplyTypeToName(lid::LidName(keyword, pin),
                                               pca::kModifiableByOwner));
  // TODO(Alison) - check LID and fail if any other instances are logged in
  std::shared_ptr<asymm::Keys> signer(new asymm::Keys(
                                          passport_.SignaturePacketDetails(passport::kAnmid,
                                                                           true)));
  std::vector<int> individual_result(1, priv::utilities::kPendingResult);
  std::condition_variable condition_variable;
  std::mutex mutex;
  OperationResults operation_result(mutex, condition_variable, individual_result);
  if (!remote_chunk_store_.Delete(packet_name,
                                  [&] (bool result) {
                                    OperationCallback(result, operation_result, 0);
                                  },
                                  signer)) {
    LOG(kError) << "Failed to delete LID.";
    OperationCallback(false, operation_result, 0);
  }
  int result = utils::WaitForResults(mutex, condition_variable, individual_result,
                                     std::chrono::seconds(30));
  if (result != kSuccess) {
    LOG(kError) << "Storing new LID timed out.";
    return result;
  }
  return individual_result.at(0);
}

int UserCredentialsImpl::ChangePassword(const std::string& new_password) {
  std::unique_lock<std::mutex> loch_a_phuill(single_threaded_class_mutex_);

  int result(CheckPasswordValidity(new_password));
  if (result != kSuccess) {
    LOG(kError) << "Incorrect input.";
    return result;
  }

  // TODO(Alison) - check LID and fail if any other instances are logged in

  std::string serialised_data_atlas;
  result = SerialiseAndSetIdentity("", "", new_password, &serialised_data_atlas);
  if (result != kSuccess) {
    LOG(kError) << "Failure setting details of new session: " << result;
    return result;
  }

  result = DoChangePasswordAdditions();
  if (result != kSuccess) {
    LOG(kError) << "Failed to perform additions.";
    return result;
  }

  result = DoChangePasswordRemovals();
  if (result != kSuccess) {
    LOG(kError) << "Failed to perform removals.";
    return result;
  }

  result = passport_.ConfirmIdentityPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed to set new identity packets: " << result;
    return kSetIdentityPacketsFailure;
  }

  std::string lid_packet;
  LockingPacket locking_packet;
  result = GetAndLockLid(session_.keyword(),
                         session_.pin(),
                         session_.password(),
                         lid_packet,
                         locking_packet);
  if (result != kSuccess) {
    LOG(kError) << "Failed to lock LID.";
    return result;
  }
  result = ModifyLid(session_.keyword(), session_.pin(), new_password, locking_packet);
  if (result != kSuccess) {
    LOG(kError) << "Failed to modify LID.";
    return result;
  }

  session_.set_password(new_password);
  session_.set_serialised_data_atlas(serialised_data_atlas);
  session_.set_changed(false);

  return kSuccess;
}

int UserCredentialsImpl::DoChangePasswordAdditions() {
  std::vector<int> individual_results(4, priv::utilities::kPendingResult);
  std::condition_variable condition_variable;
  std::mutex mutex;
  OperationResults new_results(mutex, condition_variable, individual_results);

  ModifyMid(new_results);
  ModifySmid(new_results);
  StoreTmid(new_results);
  StoreStmid(new_results);

  int result(utils::WaitForResults(mutex, condition_variable, individual_results,
                                   std::chrono::seconds(30)));
  if (result != kSuccess) {
    LOG(kError) << "Failed to store new identity packets: Time out.";
    return kChangePasswordFailure;
  }

  LOG(kInfo) << "MID: " << individual_results.at(0)
             << ", SMID: " << individual_results.at(1)
             << ", TMID: " << individual_results.at(2)
             << ", STMID: " << individual_results.at(3);

  result = AssessJointResult(individual_results);
  if (result != kSuccess) {
    LOG(kError) << "One of the operations for Identity Packets failed. "
                << "Turn on INFO for feedback on which one. ";
    return kChangePasswordFailure;
  }

  return kSuccess;
}

int UserCredentialsImpl::DoChangePasswordRemovals() {
  // Delete old TMID, STMID
  std::vector<int> individual_results(4, kSuccess);

  std::condition_variable condition_variable;
  std::mutex mutex;
  individual_results[2] = priv::utilities::kPendingResult;
  individual_results[3] = priv::utilities::kPendingResult;
  OperationResults del_results(mutex, condition_variable, individual_results);
  DeleteTmid(del_results);
  DeleteStmid(del_results);

  int result(utils::WaitForResults(mutex, condition_variable, individual_results,
                                   std::chrono::seconds(30)));
  if (result != kSuccess) {
    LOG(kError) << "Failed to store new identity packets: Time out.";
    return kChangePasswordFailure;
  }

  LOG(kInfo) << "TMID: " << individual_results.at(2)
             << ", STMID: " << individual_results.at(3);

  result = AssessJointResult(individual_results);
  if (result != kSuccess) {
    LOG(kError) << "One of the operations for Identity Packets failed. "
                << "Turn on INFO for feedback on which one. ";
    return kChangePasswordFailure;
  }

  return kSuccess;
}

int UserCredentialsImpl::SerialiseAndSetIdentity(const std::string& keyword,
                                                 const std::string& pin,
                                                 const std::string& password,
                                                 std::string* serialised_data_atlas) {
  BOOST_ASSERT(serialised_data_atlas);
  int result(session_.SerialiseDataAtlas(serialised_data_atlas));
  if (result != kSuccess || serialised_data_atlas->empty()) {
    LOG(kError) << "Failed to serialise session: " << result;
    return kSessionSerialisationFailure;
  }

  result = passport_.SetIdentityPackets(keyword.empty()? session_.keyword() : keyword,
                                        pin. empty() ? session_.pin() : pin,
                                        password.empty() ? session_.password() : password,
                                        *serialised_data_atlas,
                                        session_.serialised_data_atlas());

  if (result != kSuccess) {
    LOG(kError) << "Failed to set new identity packets: " << result;
    return kSetIdentityPacketsFailure;
  }

  return kSuccess;
}

int UserCredentialsImpl::DeleteUserCredentials() {
  std::string lid_packet;
  LockingPacket locking_packet;
  int lid_result(GetAndLockLid(session_.keyword(),
                               session_.pin(),
                               session_.password(),
                               lid_packet,
                               locking_packet));
  if (lid_result != kSuccess) {
    LOG(kError) << "Failed to GetAndLock LID.";
    return lid_result;
  }

  int result(lid::CheckLockingPacketForOthersLoggedIn(locking_packet, session_.session_name()));
  if (result != kSuccess) {
    LOG(kError) << "Can't delete locking packet because of LID contents: " << result;
    return result;
  }

  result = DeleteOldIdentityPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed to delete identity packets.";
    return result;
  }

  result = DeleteLid(session_.keyword(), session_.pin());
  if (result != kSuccess) {
    LOG(kError) << "Failed to delete LID.";
    return result;
  }

  result = DeleteSignaturePackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed to delete signature packets.";
    return result;
  }

  return kSuccess;
}

int UserCredentialsImpl::DeleteSignaturePackets() {
  std::vector<int> individual_results(4, priv::utilities::kPendingResult);
  std::condition_variable condition_variable;
  std::mutex mutex;
  OperationResults results(mutex, condition_variable, individual_results);

  // ANMID path
  DeleteAnmid(results);
  // ANSMID path
  DeleteAnsmid(results);
  // ANTMID path
  DeleteAntmid(results);
  // PMID path: PMID, MAID, ANMAID
  DeletePmid(results);

  int result(utils::WaitForResults(mutex, condition_variable, individual_results,
                                   std::chrono::seconds(30)));
  if (result != kSuccess) {
    LOG(kError) << "Wait for results timed out: " << result;
    LOG(kError) << "ANMID: " << individual_results.at(0)
              << ", ANSMID: " << individual_results.at(1)
              << ", ANTMID: " << individual_results.at(2)
              << ", PMID path: " << individual_results.at(3);
    return result;
  }
  LOG(kInfo) << "ANMID: " << individual_results.at(0)
             << ", ANSMID: " << individual_results.at(1)
             << ", ANTMID: " << individual_results.at(2)
             << ", PMID path: " << individual_results.at(3);

  result = AssessJointResult(individual_results);
  if (result != kSuccess) {
    LOG(kError) << "One of the operations for Anonymous Packets failed. "
                << "Turn on INFO for feedback on which one. ";
    return kDeleteSignaturePacketsFailure;
  }

  return kSuccess;
}

void UserCredentialsImpl::DeleteAnmid(OperationResults& results) {
  std::shared_ptr<asymm::Keys> anmid(
      new asymm::Keys(passport_.SignaturePacketDetails(passport::kAnmid, true)));
  DeleteSignaturePacket(anmid, results, 0);
}

void UserCredentialsImpl::DeleteAnsmid(OperationResults& results) {
  std::shared_ptr<asymm::Keys> ansmid(
      new asymm::Keys(passport_.SignaturePacketDetails(passport::kAnsmid, true)));
  DeleteSignaturePacket(ansmid, results, 1);
}

void UserCredentialsImpl::DeleteAntmid(OperationResults& results) {
  std::shared_ptr<asymm::Keys> antmid(
      new asymm::Keys(passport_.SignaturePacketDetails(passport::kAntmid, true)));
  DeleteSignaturePacket(antmid, results, 2);
}

void UserCredentialsImpl::DeletePmid(OperationResults& results) {
  asymm::Keys pmid(passport_.SignaturePacketDetails(passport::kPmid, true));
  std::shared_ptr<asymm::Keys> maid(
      new asymm::Keys(passport_.SignaturePacketDetails(passport::kMaid, true)));

  std::string pmid_name(pca::ApplyTypeToName(pmid.identity, pca::kSignaturePacket));
  if (!remote_chunk_store_.Delete(pmid_name,
                                  [&] (bool result) { DeleteMaid(result, results, maid); },
                                  maid)) {
    LOG(kError) << "Failed to delete PMID.";
    DeleteMaid(false, results, nullptr);
  }
}

void UserCredentialsImpl::DeleteMaid(bool result,
                                     OperationResults& results,
                                     std::shared_ptr<asymm::Keys> maid) {
  if (!result) {
    LOG(kError) << "Failed to delete PMID.";
    OperationCallback(false, results, 3);
    return;
  }

  std::shared_ptr<asymm::Keys> anmaid(
      new asymm::Keys(passport_.SignaturePacketDetails(passport::kAnmaid, true)));
  std::string maid_name(pca::ApplyTypeToName(maid->identity, pca::kSignaturePacket));
  if (!remote_chunk_store_.Delete(maid_name,
                                  [&] (bool result) {
                                    DeleteAnmaid(result, results, anmaid);
                                  },
                                  anmaid)) {
    LOG(kError) << "Failed to delete MAID.";
    DeleteAnmaid(false, results, nullptr);
  }
}

void UserCredentialsImpl::DeleteAnmaid(bool result,
                                       OperationResults& results,
                                       std::shared_ptr<asymm::Keys> anmaid) {
  if (!result) {
    LOG(kError) << "Failed to delete MAID.";
    OperationCallback(false, results, 3);
    return;
  }

  DeleteSignaturePacket(anmaid, results, 3);
}

void UserCredentialsImpl::DeleteSignaturePacket(std::shared_ptr<asymm::Keys> packet,
                                                OperationResults& results,
                                                int index) {
  std::string packet_name(pca::ApplyTypeToName(packet->identity, pca::kSignaturePacket));
  if (!remote_chunk_store_.Delete(packet_name,
                                  [&, index] (bool result) {
                                    OperationCallback(result, results, index);
                                  },
                                  packet)) {
    LOG(kError) << "Failed to delete packet: " << index;
    OperationCallback(false, results, index);
  }
}

void UserCredentialsImpl::SessionSaver(const bptime::seconds& interval,
                                       const boost::system::error_code& error_code) {
  LOG(kVerbose) << "UserCredentialsImpl::SessionSaver!!! Wooohooooo";
  if (error_code) {
    if (error_code != boost::asio::error::operation_aborted) {
      LOG(kError) << "Refresh timer error: " << error_code.message();
    } else {
      return;
    }
  }

  if (!session_saver_timer_active_) {
    LOG(kInfo) << "Timer process cancelled.";
    return;
  }

//  bool lid_success(true);
//  int result(AssessAndUpdateLid(false));
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to update LID: " << result << " - won't SaveSession.";
//    lid_success = false;
//  } else {
    if (session_.session_access_level() == kFullAccess) {
      int result = SaveSession(false);
      LOG(kInfo) << "Session saver result: " << result;
    }
//  }

//  if (lid_success)
//    session_saver_timer_.expires_from_now(bptime::seconds(interval));
//  else
//    session_saver_timer_.expires_from_now(interval + bptime::seconds(5));
  session_saver_timer_.async_wait([=] (const boost::system::error_code& error_code) {
                                    this->SessionSaver(bptime::seconds(interval), error_code);
                                  });
}

bs2::connection UserCredentialsImpl::ConnectToImmediateQuitRequiredSignal(
    const ImmediateQuitRequiredFunction& immediate_quit_required_slot) {
  return immediate_quit_required_signal_.connect(immediate_quit_required_slot);
}

}  // namespace lifestuff

}  // namespace maidsafe
