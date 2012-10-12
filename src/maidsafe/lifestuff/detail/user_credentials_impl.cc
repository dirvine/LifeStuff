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
#include <utility>
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

#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/routings_handler.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"


namespace pca = maidsafe::priv::chunk_actions;
namespace bptime = boost::posix_time;
namespace utils = maidsafe::priv::utilities;

namespace maidsafe {

namespace lifestuff {

namespace {

int CreateSignaturePacketInfo(const asymm::Keys& packet,
                              std::string* packet_name,
                              std::string* packet_content) {
  assert(packet_name && packet_content);
  *packet_name = pca::ApplyTypeToName(packet.identity, pca::kSignaturePacket);

  pca::SignedData signed_data;
  std::string public_key;
  asymm::EncodePublicKey(packet.public_key, &public_key);
  if (public_key.empty()) {
    LOG(kError) << "Public key not properly encoded.";
    return kCreateSignaturePacketInfoFailure;
  }

  signed_data.set_data(public_key);
  signed_data.set_signature(packet.validation_token);
  if (!signed_data.SerializeToString(packet_content) || packet_content->empty()) {
    LOG(kError) << "SignedData not properly serialised.";
    return kCreateSignaturePacketInfoFailure;
  }

  return kSuccess;
}

void GenerateLogoutRequest(const std::string& session_marker, std::string& serialised_message) {
  assert(serialised_message.empty());
  LogoutProceedings proceedings;
  proceedings.set_session_requestor(session_marker);

  OtherInstanceMessage other_instance_message;
  other_instance_message.set_message_type(1);

  other_instance_message.set_serialised_message(proceedings.SerializeAsString());
  serialised_message = other_instance_message.SerializeAsString();
  assert(!serialised_message.empty());
}

}  // namespace

UserCredentialsImpl::UserCredentialsImpl(priv::chunk_store::RemoteChunkStore& remote_chunk_store,
                                         Session& session,
                                         boost::asio::io_service& service,
                                         RoutingsHandler& routings_handler)
    : remote_chunk_store_(&remote_chunk_store),
      session_(session),
      passport_(session_.passport()),
      routings_handler_(routings_handler),
      single_threaded_class_mutex_(),
      asio_service_(service),
      session_saver_timer_(asio_service_),
      session_saver_timer_active_(false),
      session_saved_once_(false),
      session_saver_interval_(kSecondsInterval * 3),
      completed_log_out_(false),
      completed_log_out_conditional_(),
      completed_log_out_mutex_(),
      completed_log_out_message_(),
      pending_session_marker_() {}

UserCredentialsImpl::~UserCredentialsImpl() {}

void UserCredentialsImpl::set_remote_chunk_store(priv::chunk_store::RemoteChunkStore& chunk_store) {
  remote_chunk_store_ = &chunk_store;
}


int UserCredentialsImpl::LogIn(const std::string& keyword,
                               const std::string& pin,
                               const std::string& password) {
  int result = AttemptLogInProcess(keyword, pin, password);
  if (result != kSuccess)
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

  std::string mid_packet, smid_packet;
  result = GetUserInfo(keyword, pin, password, false, mid_packet, smid_packet);
  if (result != kSuccess) {
    LOG(kInfo) << "UserCredentialsImpl::LogIn - failed to get user info.";
    return result;
  }

  // Check other running instances
  result = CheckForOtherRunningInstances(keyword, pin, password, mid_packet, smid_packet);
  if (result != kSuccess) {
    LOG(kInfo) << "UserCredentialsImpl::LogIn - Failure to deal with other running instances.";
    return result;
  }

  session_.set_keyword(keyword);
  session_.set_pin(pin);
  session_.set_password(password);
  session_.set_session_access_level(kFullAccess);
  if (!session_.set_session_name()) {
    LOG(kError) << "Failed to set session.";
    return kSessionFailure;
  }

  session_saved_once_ = false;
//  StartSessionSaver();

  return kSuccess;
}

int UserCredentialsImpl::CheckForOtherRunningInstances(const std::string& keyword,
                                                       const std::string& pin,
                                                       const std::string& password,
                                                       std::string& mid_packet,
                                                       std::string& smid_packet) {
  // Start MAID routing
  asymm::Keys maid(passport_.SignaturePacketDetails(passport::kMaid, true));
  assert(!maid.identity.empty());
  routings_handler_.AddRoutingObject(maid,
                                     std::vector<std::pair<std::string, uint16_t> >(),
                                     maid.identity,
                                     nullptr);

  // Message self and wait for response
  std::string request_logout, logout_request_acknowledgement;
  pending_session_marker_ = RandomString(64);
  GenerateLogoutRequest(pending_session_marker_, request_logout);
  bool successful_send(routings_handler_.Send(maid.identity,
                                              maid.identity,
                                              maid.public_key,
                                              request_logout,
                                              &logout_request_acknowledgement));
  if (!successful_send) {
    if (logout_request_acknowledgement.empty()) {
      LOG(kWarning) << "Timed out. Not necessarily a failure.";
    } else {
      LOG(kError) << "Sending failed.";
      return -1;
    }
  }

  // If other instances exist wait for log out message
  if (!logout_request_acknowledgement.empty()) {
    // Check logout_request_acknowledgement
    OtherInstanceMessage other_instance_message;
    if (!other_instance_message.ParseFromString(logout_request_acknowledgement) ||
        other_instance_message.message_type() != 1) {
      LOG(kError) << "Message response is not of the type expected.";
      return -1;
    }
    LogoutProceedings proceedings;
    if (!proceedings.ParseFromString(other_instance_message.serialised_message()) ||
        !proceedings.has_session_acknowledger()) {
      LOG(kError) << "Message has wrong format.";
      return -1;
    }

    if (proceedings.session_acknowledger() != pending_session_marker_) {
      LOG(kError) << "Session marker not replicated in acknowlegdement";
      return -1;
    }

    std::unique_lock<std::mutex> loch(completed_log_out_mutex_);
    if (!completed_log_out_conditional_.wait_for(loch,
                                                 std::chrono::minutes(1),
                                                 [&] () { return completed_log_out_; })) {
      LOG(kError) << "Timed out waiting for other party to report logout. "
                  << "Failure! Too dangerous to log in.";
      return kNoLogoutResponse;
    }

    // Check response is valid
    if (completed_log_out_message_ != pending_session_marker_) {
      LOG(kError) << "Session marker does not match marker sent in request.";
      return -1;
    }

    // Run GetUserInfo again
    int result(GetUserInfo(keyword, pin, password, true, mid_packet, smid_packet));
    if (result != kSuccess) {
      LOG(kInfo) << "UserCredentialsImpl::LogIn - Failed to get user info after remote logout.";
      return result;
    }
  }

  return kSuccess;
}

int UserCredentialsImpl::LogOut() {
  int result(SaveSession(true));
  if (result != kSuccess) {
    LOG(kError) << "Failed to save session on Logout with result " << result;
    return result;
  }

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
          new_mid_packet = remote_chunk_store_->Get(pca::ApplyTypeToName(passport::MidName(keyword,
                                                                                           pin,
                                                                                           false),
                                                                         pca::kModifiableByOwner));
        });
    boost::thread get_smid_thread(
        [&] {
          new_smid_packet = remote_chunk_store_->Get(pca::ApplyTypeToName(passport::MidName(keyword,
                                                                                            pin,
                                                                                            true),
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
    return kLoginUserNonExistence;
  }

  if (mid_tmid_result == kCorruptedPacket && smid_stmid_result == kCorruptedPacket) {
    LOG(kError) << "Account corrupted. Should never happen: "
                << keyword << ", " << pin;
    return kLoginAccountCorrupted;
  }

  int result(HandleSerialisedDataMaps(keyword, pin, password, tmid_packet, stmid_packet));
  if (result != kSuccess) {
    if (result == kTryAgainLater) {
      return kLoginSessionNotYetSaved;
    } else if (result == kUsingNextToLastSession) {
      return kLoginUsingNextToLastSession;
    } else {
      LOG(kError) << "Failed to initialise session: " << result;
      return kLoginAccountCorrupted;
    }
  }

  return kSuccess;
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
  std::string id_packet(remote_chunk_store_->Get(id_name));
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

  std::string temporary_id_packet(remote_chunk_store_->Get(decrypted_rid));
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

  int id_packets_result = passport_.SetIdentityPackets(keyword, pin, password, tmid_da, stmid_da);
  id_packets_result += passport_.ConfirmIdentityPackets();
  if (id_packets_result != kSuccess) {
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

  asymm::Keys maid(passport_.SignaturePacketDetails(passport::kMaid, true));
  assert(!maid.identity.empty());
  if (!routings_handler_.AddRoutingObject(maid,
                                          std::vector<std::pair<std::string, uint16_t> >(),
                                          maid.identity,
                                          nullptr)) {
    LOG(kError) << "Failure to start the routing object for the MAID.";
    return -1;
  }

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
  asymm::Keys anmid(passport_.SignaturePacketDetails(passport::kAnmid, false));
  assert(!anmid.identity.empty());
  StoreSignaturePacket(anmid, results, 0);
}

void UserCredentialsImpl::StoreAnsmid(OperationResults& results) {
  asymm::Keys ansmid(passport_.SignaturePacketDetails(passport::kAnsmid, false));
  assert(!ansmid.identity.empty());
  StoreSignaturePacket(ansmid, results, 1);
}

void UserCredentialsImpl::StoreAntmid(OperationResults& results) {
  asymm::Keys antmid(passport_.SignaturePacketDetails(passport::kAntmid, false));
  assert(!antmid.identity.empty());
  StoreSignaturePacket(antmid, results, 2);
}

void UserCredentialsImpl::StoreSignaturePacket(asymm::Keys packet,
                                               OperationResults& results,
                                               int index) {
  std::string packet_name, packet_content;

  CreateSignaturePacketInfo(packet, &packet_name, &packet_content);
  if (!remote_chunk_store_->Store(packet_name,
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
  asymm::Keys anmaid(passport_.SignaturePacketDetails(passport::kAnmaid, false));
  assert(!anmaid.identity.empty());
  std::string packet_name, packet_content;

  CreateSignaturePacketInfo(anmaid, &packet_name, &packet_content);
  if (!remote_chunk_store_->Store(packet_name,
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

  asymm::Keys maid(passport_.SignaturePacketDetails(passport::kMaid, false));
  assert(!maid.identity.empty());
  asymm::Keys anmaid(passport_.SignaturePacketDetails(passport::kAnmaid, false));
  assert(!anmaid.identity.empty());

  std::string maid_name(pca::ApplyTypeToName(maid.identity, pca::kSignaturePacket));
  pca::SignedData signed_maid;
  signed_maid.set_signature(maid.validation_token);
  std::string maid_string_public_key;
  asymm::EncodePublicKey(maid.public_key, &maid_string_public_key);
  if (maid_string_public_key.empty()) {
    LOG(kError) << "Failed to procure sign MAID's public key.";
    StorePmid(false, results);
    return;
  }
  signed_maid.set_data(maid_string_public_key);
  if (!remote_chunk_store_->Store(maid_name,
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

  asymm::Keys pmid(passport_.SignaturePacketDetails(passport::kPmid, false));
  assert(!pmid.identity.empty());
  asymm::Keys maid(passport_.SignaturePacketDetails(passport::kMaid, false));
  assert(!maid.identity.empty());

  std::string pmid_name(pca::ApplyTypeToName(pmid.identity, pca::kSignaturePacket));
  pca::SignedData signed_pmid;
  signed_pmid.set_signature(pmid.validation_token);
  std::string pmid_string_public_key;
  asymm::EncodePublicKey(pmid.public_key, &pmid_string_public_key);
  if (pmid_string_public_key.empty()) {
    LOG(kError) << "Failed to procure sign PMID's public key.";
    StorePmid(false, results);
    return;
  }
  signed_pmid.set_data(pmid_string_public_key);

  if (!remote_chunk_store_->Store(pmid_name,
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
  asymm::Keys signer(passport_.SignaturePacketDetails(sign_pt, true));
  assert(!signer.identity.empty());

  asymm::Signature signature;
  int result(asymm::Sign(packet_content, signer.private_key, &signature));
  if (result != kSuccess) {
    LOG(kError) << "Failed to sign content: " << result;
    OperationCallback(false, results, index);
    return;
  }

  pca::SignedData signed_data;
  signed_data.set_data(packet_content);
  signed_data.set_signature(signature);
  if (!remote_chunk_store_->Store(packet_name,
                                  signed_data.SerializeAsString(),
                                  [&, index] (bool result) {
                                    OperationCallback(result, results, index);
                                  },
                                  signer)) {
    LOG(kError) << "Failed to store: " << index;
    OperationCallback(false, results, index);
  }
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
  asymm::Keys signer(passport_.SignaturePacketDetails(sign_pt, true));
  assert(!signer.identity.empty());

  asymm::Signature signature;
  int result(asymm::Sign(content, signer.private_key, &signature));
  if (result != kSuccess) {
    LOG(kError) << "Failed to sign content: " << result;
    OperationCallback(false, results, index);
    return;
  }

  pca::SignedData signed_data;
  signed_data.set_data(content);
  signed_data.set_signature(signature);
  if (!remote_chunk_store_->Modify(name,
                                   signed_data.SerializeAsString(),
                                   [&, index] (bool result) {
                                     OperationCallback(result, results, index);
                                   },
                                   signer)) {
    LOG(kError) << "Failed to modify: " << index;
    OperationCallback(false, results, index);
  }
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

  result = DeleteOldIdentityPackets();
  if (result != kSuccess) {
    LOG(kError) << "Failed to delete old identity packets: " << result;
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

  asymm::Keys signer(passport_.SignaturePacketDetails(sig_type, true));
  assert(!signer.identity.empty());
  if (!remote_chunk_store_->Delete(name,
                                   [&, index] (bool result) {
                                     OperationCallback(result, results, index);
                                   },
                                   signer)) {
    LOG(kError) << "Failed to delete: " << index;
    OperationCallback(false, results, index);
  }
}

int UserCredentialsImpl::ChangePassword(const std::string& new_password) {
  std::unique_lock<std::mutex> loch_a_phuill(single_threaded_class_mutex_);

  int result(CheckPasswordValidity(new_password));
  if (result != kSuccess) {
    LOG(kError) << "Incorrect input.";
    return result;
  }

  // TODO(Alison) - fail if any other instances are logged in

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
  int result(DeleteOldIdentityPackets());
  if (result != kSuccess) {
    LOG(kError) << "Failed to delete identity packets.";
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
  std::vector<int> individual_results(3, priv::utilities::kPendingResult);
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
//  DeletePmid(results);

  int result(utils::WaitForResults(mutex, condition_variable, individual_results,
                                   std::chrono::seconds(30)));
  if (result != kSuccess) {
    LOG(kError) << "Wait for results timed out: " << result;
    LOG(kError) << "ANMID: " << individual_results.at(0)
              << ", ANSMID: " << individual_results.at(1)
              << ", ANTMID: " << individual_results.at(2);
//              << ", PMID path: " << individual_results.at(3);
    return result;
  }
  LOG(kInfo) << "ANMID: " << individual_results.at(0)
             << ", ANSMID: " << individual_results.at(1)
             << ", ANTMID: " << individual_results.at(2);
//             << ", PMID path: " << individual_results.at(3);

  result = AssessJointResult(individual_results);
  if (result != kSuccess) {
    LOG(kError) << "One of the operations for Anonymous Packets failed. "
                << "Turn on INFO for feedback on which one. ";
    return kDeleteSignaturePacketsFailure;
  }

  return kSuccess;
}

void UserCredentialsImpl::DeleteAnmid(OperationResults& results) {
  asymm::Keys anmid(passport_.SignaturePacketDetails(passport::kAnmid, true));
  assert(!anmid.identity.empty());
  DeleteSignaturePacket(anmid, results, 0);
}

void UserCredentialsImpl::DeleteAnsmid(OperationResults& results) {
  asymm::Keys ansmid(passport_.SignaturePacketDetails(passport::kAnsmid, true));
  assert(!ansmid.identity.empty());
  DeleteSignaturePacket(ansmid, results, 1);
}

void UserCredentialsImpl::DeleteAntmid(OperationResults& results) {
  asymm::Keys antmid(passport_.SignaturePacketDetails(passport::kAntmid, true));
  assert(!antmid.identity.empty());
  DeleteSignaturePacket(antmid, results, 2);
}

void UserCredentialsImpl::DeletePmid(OperationResults& results) {
  asymm::Keys pmid(passport_.SignaturePacketDetails(passport::kPmid, true));
  assert(!pmid.identity.empty());
  asymm::Keys maid(passport_.SignaturePacketDetails(passport::kMaid, true));
  assert(!maid.identity.empty());

  std::string pmid_name(pca::ApplyTypeToName(pmid.identity, pca::kSignaturePacket));
  if (!remote_chunk_store_->Delete(pmid_name,
                                   [&] (bool result) { DeleteMaid(result, results, maid); },
                                   maid)) {
    LOG(kError) << "Failed to delete PMID.";
    DeleteMaid(false, results, asymm::Keys());
  }
}

void UserCredentialsImpl::DeleteMaid(bool result,
                                     OperationResults& results,
                                     asymm::Keys maid) {
  if (!result) {
    LOG(kError) << "Failed to delete PMID.";
    OperationCallback(false, results, 3);
    return;
  }

  asymm::Keys anmaid(passport_.SignaturePacketDetails(passport::kAnmaid, true));
  assert(!anmaid.identity.empty());
  std::string maid_name(pca::ApplyTypeToName(maid.identity, pca::kSignaturePacket));
  if (!remote_chunk_store_->Delete(maid_name,
                                   [&] (bool result) {
                                     DeleteAnmaid(result, results, anmaid);
                                   },
                                   anmaid)) {
    LOG(kError) << "Failed to delete MAID.";
    DeleteAnmaid(false, results, asymm::Keys());
  }
}

void UserCredentialsImpl::DeleteAnmaid(bool result,
                                       OperationResults& results,
                                       asymm::Keys anmaid) {
  if (!result) {
    LOG(kError) << "Failed to delete MAID.";
    OperationCallback(false, results, 3);
    return;
  }

  DeleteSignaturePacket(anmaid, results, 3);
}

void UserCredentialsImpl::DeleteSignaturePacket(asymm::Keys packet,
                                                OperationResults& results,
                                                int index) {
  std::string packet_name(pca::ApplyTypeToName(packet.identity, pca::kSignaturePacket));
  if (!remote_chunk_store_->Delete(packet_name,
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

  if (session_.session_access_level() == kFullAccess) {
    int result = SaveSession(false);
    LOG(kInfo) << "Session saver result: " << result;
  }

  session_saver_timer_.async_wait([=] (const boost::system::error_code& error_code) {
                                    this->SessionSaver(bptime::seconds(interval), error_code);
                                  });
}

void UserCredentialsImpl::LogoutCompletedArrived(const std::string& session_marker) {
  std::lock_guard<std::mutex> loch(completed_log_out_mutex_);
  completed_log_out_message_ = session_marker;
  completed_log_out_ = true;
  completed_log_out_conditional_.notify_one();
}

bool  UserCredentialsImpl::IsOwnSessionTerminationMessage(const std::string& session_marker) {
  return pending_session_marker_ == session_marker;
}

}  // namespace lifestuff

}  // namespace maidsafe
