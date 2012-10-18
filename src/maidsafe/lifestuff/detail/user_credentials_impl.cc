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
#include "maidsafe/private/chunk_actions/chunk_id.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"
#include "maidsafe/private/utils/utilities.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/routings_handler.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"


namespace pca = maidsafe::priv::chunk_actions;
namespace bptime = boost::posix_time;
namespace utils = maidsafe::priv::utils;

namespace maidsafe {

namespace lifestuff {

namespace {

void CreateSignaturePacketInfo(const Fob& packet,
                               priv::ChunkId& packet_name,
                               NonEmptyString& packet_content) {
  packet_name = SignaturePacketName(packet.identity);

  pca::SignedData signed_data;
  asymm::EncodedPublicKey public_key(asymm::EncodeKey(packet.keys.public_key));
  signed_data.set_data(public_key.string());
  signed_data.set_signature(packet.validation_token.string());
  packet_content = NonEmptyString(signed_data.SerializeAsString());
}

void GenerateLogoutRequest(const NonEmptyString& session_marker,
                           NonEmptyString& serialised_message) {
  LogoutProceedings proceedings;
  proceedings.set_session_requestor(session_marker.string());

  OtherInstanceMessage other_instance_message;
  other_instance_message.set_message_type(1);

  other_instance_message.set_serialised_message(proceedings.SerializeAsString());
  serialised_message = NonEmptyString(other_instance_message.SerializeAsString());
}

uint32_t StringToIntPin(const NonEmptyString& pin) {
  return boost::lexical_cast<uint32_t>(pin.string());
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


int UserCredentialsImpl::LogIn(const NonEmptyString& keyword,
                               const NonEmptyString& pin,
                               const NonEmptyString& password) {
  int result = AttemptLogInProcess(keyword, pin, password);
  if (result != kSuccess)
    session_.Reset();
  return result;
}

int UserCredentialsImpl::AttemptLogInProcess(const NonEmptyString& keyword,
                                             const NonEmptyString& pin,
                                             const NonEmptyString& password) {
  std::unique_lock<std::mutex>loch_a_phuill(single_threaded_class_mutex_);

  int result(CheckKeywordValidity(keyword));
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid keyword: " << keyword.string() << "    Return code: " << result << ")";
    return result;
  }
  result = CheckPinValidity(pin);
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid pin: " << pin.string() << "    Return code: " << result << ")";
    return result;
  }
  result = CheckPasswordValidity(password);
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid password: " << password.string() << "    Return code: " << result << ")";
    return result;
  }

  std::string mid_packet, smid_packet;
  result = GetUserInfo(keyword, pin, password, false, mid_packet, smid_packet);
  if (result != kSuccess) {
    LOG(kInfo) << "UserCredentialsImpl::LogIn - failed to get user info.";
    return result;
  }

  // Check other running instances
//  result = CheckForOtherRunningInstances(keyword, pin, password, mid_packet, smid_packet);
//  if (result != kSuccess) {
//    LOG(kInfo) << "UserCredentialsImpl::LogIn - Failure to deal with other running instances.";
//    return result;
//  }

  session_.set_keyword(keyword);
  session_.set_pin(pin);
  session_.set_password(password);
  session_.set_session_access_level(kFullAccess);
  session_.set_session_name();

  session_saved_once_ = false;
//  StartSessionSaver();

  return kSuccess;
}

int UserCredentialsImpl::CheckForOtherRunningInstances(const NonEmptyString& keyword,
                                                       const NonEmptyString& pin,
                                                       const NonEmptyString& password,
                                                       std::string& mid_packet,
                                                       std::string& smid_packet) {
  // Start MAID routing
  Fob maid(passport_.SignaturePacketDetails(passport::kMaid, true));
  routings_handler_.AddRoutingObject(maid,
                                     std::vector<std::pair<std::string, uint16_t> >(),
                                     NonEmptyString(maid.identity),
                                     nullptr);

  // Message self and wait for response
  std::string logout_request_acknowledgement;
  NonEmptyString request_logout;
  pending_session_marker_ = RandomString(64);
  GenerateLogoutRequest(NonEmptyString(pending_session_marker_), request_logout);
  bool successful_send(routings_handler_.Send(maid.identity,
                                              maid.identity,
                                              maid.keys.public_key,
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

int UserCredentialsImpl::GetUserInfo(const NonEmptyString& keyword,
                                     const NonEmptyString& pin,
                                     const NonEmptyString& password,
                                     const bool& compare_names,
                                     std::string& mid_packet,
                                     std::string& smid_packet) {
  if (compare_names) {
    std::string new_mid_packet;
    std::string new_smid_packet;

    uint32_t int_pin(StringToIntPin(pin));
    priv::ChunkId mid_name(ModifiableName(Identity(passport::MidName(keyword, int_pin, false))));
    priv::ChunkId smid_name(ModifiableName(Identity(passport::MidName(keyword, int_pin, false))));

    boost::thread get_mid_thread(
        [&] {
          new_mid_packet = remote_chunk_store_->Get(mid_name, Fob());
        });
    boost::thread get_smid_thread(
        [&] {
          new_smid_packet = remote_chunk_store_->Get(smid_name, Fob());
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
    LOG(kInfo) << "User doesn't exist: " << keyword.string() << ", " << pin.string();
    return kLoginUserNonExistence;
  }

  if (mid_tmid_result == kCorruptedPacket && smid_stmid_result == kCorruptedPacket) {
    LOG(kError) << "Account corrupted. Should never happen: "
                << keyword.string() << ", " << pin.string();
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

void UserCredentialsImpl::GetIdAndTemporaryId(const NonEmptyString& keyword,
                                              const NonEmptyString& pin,
                                              const NonEmptyString& password,
                                              bool surrogate,
                                              int* result,
                                              std::string* id_contents,
                                              std::string* temporary_packet) {
  priv::ChunkId id_name(ModifiableName(passport::MidName(keyword, StringToIntPin(pin), surrogate)));
  std::string id_packet(remote_chunk_store_->Get(id_name, Fob()));
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

  NonEmptyString decrypted_rid(passport::DecryptRid(keyword,
                                                    StringToIntPin(pin),
                                                    NonEmptyString(packet.data())));

  std::string temporary_id_packet(remote_chunk_store_->Get(ModifiableName(Identity(decrypted_rid)),
                                                           Fob()));
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


  *temporary_packet = passport::DecryptSession(keyword,
                                               StringToIntPin(pin),
                                               password,
                                               NonEmptyString(crypto::Hash<crypto::SHA512>(pin)),
                                               NonEmptyString(packet.data())).string();
  if (temporary_packet->empty()) {
    LOG(kError) << (surrogate ? "STMID" : "TMID") << " packet corrupted: "
                << "Failed decryption.";
    *result = kCorruptedPacket;
    return;
  }
}

int UserCredentialsImpl::HandleSerialisedDataMaps(const NonEmptyString& keyword,
                                                  const NonEmptyString& pin,
                                                  const NonEmptyString& password,
                                                  const std::string& tmid_serialised_data_atlas,
                                                  const std::string& stmid_serialised_data_atlas) {
  int result(kSuccess);
  std::string tmid_da, stmid_da;
  if (!tmid_serialised_data_atlas.empty()) {
    result = session_.ParseDataAtlas(NonEmptyString(tmid_serialised_data_atlas));
    if (result == kSuccess) {
      session_.set_serialised_data_atlas(NonEmptyString(tmid_serialised_data_atlas));
      tmid_da = tmid_serialised_data_atlas;
    } else if (result == kTryAgainLater) {
      return kTryAgainLater;
    }
  } else if (!stmid_serialised_data_atlas.empty()) {
    tmid_da = stmid_serialised_data_atlas;
    stmid_da = stmid_serialised_data_atlas;
    result = session_.ParseDataAtlas(NonEmptyString(stmid_serialised_data_atlas));
    if (result == kSuccess) {
      session_.set_serialised_data_atlas(NonEmptyString(stmid_serialised_data_atlas));
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

  int id_packets_result = passport_.SetIdentityPackets(keyword,
                                                       StringToIntPin(pin),
                                                       password,
                                                       NonEmptyString(tmid_da),
                                                       NonEmptyString(stmid_da));
  id_packets_result += passport_.ConfirmIdentityPackets();
  if (id_packets_result != kSuccess) {
    LOG(kError) << "Failure to set and confirm identity packets.";
    return kSetIdentityPacketsFailure;
  }

  return result;
}

int UserCredentialsImpl::CreateUser(const NonEmptyString& keyword,
                                    const NonEmptyString& pin,
                                    const NonEmptyString& password) {
  std::unique_lock<std::mutex> loch_a_phuill(single_threaded_class_mutex_);

  int result(CheckKeywordValidity(keyword));
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid keyword: " << keyword.string() << "    Return code: " << result << ")";
    return result;
  }
  result = CheckPinValidity(pin);
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid pin: " << pin.string() << "    Return code: " << result << ")";
    return result;
  }
  result = CheckPasswordValidity(password);
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid password: " << password.string() << "    (Return code: " << result << ")";
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
  session_.set_session_name();
  session_.set_changed(true);

//  Fob maid(passport_.SignaturePacketDetails(passport::kMaid, true));
//  if (!routings_handler_.AddRoutingObject(maid,
//                                          std::vector<std::pair<std::string, uint16_t> >(),
//                                          NonEmptyString(maid.identity),
//                                          nullptr)) {
//    LOG(kError) << "Failure to start the routing object for the MAID.";
//    return -1;
//  }

  return kSuccess;
}

int UserCredentialsImpl::ProcessSigningPackets() {
  passport_.CreateSigningPackets();

  int result = StoreAnonymousPackets();
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
  std::vector<int> individual_results(4, utils::kPendingResult);
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
  Fob anmid(passport_.SignaturePacketDetails(passport::kAnmid, false));
  StoreSignaturePacket(anmid, results, 0);
}

void UserCredentialsImpl::StoreAnsmid(OperationResults& results) {
  Fob ansmid(passport_.SignaturePacketDetails(passport::kAnsmid, false));
  StoreSignaturePacket(ansmid, results, 1);
}

void UserCredentialsImpl::StoreAntmid(OperationResults& results) {
  Fob antmid(passport_.SignaturePacketDetails(passport::kAntmid, false));
  StoreSignaturePacket(antmid, results, 2);
}

void UserCredentialsImpl::StoreSignaturePacket(const Fob& packet,
                                               OperationResults& results,
                                               int index) {
  priv::ChunkId packet_name;
  NonEmptyString packet_content;

  CreateSignaturePacketInfo(packet, packet_name, packet_content);
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
  Fob anmaid(passport_.SignaturePacketDetails(passport::kAnmaid, false));
  priv::ChunkId packet_name;
  NonEmptyString packet_content;

  CreateSignaturePacketInfo(anmaid, packet_name, packet_content);
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

  Fob maid(passport_.SignaturePacketDetails(passport::kMaid, false));
  Fob anmaid(passport_.SignaturePacketDetails(passport::kAnmaid, false));

  priv::ChunkId maid_name(SignaturePacketName(maid.identity));
  pca::SignedData signed_maid;
  signed_maid.set_signature(maid.validation_token.string());
  asymm::EncodedPublicKey maid_string_public_key(asymm::EncodeKey(maid.keys.public_key));
  signed_maid.set_data(maid_string_public_key.string());
  if (!remote_chunk_store_->Store(maid_name,
                                  NonEmptyString(signed_maid.SerializeAsString()),
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

  Fob pmid(passport_.SignaturePacketDetails(passport::kPmid, false));
  Fob maid(passport_.SignaturePacketDetails(passport::kMaid, false));

  priv::ChunkId pmid_name(SignaturePacketName(pmid.identity));
  pca::SignedData signed_pmid;
  signed_pmid.set_signature(pmid.validation_token.string());
  asymm::EncodedPublicKey pmid_string_public_key(asymm::EncodeKey(pmid.keys.public_key));
  signed_pmid.set_data(pmid_string_public_key.string());

  if (!remote_chunk_store_->Store(pmid_name,
                                  NonEmptyString(signed_pmid.SerializeAsString()),
                                  [&] (bool result) {
                                    OperationCallback(result, results, 3);
                                  },
                                  maid)) {
    LOG(kError) << "Failed to store PMID.";
    OperationCallback(false, results, 3);
  }
}

int UserCredentialsImpl::ProcessIdentityPackets(const NonEmptyString& keyword,
                                                const NonEmptyString& pin,
                                                const NonEmptyString& password) {
  NonEmptyString serialised_data_atlas(session_.SerialiseDataAtlas());
  Sleep(bptime::milliseconds(1));  // Need different timestamps
  NonEmptyString surrogate_serialised_data_atlas(session_.SerialiseDataAtlas());

  int result(passport_.SetIdentityPackets(keyword,
                                          StringToIntPin(pin),
                                          password,
                                          serialised_data_atlas,
                                          surrogate_serialised_data_atlas));
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
  std::vector<int> individual_results(4, utils::kPendingResult);
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
  Identity packet_name(passport_.IdentityPacketName(id_pt, false));
  NonEmptyString packet_content(passport_.IdentityPacketValue(id_pt, false));
  Fob signer(passport_.SignaturePacketDetails(sign_pt, true));

  asymm::Signature signature(asymm::Sign(packet_content, signer.keys.private_key));
  pca::SignedData signed_data;
  signed_data.set_data(packet_content.string());
  signed_data.set_signature(signature.string());
  if (!remote_chunk_store_->Store(ModifiableName(packet_name),
                                  NonEmptyString(signed_data.SerializeAsString()),
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

  NonEmptyString serialised_data_atlas;
  int result(SerialiseAndSetIdentity("", "", "", serialised_data_atlas));
  if (result != kSuccess) {
    LOG(kError) << "Failure setting details of new session: " << result;
    return result;
  }

  std::vector<int> individual_results(4, utils::kPendingResult);
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
  Identity name(passport_.IdentityPacketName(id_pt, false));
  NonEmptyString content(passport_.IdentityPacketValue(id_pt, false));
  Fob signer(passport_.SignaturePacketDetails(sign_pt, true));

  asymm::Signature signature(asymm::Sign(content, signer.keys.private_key));

  pca::SignedData signed_data;
  signed_data.set_data(content.string());
  signed_data.set_signature(signature.string());
  if (!remote_chunk_store_->Modify(ModifiableName(name),
                                   NonEmptyString(signed_data.SerializeAsString()),
                                   [&, index] (bool result) {
                                     OperationCallback(result, results, index);
                                   },
                                   signer)) {
    LOG(kError) << "Failed to modify: " << index;
    OperationCallback(false, results, index);
  }
}

int UserCredentialsImpl::ChangePin(const NonEmptyString& new_pin) {
  std::unique_lock<std::mutex> loch_a_phuill(single_threaded_class_mutex_);

  int result(CheckPinValidity(new_pin));
  if (result != kSuccess) {
    LOG(kError) << "Incorrect input.";
    return result;
  }

  NonEmptyString keyword(session_.keyword());
  return ChangeKeywordPin(keyword, new_pin);
}

int UserCredentialsImpl::ChangeKeyword(const NonEmptyString& new_keyword) {
  std::unique_lock<std::mutex> loch_a_phuill(single_threaded_class_mutex_);

  int result(CheckKeywordValidity(new_keyword));
  if (result != kSuccess) {
    LOG(kError) << "Incorrect input.";
    return result;
  }

  NonEmptyString pin(session_.pin());
  return ChangeKeywordPin(new_keyword, pin);
}

int UserCredentialsImpl::ChangeKeywordPin(const NonEmptyString& new_keyword,
                                          const NonEmptyString& new_pin) {
  NonEmptyString serialised_data_atlas;
  int result(SerialiseAndSetIdentity(new_keyword.string(),
                                     new_pin.string(),
                                     "",
                                     serialised_data_atlas));
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
  std::vector<int> individual_results(4, utils::kPendingResult);
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
  Identity name(passport_.IdentityPacketName(id_type, true));

  Fob signer(passport_.SignaturePacketDetails(sig_type, true));
  if (!remote_chunk_store_->Delete(ModifiableName(name),
                                   [&, index] (bool result) {
                                     OperationCallback(result, results, index);
                                   },
                                   signer)) {
    LOG(kError) << "Failed to delete: " << index;
    OperationCallback(false, results, index);
  }
}

int UserCredentialsImpl::ChangePassword(const NonEmptyString& new_password) {
  std::unique_lock<std::mutex> loch_a_phuill(single_threaded_class_mutex_);

  int result(CheckPasswordValidity(new_password));
  if (result != kSuccess) {
    LOG(kError) << "Incorrect input.";
    return result;
  }

  // TODO(Alison) - fail if any other instances are logged in

  NonEmptyString serialised_data_atlas;
  result = SerialiseAndSetIdentity("", "", new_password.string(), serialised_data_atlas);
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
  std::vector<int> individual_results(4, utils::kPendingResult);
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
  individual_results[2] = utils::kPendingResult;
  individual_results[3] = utils::kPendingResult;
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
                                                 NonEmptyString& serialised_data_atlas) {
  serialised_data_atlas = session_.SerialiseDataAtlas();
  return passport_.SetIdentityPackets(keyword.empty() ? session_.keyword() :
                                                        NonEmptyString(keyword),
                                      pin.empty() ? StringToIntPin(session_.pin()) :
                                                    StringToIntPin(NonEmptyString(pin)),
                                      password.empty() ? session_.password() :
                                                         NonEmptyString(password),
                                      serialised_data_atlas,
                                      session_.serialised_data_atlas());
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
  std::vector<int> individual_results(4, utils::kPendingResult);
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
  Fob anmid(passport_.SignaturePacketDetails(passport::kAnmid, true));
  DeleteSignaturePacket(anmid, results, 0);
}

void UserCredentialsImpl::DeleteAnsmid(OperationResults& results) {
  Fob ansmid(passport_.SignaturePacketDetails(passport::kAnsmid, true));
  DeleteSignaturePacket(ansmid, results, 1);
}

void UserCredentialsImpl::DeleteAntmid(OperationResults& results) {
  Fob antmid(passport_.SignaturePacketDetails(passport::kAntmid, true));
  DeleteSignaturePacket(antmid, results, 2);
}

void UserCredentialsImpl::DeletePmid(OperationResults& results) {
  Fob pmid(passport_.SignaturePacketDetails(passport::kPmid, true));
  Fob maid(passport_.SignaturePacketDetails(passport::kMaid, true));

  if (!remote_chunk_store_->Delete(SignaturePacketName(pmid.identity),
                                   [&] (bool result) { DeleteMaid(result, results, maid); },
                                   maid)) {
    LOG(kError) << "Failed to delete PMID.";
    DeleteMaid(false, results, Fob());
  }
}

void UserCredentialsImpl::DeleteMaid(bool result,
                                     OperationResults& results,
                                     const Fob& maid) {
  if (!result) {
    LOG(kError) << "Failed to delete PMID.";
    OperationCallback(false, results, 3);
    return;
  }

  Fob anmaid(passport_.SignaturePacketDetails(passport::kAnmaid, true));
  if (!remote_chunk_store_->Delete(SignaturePacketName(maid.identity),
                                   [&] (bool result) {
                                     DeleteAnmaid(result, results, anmaid);
                                   },
                                   anmaid)) {
    LOG(kError) << "Failed to delete MAID.";
    DeleteAnmaid(false, results, Fob());
  }
}

void UserCredentialsImpl::DeleteAnmaid(bool result,
                                       OperationResults& results,
                                       const Fob& anmaid) {
  if (!result) {
    LOG(kError) << "Failed to delete MAID.";
    OperationCallback(false, results, 3);
    return;
  }

  DeleteSignaturePacket(anmaid, results, 3);
}

void UserCredentialsImpl::DeleteSignaturePacket(const Fob& packet,
                                                OperationResults& results,
                                                int index) {
  if (!remote_chunk_store_->Delete(SignaturePacketName(packet.identity),
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
