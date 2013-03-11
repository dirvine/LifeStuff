/***************************************************************************************************
 *  Copyright 2013 MaidSafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use.  The use of this code is governed by the licence file licence.txt found in the root of    *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit         *
 *  written permission of the board of directors of MaidSafe.net.                                  *
 **************************************************************************************************/

#include "maidsafe/lifestuff/detail/user_credentials.h"

#include <memory>
#include <utility>

#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/thread/thread.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/routings_handler.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace args = std::placeholders;

namespace maidsafe {
namespace lifestuff {

namespace {

// void CreateSignaturePacketInfo(const Fob& packet,
//                               priv::ChunkId& packet_name,
//                               NonEmptyString& packet_content) {
//  packet_name = SignaturePacketName(packet.identity);
//
//  pca::SignedData signed_data;
//  asymm::EncodedPublicKey public_key(asymm::EncodeKey(packet.keys.public_key));
//  signed_data.set_data(public_key.string());
//  signed_data.set_signature(packet.validation_token.string());
//  packet_content = NonEmptyString(signed_data.SerializeAsString());
// }
//
// void GenerateLogoutRequest(const NonEmptyString& session_marker,
//                           NonEmptyString& serialised_message) {
//  LogoutProceedings proceedings;
//  proceedings.set_session_requestor(session_marker.string());
//
//  OtherInstanceMessage other_instance_message;
//  other_instance_message.set_message_type(1);
//
//  other_instance_message.set_serialised_message(proceedings.SerializeAsString());
//  serialised_message = NonEmptyString(other_instance_message.SerializeAsString());
// }

uint32_t StringToIntPin(const NonEmptyString& pin) {
  return std::stoul(pin.string());
}

}  // namespace

UserCredentials::UserCredentials(ClientNfs& client_nfs)
  : passport_(),
    client_nfs_(client_nfs) {}

UserCredentials::~UserCredentials() {}

void UserCredentials::CreateUser(const Keyword& /*keyword*/,
                                 const Pin& /*pin*/,
                                 const Password& /*password*/) {
  return;
}

void UserCredentials::LogIn(const Keyword& /*keyword*/,
                            const Pin& /*pin*/,
                            const Password& /*password*/) {
//   CheckInputs(keyword, pin, password);

  return;
//  std::string mid_packet, smid_packet;
//  result = GetUserInfo(keyword, pin, password, false, mid_packet, smid_packet);
//  if (result != kSuccess) {
//    LOG(kInfo) << "UserCredentials::LogIn - failed to get user info.";
//    return result;
//  }
//
//  // Check other running instances
//  if (!test_) {
//    result = CheckForOtherRunningInstances(keyword, pin, password, mid_packet, smid_packet);
//    if (result != kSuccess) {
//      LOG(kInfo) << "UserCredentials::LogIn - Failure to deal with other running instances.";
//      return result;
//    }
//  }
//
//  session_.set_keyword(keyword);
//  session_.set_pin(pin);
//  session_.set_password(password);
//  session_.set_session_access_level(kFullAccess);
//  session_.set_session_name();
//
//  session_saved_once_ = false;
// //  StartSessionSaver();
//
//  return kSuccess;
}

// int UserCredentials::CheckForOtherRunningInstances(const NonEmptyString& keyword,
//                                                   const NonEmptyString& pin,
//                                                   const NonEmptyString& password,
//                                                   std::string& mid_packet,
//                                                   std::string& smid_packet) {
//  // Start MAID routing
//  Fob maid(passport_.SignaturePacketDetails(passport::kMaid, true));
//  if (!routings_handler_.AddRoutingObject(maid,
//                                          session_.bootstrap_endpoints(),
//                                          NonEmptyString(maid.identity),
//                                          nullptr)) {
//    LOG(kError) << "Failed to add MAID routing object to check for running instances.";
//    return -1;
//  }
//
//  // Message self and wait for response
//  std::string logout_request_acknowledgement;
//  NonEmptyString request_logout;
//  pending_session_marker_ = RandomString(64);
//  GenerateLogoutRequest(NonEmptyString(pending_session_marker_), request_logout);
//  bool successful_send(routings_handler_.Send(maid.identity,
//                                              maid.identity,
//                                              maid.keys.public_key,
//                                              request_logout,
//                                              &logout_request_acknowledgement));
//  if (!successful_send) {
//    if (logout_request_acknowledgement.empty()) {
//      LOG(kWarning) << "Timed out. Not necessarily a failure.";
//    } else {
//      LOG(kError) << "Sending failed.";
//      return -1;
//    }
//  }
//
//  // If other instances exist wait for log out message
//  if (!logout_request_acknowledgement.empty()) {
//    // Check logout_request_acknowledgement
//    OtherInstanceMessage other_instance_message;
//    if (!other_instance_message.ParseFromString(logout_request_acknowledgement) ||
//        other_instance_message.message_type() != 1) {
//      LOG(kError) << "Message response is not of the type expected.";
//      return -1;
//    }
//    LogoutProceedings proceedings;
//    if (!proceedings.ParseFromString(other_instance_message.serialised_message()) ||
//        !proceedings.has_session_acknowledger()) {
//      LOG(kError) << "Message has wrong format.";
//      return -1;
//    }
//
//    if (proceedings.session_acknowledger() != pending_session_marker_) {
//      LOG(kError) << "Session marker not replicated in acknowlegdement";
//      return -1;
//    }
//
//    std::unique_lock<std::mutex> lock(completed_log_out_mutex_);
//    if (!completed_log_out_conditional_.wait_for(lock,
//                                                 std::chrono::minutes(1),
//                                                 [&] () { return completed_log_out_; })) {
//      LOG(kError) << "Timed out waiting for other party to report logout. "
//                  << "Failure! Too dangerous to log in.";
//      return kNoLogoutResponse;
//    }
//
//    // Check response is valid
//    if (completed_log_out_message_ != pending_session_marker_) {
//      LOG(kError) << "Session marker does not match marker sent in request.";
//      return -1;
//    }
//
//    // Run GetUserInfo again
//    int result(GetUserInfo(keyword, pin, password, true, mid_packet, smid_packet));
//    if (result != kSuccess) {
//      LOG(kInfo) << "UserCredentials::LogIn - Failed to get user info after remote logout.";
//      return result;
//    }
//  }
//
//  return kSuccess;
// }

void UserCredentials::LogOut() {
  // SaveSession(true); !!!
  return;
}

// void UserCredentials::StartSessionSaver() {
//  session_saver_timer_active_ = true;
//  session_saver_timer_.expires_from_now(bptime::seconds(session_saver_interval_));
//  session_saver_timer_.async_wait([=] (const boost::system::error_code &error_code) {
//                                    this->SessionSaver(bptime::seconds(session_saver_interval_),
//                                                       error_code);
//                                  });
// }
//
// void UserCredentials::GetIdAndTemporaryId(const NonEmptyString& keyword,
//                                              const NonEmptyString& pin,
//                                              const NonEmptyString& password,
//                                              bool surrogate,
//                                              int* result,
//                                              std::string* id_contents,
//                                              std::string* temporary_packet) {
//  priv::ChunkId id_name(ModifiableName(passport::MidName(keyword, StringToIntPin(pin), surrogate))); // NOLINT
//  std::string id_packet(remote_chunk_store_->Get(id_name, Fob()));
//  if (id_packet.empty()) {
//    LOG(kError) << "No " << (surrogate ? "SMID" : "MID") << " found.";
//    *result = kIdPacketNotFound;
//    return;
//  }
//  *id_contents = id_packet;
//
//  pca::SignedData packet;
//  if (!packet.ParseFromString(id_packet) || packet.data().empty()) {
//    LOG(kError) << (surrogate ? "SMID" : "MID") << " packet corrupted: Failed parse.";
//    *result = kCorruptedPacket;
//    return;
//  }
//
//  Identity decrypted_rid(passport::DecryptRid(keyword,
//                                              StringToIntPin(pin),
//                                              NonEmptyString(packet.data())).string());
//
//  std::string temporary_id_packet(remote_chunk_store_->Get(ModifiableName(Identity(decrypted_rid)), // NOLINT
//                                                           Fob()));
//  if (temporary_id_packet.empty()) {
//    LOG(kError) << "No " << (surrogate ? "STMID" : "TMID") << " found.";
//    *result = kTemporaryIdPacketNotFound;
//    return;
//  }
//
//  packet.Clear();
//  if (!packet.ParseFromString(temporary_id_packet) || packet.data().empty()) {
//    LOG(kError) << (surrogate ? "STMID" : "TMID") << " packet corrupted: "
//                << "Failed parse.";
//    *result = kCorruptedPacket;
//    return;
//  }
//
//
//  *temporary_packet = passport::DecryptSession(keyword,
//                                               StringToIntPin(pin),
//                                               password,
//                                               NonEmptyString(crypto::Hash<crypto::SHA512>(pin)),
//                                               NonEmptyString(packet.data())).string();
//  if (temporary_packet->empty()) {
//    LOG(kError) << (surrogate ? "STMID" : "TMID") << " packet corrupted: "
//                << "Failed decryption.";
//    *result = kCorruptedPacket;
//    return;
//  }
// }
//
// int TmidAndNoStmid(const std::string& tmid_serialised_data_atlas,
//                   Session& session,
//                   std::string& tmid_da,
//                   std::string& stmid_da) {
//  int result = session.ParseDataAtlas(NonEmptyString(tmid_serialised_data_atlas));
//  if (result == kSuccess) {
//    tmid_da = tmid_serialised_data_atlas;
//    stmid_da = tmid_serialised_data_atlas;
//    session.set_serialised_data_atlas(NonEmptyString(tmid_serialised_data_atlas));
//    return kSuccess;
//  }
//  return kLoginAccountCorrupted;
// }
//
// int StmidAndNoTmid(const std::string& stmid_serialised_data_atlas,
//                   Session& session,
//                   std::string& tmid_da,
//                   std::string& stmid_da) {
//  int result = session.ParseDataAtlas(NonEmptyString(stmid_serialised_data_atlas));
//  if (result == kSuccess) {
//    tmid_da = stmid_serialised_data_atlas;
//    stmid_da = stmid_serialised_data_atlas;
//    session.set_serialised_data_atlas(NonEmptyString(stmid_serialised_data_atlas));
//    return kSuccess;
//  }
//  return kLoginAccountCorrupted;
// }
//
// int BothTmidAndStmid(const std::string& tmid_serialised_data_atlas,
//                     const std::string& stmid_serialised_data_atlas,
//                     Session& session,
//                     std::string& tmid_da,
//                     std::string& stmid_da) {
//  int result = session.ParseDataAtlas(NonEmptyString(tmid_serialised_data_atlas));
//  if (result == kSuccess) {
//    tmid_da = tmid_serialised_data_atlas;
//    stmid_da = stmid_serialised_data_atlas;
//    session.set_serialised_data_atlas(NonEmptyString(stmid_serialised_data_atlas));
//    return kSuccess;
//  } else {
//    result = session.ParseDataAtlas(NonEmptyString(stmid_serialised_data_atlas));
//    if (result == kSuccess) {
//      tmid_da = stmid_serialised_data_atlas;
//      stmid_da = stmid_serialised_data_atlas;
//      session.set_serialised_data_atlas(NonEmptyString(stmid_serialised_data_atlas));
//      return kSuccess;
//    }
//  }
//  return kLoginAccountCorrupted;
// }
//
// int UserCredentials::HandleSerialisedDataMaps(const NonEmptyString& keyword,
//                                                  const NonEmptyString& pin,
//                                                  const NonEmptyString& password,
//                                                  const std::string& tmid_serialised_data_atlas,
//                                                  const std::string& stmid_serialised_data_atlas) { // NOLINT
//  if (tmid_serialised_data_atlas.empty() && stmid_serialised_data_atlas.empty()) {
//    LOG(kError) << "No valid DA.";
//    return kSetIdentityPacketsFailure;
//  }
//
//  int result(kSuccess);
//  std::string tmid_da, stmid_da;
//  if (!tmid_serialised_data_atlas.empty() && stmid_serialised_data_atlas.empty()) {
//    result = TmidAndNoStmid(tmid_serialised_data_atlas, session_, tmid_da, stmid_da);
//    if (result != kSuccess)
//      return result;
//  } else if (tmid_serialised_data_atlas.empty() && stmid_serialised_data_atlas.empty()) {
//    result = StmidAndNoTmid(stmid_serialised_data_atlas, session_, tmid_da, stmid_da);
//    if (result != kSuccess)
//      return result;
//  } else {
//    result = BothTmidAndStmid(tmid_serialised_data_atlas,
//                              stmid_serialised_data_atlas,
//                              session_,
//                              tmid_da,
//                              stmid_da);
//    if (result != kSuccess)
//      return result;
//  }
//
//  int id_packets_result = passport_.SetIdentityPackets(keyword,
//                                                       StringToIntPin(pin),
//                                                       password,
//                                                       NonEmptyString(tmid_da),
//                                                       NonEmptyString(stmid_da));
//  id_packets_result += passport_.ConfirmIdentityPackets();
//  if (id_packets_result != kSuccess) {
//    LOG(kError) << "Failure to set and confirm identity packets.";
//    return kSetIdentityPacketsFailure;
//  }
//
//  return result;
// }
//
// int UserCredentials::ProcessSigningPackets() {
//  passport_.CreateSigningPackets();
//
//  int result = StoreAnonymousPackets();
//  if (result != kSuccess) {
//    LOG(kError) << "Failure to Store Anonymous packets: " << result;
//    return result;
//  }
//
//  result = passport_.ConfirmSigningPackets();
//  if (result != kSuccess) {
//    LOG(kError) << "Failed confirming signature packets: " << result;
//    return kSessionFailure;
//  }
//
//  return kSuccess;
// }
//
// int UserCredentials::StoreAnonymousPackets() {
//  std::vector<int> individual_results(4, utils::kPendingResult);
//  std::condition_variable condition_variable;
//  std::mutex mutex;
//  OperationResults results(mutex, condition_variable, individual_results);
//
//  // ANMID path
//  StoreAnmid(results);
//  // ANSMID path
//  StoreAnsmid(results);
//  // ANTMID path
//  StoreAntmid(results);
//  // PMID path: ANMAID, MAID, PMID
//  StoreAnmaid(results);
//
//  int result(utils::WaitForResults(mutex, condition_variable, individual_results,
//                                   std::chrono::seconds(120)));
//  if (result != kSuccess) {
//    LOG(kError) << "Wait for results timed out: " << result;
//    LOG(kError) << "ANMID: " << individual_results.at(0)
//              << ", ANSMID: " << individual_results.at(1)
//              << ", ANTMID: " << individual_results.at(2)
//              << ", PMID path: " << individual_results.at(3);
//    return result;
//  }
//  LOG(kInfo) << "ANMID: " << individual_results.at(0)
//             << ", ANSMID: " << individual_results.at(1)
//             << ", ANTMID: " << individual_results.at(2)
//             << ", PMID path: " << individual_results.at(3);
//
//  result = AssessJointResult(individual_results);
//  if (result != kSuccess) {
//    LOG(kError) << "One of the operations for Anonymous Packets failed. "
//                << "Turn on INFO for feedback on which one. ";
//    return kCreateSignaturePacketsFailure;
//  }
//
//  return kSuccess;
// }
//
// void UserCredentials::StoreAnmid(OperationResults& results) {
//  Fob anmid(passport_.SignaturePacketDetails(passport::kAnmid, false));
//  StoreSignaturePacket(anmid, results, 0);
// }
//
// void UserCredentials::StoreAnsmid(OperationResults& results) {
//  Fob ansmid(passport_.SignaturePacketDetails(passport::kAnsmid, false));
//  StoreSignaturePacket(ansmid, results, 1);
// }
//
// void UserCredentials::StoreAntmid(OperationResults& results) {
//  Fob antmid(passport_.SignaturePacketDetails(passport::kAntmid, false));
//  StoreSignaturePacket(antmid, results, 2);
// }
//
// void UserCredentials::StoreSignaturePacket(const Fob& packet,
//                                               OperationResults& results,
//                                               int index) {
//  priv::ChunkId packet_name;
//  NonEmptyString packet_content;
//
//  CreateSignaturePacketInfo(packet, packet_name, packet_content);
//  if (!remote_chunk_store_->Store(packet_name,
//                                  packet_content,
//                                  [&, index] (bool result) {
//                                    OperationCallback(result, results, index);
//                                  },
//                                  packet)) {
//    LOG(kError) << "Failed to store: " << index;
//    OperationCallback(false, results, index);
//  }
// }
//
// void UserCredentials::StoreAnmaid(OperationResults& results) {
//  Fob anmaid(passport_.SignaturePacketDetails(passport::kAnmaid, false));
//  priv::ChunkId packet_name;
//  NonEmptyString packet_content;
//
//  CreateSignaturePacketInfo(anmaid, packet_name, packet_content);
//  if (!remote_chunk_store_->Store(packet_name,
//                                  packet_content,
//                                  [&] (bool result) { StoreMaid(result, results); },
//                                  anmaid)) {
//    LOG(kError) << "Failed to store ANMAID.";
//    StoreMaid(false, results);
//  }
// }
//
// void UserCredentials::StoreMaid(bool result, OperationResults& results) {
//  if (!result) {
//    LOG(kError) << "Anmaid failed to store.";
//    OperationCallback(false, results, 3);
//    return;
//  }
//
//  Fob maid(passport_.SignaturePacketDetails(passport::kMaid, false));
//  Fob anmaid(passport_.SignaturePacketDetails(passport::kAnmaid, false));
//
//  priv::ChunkId maid_name(SignaturePacketName(maid.identity));
//  pca::SignedData signed_maid;
//  signed_maid.set_signature(maid.validation_token.string());
//  asymm::EncodedPublicKey maid_string_public_key(asymm::EncodeKey(maid.keys.public_key));
//  signed_maid.set_data(maid_string_public_key.string());
//  if (!remote_chunk_store_->Store(maid_name,
//                                  NonEmptyString(signed_maid.SerializeAsString()),
//                                  [&] (bool result) { StorePmid(result, results); },
//                                  anmaid)) {
//    LOG(kError) << "Failed to store MAID.";
//    StorePmid(false, results);
//  }
// }
//
// void UserCredentials::StorePmid(bool result, OperationResults& results) {
//  if (!result) {
//    LOG(kError) << "Maid failed to store.";
//    OperationCallback(false, results, 3);
//    return;
//  }
//
//  Fob pmid(passport_.SignaturePacketDetails(passport::kPmid, false));
//  Fob maid(passport_.SignaturePacketDetails(passport::kMaid, false));
//
//  priv::ChunkId pmid_name(SignaturePacketName(pmid.identity));
//  pca::SignedData signed_pmid;
//  signed_pmid.set_signature(pmid.validation_token.string());
//  asymm::EncodedPublicKey pmid_string_public_key(asymm::EncodeKey(pmid.keys.public_key));
//  signed_pmid.set_data(pmid_string_public_key.string());
//
//  if (!remote_chunk_store_->Store(pmid_name,
//                                  NonEmptyString(signed_pmid.SerializeAsString()),
//                                  [&] (bool result) {
//                                    OperationCallback(result, results, 3);
//                                  },
//                                  maid)) {
//    LOG(kError) << "Failed to store PMID.";
//    OperationCallback(false, results, 3);
//  }
// }
//
// int UserCredentials::ProcessIdentityPackets(const NonEmptyString& keyword,
//                                                const NonEmptyString& pin,
//                                                const NonEmptyString& password) {
//  NonEmptyString serialised_data_atlas(session_.SerialiseDataAtlas());
//  Sleep(bptime::milliseconds(1));  // Need different timestamps
//  NonEmptyString surrogate_serialised_data_atlas(session_.SerialiseDataAtlas());
//
//  int result(passport_.SetIdentityPackets(keyword,
//                                          StringToIntPin(pin),
//                                          password,
//                                          serialised_data_atlas,
//                                          surrogate_serialised_data_atlas));
//  if (result!= kSuccess) {
//    LOG(kError) << "Creation of ID packets failed.";
//    return kSessionSerialisationFailure;
//  }
//
//  result = StoreIdentityPackets();
//  if (result!= kSuccess) {
//    LOG(kError) << "Storing of ID packets failed.";
//    return result;
//  }
//
//  result = passport_.ConfirmIdentityPackets();
//  if (result != kSuccess) {
//    LOG(kError) << "Failed confirming identity packets: " << result;
//    return kSessionFailure;
//  }
//
//  session_.set_serialised_data_atlas(serialised_data_atlas);
//
//  return kSuccess;
// }
//
// int UserCredentials::StoreIdentityPackets() {
//  std::vector<int> individual_results(4, utils::kPendingResult);
//  std::condition_variable condition_variable;
//  std::mutex mutex;
//  OperationResults results(mutex, condition_variable, individual_results);
//
//  // MID path
//  StoreMid(results);
//  // SMID path
//  StoreSmid(results);
//  // TMID path
//  StoreTmid(results);
//  // STMID
//  StoreStmid(results);
//
//  int result(utils::WaitForResults(mutex, condition_variable, individual_results,
//                                   std::chrono::seconds(120)));
//  if (result != kSuccess) {
//    LOG(kError) << "Wait for results timed out.";
//    return result;
//  }
//  LOG(kInfo) << "MID: " << individual_results.at(0)
//             << ", SMID: " << individual_results.at(1)
//             << ", TMID: " << individual_results.at(2)
//             << ", STMID: " << individual_results.at(3);
//
//  result = AssessJointResult(individual_results);
//  if (result != kSuccess) {
//    LOG(kError) << "One of the operations for Identity Packets failed. "
//                << "Turn on INFO for feedback on which one. ";
//    return kStoreIdentityPacketsFailure;
//  }
//
//  return kSuccess;
// }
//
// void UserCredentials::StoreMid(OperationResults& results) {
//  StoreIdentity(results, passport::kMid, passport::kAnmid, 0);
// }
//
// void UserCredentials::StoreSmid(OperationResults& results) {
//  StoreIdentity(results, passport::kSmid, passport::kAnsmid, 1);
// }
//
// void UserCredentials::StoreTmid(OperationResults& results) {
//  StoreIdentity(results, passport::kTmid, passport::kAntmid, 2);
// }
//
// void UserCredentials::StoreStmid(OperationResults& results) {
//  StoreIdentity(results, passport::kStmid, passport::kAntmid, 3);
// }
//
// void UserCredentials::StoreIdentity(OperationResults& results,
//                                        int identity_type,
//                                        int signer_type,
//                                        int index) {
//  passport::PacketType id_pt(static_cast<passport::PacketType>(identity_type));
//  passport::PacketType sign_pt(static_cast<passport::PacketType>(signer_type));
//  Identity packet_name(passport_.IdentityPacketName(id_pt, false));
//  NonEmptyString packet_content(passport_.IdentityPacketValue(id_pt, false));
//  Fob signer(passport_.SignaturePacketDetails(sign_pt, true));
//
//  asymm::Signature signature(asymm::Sign(packet_content, signer.keys.private_key));
//  pca::SignedData signed_data;
//  signed_data.set_data(packet_content.string());
//  signed_data.set_signature(signature.string());
//  if (!remote_chunk_store_->Store(ModifiableName(packet_name),
//                                  NonEmptyString(signed_data.SerializeAsString()),
//                                  [&, index] (bool result) {
//                                    OperationCallback(result, results, index);
//                                  },
//                                  signer)) {
//    LOG(kError) << "Failed to store: " << index;
//    OperationCallback(false, results, index);
//  }
// }
//
// int UserCredentials::SaveSession(bool log_out) {
//
//  if (log_out) {
//    session_saver_timer_active_ = false;
//    session_saver_timer_.cancel();
//
//    if (!session_.changed() && session_saved_once_) {
//      LOG(kError) << "Session has not changed.";
//      return kSuccess;
//    }
//  } else if (!session_.changed()) {
//    LOG(kError) << "Session has not changed.";
//    return kSuccess;
//  }
//
//  NonEmptyString serialised_data_atlas;
//  int result(SerialiseAndSetIdentity("", "", "", serialised_data_atlas));
//  if (result != kSuccess) {
//    LOG(kError) << "Failure setting details of new session: " << result;
//    return result;
//  }
//
//  std::vector<int> individual_results(4, utils::kPendingResult);
//  std::condition_variable condition_variable;
//  std::mutex mutex;
//  OperationResults results(mutex, condition_variable, individual_results);
//
//  ModifyMid(results);
//  ModifySmid(results);
//  StoreTmid(results);
//  DeleteStmid(results);
//
//  result = utils::WaitForResults(mutex, condition_variable, individual_results,
//                                 std::chrono::seconds(120));
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to store new identity packets: Time out.";
//    return kSaveSessionFailure;
//  }
//
//  LOG(kInfo) << "MID: " << individual_results.at(0)
//             << ", SMID: " << individual_results.at(1)
//             << ", TMID: " << individual_results.at(2)
//             << ", STMID: " << individual_results.at(3);
//
//  result = AssessJointResult(individual_results);
//  if (result != kSuccess) {
//    LOG(kError) << "One of the operations for Identity Packets failed. "
//                << "Turn on INFO for feedback on which one. ";
//    return kSaveSessionFailure;
//  }
//
//  session_.set_serialised_data_atlas(serialised_data_atlas);
//  session_.set_changed(false);
//  session_saved_once_ = true;
//
//  LOG(kSuccess) << "Success in SaveSession.";
//  return kSuccess;
// }
//
// void UserCredentials::ModifyMid(OperationResults& results) {
//  ModifyIdentity(results, passport::kMid, passport::kAnmid, 0);
// }
//
// void UserCredentials::ModifySmid(OperationResults& results) {
//  ModifyIdentity(results, passport::kSmid, passport::kAnsmid, 1);
// }
//
// void UserCredentials::ModifyIdentity(OperationResults& results,
//                                         int identity_type,
//                                         int signer_type,
//                                         int index) {
//  passport::PacketType id_pt(static_cast<passport::PacketType>(identity_type));
//  passport::PacketType sign_pt(static_cast<passport::PacketType>(signer_type));
//  Identity name(passport_.IdentityPacketName(id_pt, false));
//  NonEmptyString content(passport_.IdentityPacketValue(id_pt, false));
//  Fob signer(passport_.SignaturePacketDetails(sign_pt, true));
//
//  asymm::Signature signature(asymm::Sign(content, signer.keys.private_key));
//
//  pca::SignedData signed_data;
//  signed_data.set_data(content.string());
//  signed_data.set_signature(signature.string());
//  if (!remote_chunk_store_->Modify(ModifiableName(name),
//                                   NonEmptyString(signed_data.SerializeAsString()),
//                                   [&, index] (bool result) {
//                                     OperationCallback(result, results, index);
//                                   },
//                                   signer)) {
//    LOG(kError) << "Failed to modify: " << index;
//    OperationCallback(false, results, index);
//  }
// }
//
// int UserCredentials::ChangePin(const NonEmptyString& new_pin) {
//  int result(CheckPinValidity(new_pin));
//  if (result != kSuccess) {
//    LOG(kError) << "Incorrect input.";
//    return result;
//  }
//
//  NonEmptyString keyword(session_.keyword());
//  return ChangeKeywordPin(keyword, new_pin);
// }
//
// int UserCredentials::ChangeKeyword(const NonEmptyString& new_keyword) {
//
//  int result(CheckKeywordValidity(new_keyword));
//  if (result != kSuccess) {
//    LOG(kError) << "Incorrect input.";
//    return result;
//  }
//
//  NonEmptyString pin(session_.pin());
//  return ChangeKeywordPin(new_keyword, pin);
// }
//
// int UserCredentials::ChangeKeywordPin(const NonEmptyString& new_keyword,
//                                          const NonEmptyString& new_pin) {
//  NonEmptyString serialised_data_atlas;
//  int result(SerialiseAndSetIdentity(new_keyword.string(),
//                                     new_pin.string(),
//                                     "",
//                                     serialised_data_atlas));
//  if (result != kSuccess) {
//    LOG(kError) << "Failure setting details of new session: " << result;
//    return result;
//  }
//
//  result = StoreIdentityPackets();
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to store new identity packets: " << result;
//    return result;
//  }
//
//  result = DeleteOldIdentityPackets();
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to delete old identity packets: " << result;
//    return result;
//  }
//
//  result = passport_.ConfirmIdentityPackets();
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to set new identity packets: " << result;
//    return kSetIdentityPacketsFailure;
//  }
//
//  session_.set_keyword(new_keyword);
//  session_.set_pin(new_pin);
//  session_.set_serialised_data_atlas(serialised_data_atlas);
//  session_.set_changed(false);
//
//  return kSuccess;
// }
//
// int UserCredentials::DeleteOldIdentityPackets() {
//  std::vector<int> individual_results(4, utils::kPendingResult);
//  std::condition_variable condition_variable;
//  std::mutex mutex;
//  OperationResults results(mutex, condition_variable, individual_results);
//
//  DeleteMid(results);
//  DeleteSmid(results);
//  DeleteTmid(results);
//  DeleteStmid(results);
//
//  int result(utils::WaitForResults(mutex, condition_variable, individual_results,
//                                   std::chrono::seconds(120)));
//  if (result != kSuccess) {
//    LOG(kError) << "Wait for results timed out.";
//    return result;
//  }
//  LOG(kInfo) << "MID: " << individual_results.at(0)
//             << ", SMID: " << individual_results.at(1)
//             << ", TMID: " << individual_results.at(2)
//             << ", STMID: " << individual_results.at(3);
//
//  result = AssessJointResult(individual_results);
//  if (result != kSuccess) {
//    LOG(kError) << "One of the operations for Identity Packets failed. "
//                << "Turn on INFO for feedback on which one. ";
//    return kDeleteIdentityPacketsFailure;
//  }
//
//  return kSuccess;
// }
//
// void UserCredentials::DeleteMid(OperationResults& results) {
//  DeleteIdentity(results, passport::kMid, passport::kAnmid, 0);
// }
//
// void UserCredentials::DeleteSmid(OperationResults& results) {
//  DeleteIdentity(results, passport::kSmid, passport::kAnsmid, 1);
// }
//
// void UserCredentials::DeleteTmid(OperationResults& results) {
//  DeleteIdentity(results, passport::kTmid, passport::kAntmid, 2);
// }
//
// void UserCredentials::DeleteStmid(OperationResults& results) {
//  DeleteIdentity(results, passport::kStmid, passport::kAntmid, 3);
// }
//
// void UserCredentials::DeleteIdentity(OperationResults& results,
//                                         int packet_type,
//                                         int signer_type,
//                                         int index) {
//  passport::PacketType id_type(static_cast<passport::PacketType>(packet_type));
//  passport::PacketType sig_type(static_cast<passport::PacketType>(signer_type));
//  Identity name(passport_.IdentityPacketName(id_type, true));
//
//  Fob signer(passport_.SignaturePacketDetails(sig_type, true));
//  if (!remote_chunk_store_->Delete(ModifiableName(name),
//                                   [&, index] (bool result) {
//                                     OperationCallback(result, results, index);
//                                   },
//                                   signer)) {
//    LOG(kError) << "Failed to delete: " << index;
//    OperationCallback(false, results, index);
//  }
// }
//
// int UserCredentials::ChangePassword(const NonEmptyString& new_password) {
//
//  int result(CheckPasswordValidity(new_password));
//  if (result != kSuccess) {
//    LOG(kError) << "Incorrect input.";
//    return result;
//  }
//
//  // TODO(Alison) - fail if any other instances are logged in
//
//  NonEmptyString serialised_data_atlas;
//  result = SerialiseAndSetIdentity("", "", new_password.string(), serialised_data_atlas);
//  if (result != kSuccess) {
//    LOG(kError) << "Failure setting details of new session: " << result;
//    return result;
//  }
//
//  result = DoChangePasswordAdditions();
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to perform additions.";
//    return result;
//  }
//
//  result = DoChangePasswordRemovals();
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to perform removals.";
//    return result;
//  }
//
//  result = passport_.ConfirmIdentityPackets();
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to set new identity packets: " << result;
//    return kSetIdentityPacketsFailure;
//  }
//
//  session_.set_password(new_password);
//  session_.set_serialised_data_atlas(serialised_data_atlas);
//  session_.set_changed(false);
//
//  return kSuccess;
// }
//
// int UserCredentials::DoChangePasswordAdditions() {
//  std::vector<int> individual_results(4, utils::kPendingResult);
//  std::condition_variable condition_variable;
//  std::mutex mutex;
//  OperationResults new_results(mutex, condition_variable, individual_results);
//
//  ModifyMid(new_results);
//  ModifySmid(new_results);
//  StoreTmid(new_results);
//  StoreStmid(new_results);
//
//  int result(utils::WaitForResults(mutex, condition_variable, individual_results,
//                                   std::chrono::seconds(120)));
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to store new identity packets: Time out.";
//    return kChangePasswordFailure;
//  }
//
//  LOG(kInfo) << "MID: " << individual_results.at(0)
//             << ", SMID: " << individual_results.at(1)
//             << ", TMID: " << individual_results.at(2)
//             << ", STMID: " << individual_results.at(3);
//
//  result = AssessJointResult(individual_results);
//  if (result != kSuccess) {
//    LOG(kError) << "One of the operations for Identity Packets failed. "
//                << "Turn on INFO for feedback on which one. ";
//    return kChangePasswordFailure;
//  }
//
//  return kSuccess;
// }
//
// int UserCredentials::DoChangePasswordRemovals() {
//  // Delete old TMID, STMID
//  std::vector<int> individual_results(4, kSuccess);
//
//  std::condition_variable condition_variable;
//  std::mutex mutex;
//  individual_results[2] = utils::kPendingResult;
//  individual_results[3] = utils::kPendingResult;
//  OperationResults del_results(mutex, condition_variable, individual_results);
//  DeleteTmid(del_results);
//  DeleteStmid(del_results);
//
//  int result(utils::WaitForResults(mutex, condition_variable, individual_results,
//                                   std::chrono::seconds(120)));
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to store new identity packets: Time out.";
//    return kChangePasswordFailure;
//  }
//
//  LOG(kInfo) << "TMID: " << individual_results.at(2)
//             << ", STMID: " << individual_results.at(3);
//
//  result = AssessJointResult(individual_results);
//  if (result != kSuccess) {
//    LOG(kError) << "One of the operations for Identity Packets failed. "
//                << "Turn on INFO for feedback on which one. ";
//    return kChangePasswordFailure;
//  }
//
//  return kSuccess;
// }
//
// int UserCredentials::SerialiseAndSetIdentity(const std::string& keyword,
//                                                 const std::string& pin,
//                                                 const std::string& password,
//                                                 NonEmptyString& serialised_data_atlas) {
//  serialised_data_atlas = session_.SerialiseDataAtlas();
//  return passport_.SetIdentityPackets(keyword.empty() ? session_.keyword() :
//                                                        NonEmptyString(keyword),
//                                      pin.empty() ? StringToIntPin(session_.pin()) :
//                                                    StringToIntPin(NonEmptyString(pin)),
//                                      password.empty() ? session_.password() :
//                                                         NonEmptyString(password),
//                                      serialised_data_atlas,
//                                      session_.serialised_data_atlas());
// }
//
// int UserCredentials::DeleteUserCredentials() {
//  int result(DeleteOldIdentityPackets());
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to delete identity packets.";
//    return result;
//  }
//
//  result = DeleteSignaturePackets();
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to delete signature packets.";
//    return result;
//  }
//
//  return kSuccess;
// }
//
// int UserCredentials::DeleteSignaturePackets() {
//  std::vector<int> individual_results(4, utils::kPendingResult);
//  std::condition_variable condition_variable;
//  std::mutex mutex;
//  OperationResults results(mutex, condition_variable, individual_results);
//
//  // ANMID path
//  DeleteAnmid(results);
//  // ANSMID path
//  DeleteAnsmid(results);
//  // ANTMID path
//  DeleteAntmid(results);
//  // PMID path: PMID, MAID, ANMAID
//  DeletePmid(results);
//
//  int result(utils::WaitForResults(mutex, condition_variable, individual_results,
//                                   std::chrono::seconds(120)));
//  if (result != kSuccess) {
//    LOG(kError) << "Wait for results timed out: " << result;
//    LOG(kError) << "ANMID: " << individual_results.at(0)
//              << ", ANSMID: " << individual_results.at(1)
//              << ", ANTMID: " << individual_results.at(2)
//              << ", PMID path: " << individual_results.at(3);
//    return result;
//  }
//  LOG(kInfo) << "ANMID: " << individual_results.at(0)
//             << ", ANSMID: " << individual_results.at(1)
//             << ", ANTMID: " << individual_results.at(2)
//             << ", PMID path: " << individual_results.at(3);
//
//  result = AssessJointResult(individual_results);
//  if (result != kSuccess) {
//    LOG(kError) << "One of the operations for Anonymous Packets failed. "
//                << "Turn on INFO for feedback on which one. ";
//    return kDeleteSignaturePacketsFailure;
//  }
//
//  return kSuccess;
// }
//
// void UserCredentials::DeleteAnmid(OperationResults& results) {
//  Fob anmid(passport_.SignaturePacketDetails(passport::kAnmid, true));
//  DeleteSignaturePacket(anmid, results, 0);
// }
//
// void UserCredentials::DeleteAnsmid(OperationResults& results) {
//  Fob ansmid(passport_.SignaturePacketDetails(passport::kAnsmid, true));
//  DeleteSignaturePacket(ansmid, results, 1);
// }
//
// void UserCredentials::DeleteAntmid(OperationResults& results) {
//  Fob antmid(passport_.SignaturePacketDetails(passport::kAntmid, true));
//  DeleteSignaturePacket(antmid, results, 2);
// }
//
// void UserCredentials::DeletePmid(OperationResults& results) {
//  Fob pmid(passport_.SignaturePacketDetails(passport::kPmid, true));
//  Fob maid(passport_.SignaturePacketDetails(passport::kMaid, true));
//
//  if (!remote_chunk_store_->Delete(SignaturePacketName(pmid.identity),
//                                   [&] (bool result) { DeleteMaid(result, results, maid); },
//                                   maid)) {
//    LOG(kError) << "Failed to delete PMID.";
//    DeleteMaid(false, results, Fob());
//  }
// }
//
// void UserCredentials::DeleteMaid(bool result,
//                                     OperationResults& results,
//                                     const Fob& maid) {
//  if (!result) {
//    LOG(kError) << "Failed to delete PMID.";
//    OperationCallback(false, results, 3);
//    return;
//  }
//
//  Fob anmaid(passport_.SignaturePacketDetails(passport::kAnmaid, true));
//  if (!remote_chunk_store_->Delete(SignaturePacketName(maid.identity),
//                                   [&] (bool result) {
//                                     DeleteAnmaid(result, results, anmaid);
//                                   },
//                                   anmaid)) {
//    LOG(kError) << "Failed to delete MAID.";
//    DeleteAnmaid(false, results, Fob());
//  }
// }
//
// void UserCredentials::DeleteAnmaid(bool result,
//                                       OperationResults& results,
//                                       const Fob& anmaid) {
//  if (!result) {
//    LOG(kError) << "Failed to delete MAID.";
//    OperationCallback(false, results, 3);
//    return;
//  }
//
//  DeleteSignaturePacket(anmaid, results, 3);
// }
//
// void UserCredentials::DeleteSignaturePacket(const Fob& packet,
//                                                OperationResults& results,
//                                                int index) {
//  if (!remote_chunk_store_->Delete(SignaturePacketName(packet.identity),
//                                   [&, index] (bool result) {
//                                     OperationCallback(result, results, index);
//                                   },
//                                   packet)) {
//    LOG(kError) << "Failed to delete packet: " << index;
//    OperationCallback(false, results, index);
//  }
// }
//
//
// void UserCredentials::LogoutCompletedArrived(const std::string& session_marker) {
//  std::lock_guard<std::mutex> lock(completed_log_out_mutex_);
//  completed_log_out_message_ = session_marker;
//  completed_log_out_ = true;
//  completed_log_out_conditional_.notify_one();
// }
//
// bool UserCredentials::IsOwnSessionTerminationMessage(const std::string& session_marker) {
//  return pending_session_marker_ == session_marker;
// }
//
// void UserCredentials::CheckInputs(const Keyword& keyword, const Pin& pin, const Password& password) { // NOLINT
//  CheckKeywordValidity(keyword);
//  CheckPinValidity(pin);
//  CheckPasswordValidity(password);
//  return;
// }
//
// void UserCredentials::CheckKeywordValidity(const Keyword& keyword) {
//  if (!AcceptableWordSize(keyword.data))
//    ThrowError(LifeStuffErrors::kKeywordSizeInvalid);
//  if (!AcceptableWordPattern(keyword.data))
//    ThrowError(LifeStuffErrors::kKeywordPatternInvalid);
//  return;
// }
//
// void UserCredentials::CheckPinValidity(const Pin& pin) {
//  if (pin.data.string().size() != kPinSize)
//    ThrowError(LifeStuffErrors::kPinSizeInvalid);
//  if (boost::lexical_cast<int>(pin.data.string()) < 1)
//    ThrowError(LifeStuffErrors::kPinPatternInvalid);
//  return;
// }
//
// void UserCredentials::CheckPasswordValidity(const Password& password) {
//  if (!AcceptableWordSize(password.data))
//    ThrowError(LifeStuffErrors::kPasswordSizeInvalid);
//  if (!AcceptableWordPattern(password.data))
//    ThrowError(LifeStuffErrors::kPasswordPatternInvalid);
//  return;
// }
//
// bool UserCredentials::AcceptableWordSize(const Identity& word) {
//  return word.string().size() >= kMinWordSize && word.string().size() <= kMaxWordSize;
// }
//
// bool UserCredentials::AcceptableWordPattern(const Identity& word) {
//  boost::regex space(" ");
//  return !boost::regex_search(word.string().begin(), word.string().end(), space);
// }
//
// void UserCredentials::GetUserInfo(const Keyword& keyword,
//                                  const Pin& pin,
//                                  const Password& password,
//                                  const bool& compare_names,
//                                  std::string& mid_packet,
//                                  std::string& smid_packet) {
//  if (compare_names) {
//    std::string re_mid_packet;
//    std::string re_smid_packet;
//
//    uint32_t int_pin(StringToIntPin(pin));
//    priv::ChunkId mid_name(ModifiableName(Identity(passport::MidName(keyword, int_pin, false))));
//    priv::ChunkId smid_name(ModifiableName(Identity(passport::MidName(keyword, int_pin, false))));
//
//    boost::thread mid_thread([&] { re_mid_packet = remote_chunk_store_->Get(mid_name, Fob()); });  // NOLINT (Dan)
//    boost::thread smid_thread([&] { re_smid_packet = remote_chunk_store_->Get(smid_name, Fob()); });  // NOLINT (Dan)
//
//    mid_thread.join();
//    smid_thread.join();
//
//    if (re_mid_packet.empty()) {
//      LOG(kError) << "No MID found.";
//      return kIdPacketNotFound;
//    }
//    if (re_smid_packet.empty()) {
//      LOG(kError) << "No SMID found.";
//      return kIdPacketNotFound;
//    }
//
//    if (mid_packet == re_mid_packet && smid_packet == re_smid_packet) {
//      LOG(kInfo) << "MID and SMID are up to date.";
//      return kSuccess;
//    }
//  }
//
//  // Obtain MID, TMID
//  int mid_tmid_result(kSuccess);
//  std::string tmid_packet;
//  boost::thread mid_tmid_thread([&] {
//                                  GetIdAndTemporaryId(keyword,
//                                                      pin,
//                                                      password,
//                                                      false,
//                                                      &mid_tmid_result,
//                                                      &mid_packet,
//                                                      &tmid_packet);
//                                });
//  // Obtain SMID, STMID
//  int smid_stmid_result(kSuccess);
//  std::string stmid_packet;
//  boost::thread smid_stmid_thread([&] {
//                                    GetIdAndTemporaryId(keyword,
//                                                        pin,
//                                                        password,
//                                                        true,
//                                                        &smid_stmid_result,
//                                                        &smid_packet,
//                                                        &stmid_packet);
//                                  });
//
//  // Wait for them to finish
//  mid_tmid_thread.join();
//  smid_stmid_thread.join();
//  LOG(kInfo) << "mid_tmid_result: " << mid_tmid_result << " - "
//             << std::boolalpha << mid_packet.empty() << " - " << tmid_packet.empty();
//  LOG(kInfo) << "smid_stmid_result: " << smid_stmid_result << " - "
//             << std::boolalpha << smid_packet.empty() << " - " << stmid_packet.empty();
//
//  // Evaluate MID & TMID
//  if (mid_tmid_result == kIdPacketNotFound && smid_stmid_result == kIdPacketNotFound) {
//    LOG(kInfo) << "User doesn't exist: " << keyword.string() << ", " << pin.string();
//    return kLoginUserNonExistence;
//  }
//
//  if (mid_tmid_result == kCorruptedPacket && smid_stmid_result == kCorruptedPacket) {
//    LOG(kError) << "Account corrupted. Should never happen: "
//                << keyword.string() << ", " << pin.string();
//    return kLoginAccountCorrupted;
//  }
//
//  int result(HandleSerialisedDataMaps(keyword, pin, password, tmid_packet, stmid_packet));
//  if (result != kSuccess) {
//    if (result == kTryAgainLater) {
//      return kLoginSessionNotYetSaved;
//    } else if (result == kUsingNextToLastSession) {
//      return kLoginUsingNextToLastSession;
//    } else {
//      LOG(kError) << "Failed to initialise session: " << result;
//      return kLoginAccountCorrupted;
//    }
//  }
//
//  return kSuccess;
// }

}  // namespace lifestuff
}  // namespace maidsafe
