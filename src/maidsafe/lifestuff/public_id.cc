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

#include "maidsafe/lifestuff/public_id.h"

#include <vector>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/data_types_pb.h"
#include "maidsafe/lifestuff/lifestuff_messages_pb.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/maidsafe.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/store_components/packet_manager.h"
#include "maidsafe/lifestuff/utils.h"

namespace arg = std::placeholders;


namespace maidsafe {

namespace lifestuff {

namespace {

void SendContactInfoCallback(const int &response,
                             boost::mutex *mutex,
                             boost::condition_variable *cond_var,
                             int *result) {
  if (!mutex || !cond_var || !result)
    return;
  boost::mutex::scoped_lock lock(*mutex);
  *result = response;
  cond_var->notify_one();
}

std::string AnmpidName(const passport::SelectableIdentityData &data) {
  return std::get<0>(data.at(0));
}

std::string AnmpidValue(const passport::SelectableIdentityData &data,
                        const std::string &public_username) {
  std::string public_key;
  asymm::EncodePublicKey(std::get<1>(data.at(0)), &public_key);
  GenericPacket packet;
  packet.set_data(public_key);
  packet.set_signature(std::get<2>(data.at(0)));
  packet.set_type(DataWrapper::kAnmpid);
  packet.set_signing_id(public_username);
  return packet.SerializeAsString();
}

std::string MpidName(const passport::SelectableIdentityData &data) {
  return std::get<0>(data.at(1));
}

std::string MpidValue(const passport::SelectableIdentityData &data,
                      const std::string &public_username) {
  std::string public_key;
  asymm::EncodePublicKey(std::get<1>(data.at(1)), &public_key);
  GenericPacket packet;
  packet.set_data(public_key);
  packet.set_signature(std::get<2>(data.at(1)));
  packet.set_type(DataWrapper::kMpid);
  packet.set_signing_id(public_username);
  return packet.SerializeAsString();
}

std::string MmidName(const passport::SelectableIdentityData &data) {
  return std::get<0>(data.at(2));
}

std::string MmidValue(const passport::SelectableIdentityData &data,
                      const std::string &public_username) {
  std::string public_key;
  asymm::EncodePublicKey(std::get<1>(data.at(2)), &public_key);
  MMID mmid;
  mmid.set_public_key(public_key);
  mmid.set_signature(std::get<2>(data.at(2)));
  GenericPacket packet;
  packet.set_data(mmid.SerializeAsString());
  packet.set_signature(mmid.signature());
  packet.set_type(DataWrapper::kMmid);
  packet.set_signing_id(public_username);
  return packet.SerializeAsString();
}

std::string MsidName(const std::string &public_username) {
  return crypto::Hash<crypto::SHA512>(public_username);
}

std::string MsidValue(const passport::SelectableIdentityData &data,
                      const std::string &public_username,
                      bool accepts_new_contacts) {
  std::string public_key;
  asymm::EncodePublicKey(std::get<1>(data.at(1)), &public_key);
//  DLOG(ERROR) << "PublicId: " << EncodeToBase32(public_key);
  MSID msid;
  msid.set_public_key(public_key);
  msid.set_signature(std::get<2>(data.at(1)));
  msid.set_accepts_new_contacts(accepts_new_contacts);
  GenericPacket packet;
  packet.set_data(msid.SerializeAsString());
  packet.set_signature(msid.signature());
  packet.set_type(DataWrapper::kMsid);
  packet.set_signing_id(public_username);
  return packet.SerializeAsString();
}

}  // namespace

PublicId::PublicId(std::shared_ptr<PacketManager> packet_manager,
                   std::shared_ptr<Session> session,
                   boost::asio::io_service &asio_service)  // NOLINT (Fraser)
    : packet_manager_(packet_manager),
      session_(session),
      asio_service_(asio_service),
      get_new_contacts_timer_(asio_service),
      new_contact_signal_(new NewContactSignal) {}

PublicId::~PublicId() {
  StopCheckingForNewContacts();
}

int PublicId::StartCheckingForNewContacts(bptime::seconds interval) {
  std::vector<passport::SelectableIdData> selectables;
  session_->passport_->SelectableIdentitiesList(&selectables);
  if (selectables.empty()) {
    DLOG(ERROR) << "No public username set";
    return kNoPublicIds;
  }
  get_new_contacts_timer_.expires_from_now(interval);
  get_new_contacts_timer_.async_wait(std::bind(&PublicId::GetNewContacts,
                                               this,
                                               interval,
                                               std::placeholders::_1));
  return kSuccess;
}

void PublicId::StopCheckingForNewContacts() {
  get_new_contacts_timer_.cancel();
}

int PublicId::CreatePublicId(const std::string &public_username,
                             bool accepts_new_contacts) {
  if (public_username.empty()) {
    DLOG(ERROR) << "Public ID name empty";
    return kPublicIdEmpty;
  }

  // Check chosen name is available
  if (!packet_manager_->KeyUnique(MsidName(public_username))) {
    DLOG(ERROR) << "Public ID with name " << public_username << " unavailable";
    return kPublicIdExists;
  }

  // Create packets (pending) in passport
  int result(session_->passport_->CreateSelectableIdentity(public_username));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to create Public ID with name " << public_username;
    return result;
  }

  passport::SelectableIdentityData data;
  // Retrieves ANMPID, MPID, and MMID's <name, value, signature>
  result = session_->passport_->GetSelectableIdentityData(public_username,
                                                          false,
                                                          &data);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get own public ID data: " << result;
    return kGetPublicIdError;
  }
  BOOST_ASSERT(data.size() == 3U);

  // Store packets
  boost::mutex mutex;
  boost::condition_variable cond_var;
  int anmpid_result(kPendingResult), mpid_result(kPendingResult),
      mmid_result(kPendingResult), msid_result(kPendingResult);
  packet_manager_->StorePacket(MsidName(public_username),
                               MsidValue(data,
                                         public_username,
                                         accepts_new_contacts),
                               std::bind(&SendContactInfoCallback, arg::_1,
                                         &mutex, &cond_var, &msid_result));
  packet_manager_->StorePacket(AnmpidName(data),
                               AnmpidValue(data, public_username),
                               std::bind(&SendContactInfoCallback, arg::_1,
                                         &mutex, &cond_var, &anmpid_result));
  packet_manager_->StorePacket(MpidName(data),
                               MpidValue(data, public_username),
                               std::bind(&SendContactInfoCallback, arg::_1,
                                         &mutex, &cond_var, &mpid_result));
  packet_manager_->StorePacket(MmidName(data),
                               MmidValue(data, public_username),
                               std::bind(&SendContactInfoCallback, arg::_1,
                                         &mutex, &cond_var, &mmid_result));

  try {
    boost::mutex::scoped_lock lock(mutex);
    if (!cond_var.timed_wait(lock,
                             bptime::seconds(30),
                             [&]()->bool {
                               return anmpid_result != kPendingResult &&
                                      mpid_result != kPendingResult &&
                                      mmid_result != kPendingResult &&
                                      msid_result != kPendingResult;
                             })) {
      DLOG(ERROR) << "Timed out storing packets.";
      return kPublicIdTimeout;
    }
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Failed to store packets: " << e.what();
    return kPublicIdException;
  }
  if (anmpid_result != kSuccess || mpid_result != kSuccess ||
      mmid_result != kSuccess || msid_result != kSuccess) {
    DLOG(ERROR) << "Failed to store packets.  ANMPID: " << anmpid_result
                << "   MPID: " << mpid_result << "   MMID: " << mmid_result
                << "   MSID: " << msid_result;
    return kStorePublicIdFailure;
  }

  // Confirm packets as stored
  result = session_->passport_->ConfirmSelectableIdentity(public_username);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to confirm Public ID with name " << public_username;
    return result;
  }
  return kSuccess;
}

int PublicId::SendContactInfo(const std::string &public_username,
                              const std::string &recipient_public_username) {
  // Get recipient's public key
  asymm::PublicKey recipient_public_key;
  int result(GetValidatedPublicKey(recipient_public_username,
                                   packet_manager_,
                                   &recipient_public_key));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get public key for " << recipient_public_username;
    return result;
  }

  // Get our MMID name, and MPID private key
  passport::SelectableIdentityData data;
  // Retrieves ANMPID, MPID, and MMID's <name, value, signature>
  result = session_->passport_->GetSelectableIdentityData(public_username,
                                                          true,
                                                          &data);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get own public ID data: " << result;
    return kGetPublicIdError;
  }
  BOOST_ASSERT(data.size() == 3U);

  std::vector<passport::SelectableIdData> selectables;
  session_->passport_->SelectableIdentitiesList(&selectables);
  passport::SelectableIdData selectable_id;
  auto it(std::find_if(selectables.begin(),
                       selectables.end(),
                       [public_username]
                           (const passport::SelectableIdData &selectable) {
                         return (std::get<0>(selectable) == public_username);
                       }));

  if (it == selectables.end()) {
    DLOG(ERROR) << "Failed to get own MPID private key";
    return kGetPublicIdError;
  }

  // Create MCID, encrypted for recipient
  MCID mcid;
  std::string mmid_name(std::get<0>(data.at(2)));
  mcid.set_mmid(mmid_name);
  mcid.set_public_username(public_username);
  asymm::Signature sig;
  result = asymm::Sign(mmid_name + public_username, std::get<2>(*it), &sig);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to sign MCID data: " << result;
    return kSigningError;
  }
  mcid.set_signature(sig);

  BOOST_ASSERT(!mcid.SerializeAsString().empty());

  std::string encrypted_mcid;
  result = asymm::Encrypt(mcid.SerializeAsString(),
                          recipient_public_key,
                          &encrypted_mcid);

  // Store encrypted MCID at recipient's MPID's name
  boost::mutex mutex;
  boost::condition_variable cond_var;
  result = kPendingResult;
  VoidFuncOneInt callback(std::bind(&SendContactInfoCallback, arg::_1, &mutex,
                                    &cond_var, &result));

  GenericPacket gp;
  gp.set_data(encrypted_mcid);
  gp.set_signature(sig);
  gp.set_type(DataWrapper::kMsid);
  packet_manager_->StorePacket(
      crypto::Hash<crypto::SHA512>(recipient_public_username),
      gp.SerializeAsString(),
      callback);

  try {
    boost::mutex::scoped_lock lock(mutex);
    if (!cond_var.timed_wait(lock,
                             bptime::seconds(30),
                             [&result]()->bool {
                               return result != kPendingResult;
                             })) {
      DLOG(ERROR) << "Timed out storing packet.";
      return kPublicIdTimeout;
    }
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Failed to store packet: " << e.what();
    return kPublicIdException;
  }
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to store packet.  Result: " << result;
    return kSendContactInfoFailure;
  }

  return kSuccess;
}

int PublicId::DeletePublicId(const std::string &/*public_username*/) {
  return kSuccess;
}

PublicId::NewContactSignalPtr PublicId::new_contact_signal() const {
  return new_contact_signal_;
}

void PublicId::GetNewContacts(const bptime::seconds &interval,
                              const boost::system::error_code &error_code) {
  if (error_code) {
    if (error_code != ba::error::operation_aborted) {
      DLOG(ERROR) << "Refresh timer error: " << error_code.message();
    } else {
      return;
    }
  }

  std::vector<passport::SelectableIdData> selectables;
  session_->passport_->SelectableIdentitiesList(&selectables);
  for (auto it(selectables.begin()); it != selectables.end(); ++it) {
    std::vector<std::string> mpid_values;
    int result(packet_manager_->GetPacket(
                   crypto::Hash<crypto::SHA512>(std::get<0>(*it)),
                   &mpid_values));
    if (result == kSuccess) {
      ProcessRequests(*it, mpid_values);
    } else {
      DLOG(ERROR) << "Failed to get MPID contents for " << std::get<0>(*it);
    }
  }

  get_new_contacts_timer_.expires_at(get_new_contacts_timer_.expires_at() +
                                     interval);
  get_new_contacts_timer_.async_wait(std::bind(&PublicId::GetNewContacts,
                                               this,
                                               interval,
                                               std::placeholders::_1));
}

void PublicId::ProcessRequests(const passport::SelectableIdData &data,
                               const std::vector<std::string> &mpid_values) {
  for (auto it(mpid_values.begin()); it != mpid_values.end(); ++it) {
    std::string decrypted_mcid;
    int n(asymm::Decrypt(*it, std::get<2>(data), &decrypted_mcid));
    if (n != kSuccess || decrypted_mcid.empty()) {
      DLOG(ERROR) << "Failed to decrypt message: " << n;
      continue;
    }

    MCID mcid;
    if (!mcid.ParseFromString(decrypted_mcid)) {
      DLOG(ERROR) << "Failed to parse MCID";
      continue;
    }

    if ((*new_contact_signal_)(mcid.public_username())) {
      // add contact to contacts
      session_->contacts_handler()->AddContact(mcid.public_username(), "", "",
                                               "", "", '\0', 0, 0, "", '\0', 0,
                                               0);
    }
    // Delete MCID from network - do nothing in callback
    packet_manager_->DeletePacket(
        crypto::Hash<crypto::SHA512>(std::get<0>(data)),
        *it,
        [](int /*result*/) {});
  }
}


}  // namespace lifestuff

}  // namespace maidsafe
