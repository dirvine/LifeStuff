/***************************************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use.  The use of this code is governed by the licence file licence.txt found in the root of    *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit         *
 *  written permission of the board of directors of MaidSafe.net.                                  *
 **************************************************************************************************/

#include "maidsafe/lifestuff/detail/client_maid.h"

#include "boost/regex.hpp"
#include "boost/filesystem/path.hpp"
#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/nfs/client_utils.h"

#include "maidsafe/lifestuff/detail/utils.h"

namespace maidsafe {
namespace lifestuff {

ClientMaid::ClientMaid(Session& session, const Slots& slots)
  : slots_(CheckSlots(slots)),
    session_(session),
    client_controller_(slots_.update_available),
    user_storage_(),
    routing_handler_(),
    client_nfs_() {
}

ReturnCode ClientMaid::CreateUser(const Keyword& keyword,
                                  const Pin& pin,
                                  const Password& password,
                                  const boost::filesystem::path& vault_path,
                                  ReportProgressFunction& report_progress) {
  bool fobs_confirmed(false), drive_mounted(false);
  try {
    ReturnCode result(kSuccess);
    report_progress(kCreateUser, kCreatingUserCredentials);
    session_.passport().CreateFobs();
    Maid maid(session_.passport().Get<Maid>(false));
    Pmid pmid(session_.passport().Get<Pmid>(false));
    try {
      report_progress(kCreateUser, kJoiningNetwork);
      JoinNetwork(maid);
    }
    catch(...) {
      return kNetworkFailure;
    }
    result = PutFreeFobs();
    if (result != kSuccess)
      return result;
    report_progress(kCreateUser, kInitialisingClientComponents);
    client_nfs_.reset(new ClientNfs(routing_handler_->routing(), maid));
    report_progress(kCreateUser, kCreatingVault);
    session_.set_vault_path(vault_path);
    client_controller_.StartVault(pmid, maid.name(), vault_path);
    RegisterPmid(maid, pmid);
    report_progress(kCreateUser, kCreatingUserCredentials);
    session_.passport().ConfirmFobs();
    fobs_confirmed = true;
    result = PutPaidFobs();
    if (result != kSuccess)
      return result;
    session_.set_unique_user_id(Identity(RandomAlphaNumericString(64)));
    MountDrive();
    drive_mounted = true;
    UnMountDrive();
    drive_mounted = false;
    session_.set_initialised();
    report_progress(kCreateUser, kStoringUserCredentials);
    PutSession(keyword, pin, password);
  }
  catch(...) {
    UnCreateUser(fobs_confirmed, drive_mounted);
    return kStartupFailure;
  }
  return kSuccess;
}

ReturnCode ClientMaid::LogIn(const Keyword& keyword,
                             const Pin& pin,
                             const Password& password,
                             ReportProgressFunction& report_progress) {
   slots_.network_health(10);
   slots_.operations_pending(true);
   report_progress(kLogin, kJoiningNetwork);
   maidsafe::Sleep(boost::posix_time::seconds(2));
   report_progress(kLogin, kInitialisingClientComponents);
   maidsafe::Sleep(boost::posix_time::seconds(2));
   report_progress(kLogin, kRetrievingUserCredentials);
   maidsafe::Sleep(boost::posix_time::seconds(2));
   slots_.update_available("C:\\Program Files (x86)\\CamStudio 2.7\\Videos\\Blah.exe");
   using namespace maidsafe::passport::detail;
   if(SafeString(keyword.string()) == "abcde" && SafeString(pin.string()) == "1111" && SafeString(password.string()) == "12345")
    return kSuccess;
   return kNetworkFailure;

  /*try {
    Anmaid anmaid;
    Maid maid(anmaid);
    try {
      report_progress(kJoiningNetwork);
      JoinNetwork(maid);
    }
    catch(...) {
      return kNetworkFailure;
    }
    report_progress(kInitialisingClientComponents);
    client_nfs_.reset(new ClientNfs(routing_handler_->routing(), maid));
    report_progress(kRetrievingUserCredentials);
    GetSession(keyword, pin, password);
    maid = session_.passport().Get<Maid>(true);
    Pmid pmid(session_.passport().Get<Pmid>(true));
    try {
      report_progress(kJoiningNetwork);
      JoinNetwork(maid);
    }
    catch(...) {
      return kNetworkFailure;
    }
    report_progress(kInitialisingClientComponents);
    client_nfs_.reset(new ClientNfs(routing_handler_->routing(), maid));
    report_progress(kStartingVault);
    client_controller_.StartVault(pmid, maid.name(), session_.vault_path());
  }
  catch(...) {
    // client_controller_.StopVault(); get params!!!!!!!!!
    client_nfs_.reset();
    return kStartupFailure;
  }*/
}

ReturnCode ClientMaid::LogOut() {
  //  client_controller_.StopVault(  );  parameters???
  return UnMountDrive();
}

ReturnCode ClientMaid::MountDrive() {
  try {
    user_storage_.MountDrive(*client_nfs_, session_);
  }
  catch(...) {
    return kMountFailed;
  }
  return kSuccess;
}

ReturnCode ClientMaid::UnMountDrive() {
  try {
    user_storage_.UnMountDrive(session_);
  }
  catch(...) {
    return kUnmountFailed;
  }
  return kSuccess;
}

void ClientMaid::ChangeKeyword(const Keyword& old_keyword,
                               const Keyword& new_keyword,
                               const Pin& pin,
                               const Password& password) {
  PutSession(new_keyword, pin, password);
  DeleteSession(old_keyword, pin);
  return;
}

void ClientMaid::ChangePin(const Keyword& keyword,
                           const Pin& old_pin,
                           const Pin& new_pin,
                           const Password& password) {
  PutSession(keyword, new_pin, password);
  DeleteSession(keyword, old_pin);
  return;
}

void ClientMaid::ChangePassword(const Keyword& keyword,
                                const Pin& pin,
                                const Password& new_password) {
  PutSession(keyword, pin, new_password);
  return;
}

boost::filesystem::path ClientMaid::mount_path() {
  return user_storage_.mount_path();
}

boost::filesystem::path ClientMaid::owner_path() {
  return user_storage_.owner_path();
}

const Slots& ClientMaid::CheckSlots(const Slots& slots) {
  if (!slots.update_available)
    throw std::invalid_argument("missing update_available function");
  if (!slots.network_health)
    throw std::invalid_argument("missing network_health function");
  if (!slots.operations_pending)
    throw std::invalid_argument("missing operations_pending function");
  return slots;
}

void ClientMaid::PutSession(const Keyword& keyword, const Pin& pin, const Password& password) {
  NonEmptyString serialised_session(session_.Serialise());
  passport::EncryptedSession encrypted_session(passport::EncryptSession(
                                                  keyword, pin, password, serialised_session));
  Tmid tmid(encrypted_session, session_.passport().Get<Antmid>(true));
  passport::EncryptedTmidName encrypted_tmid_name(passport::EncryptTmidName(
                                                    keyword, pin, tmid.name()));
  Mid::name_type mid_name(Mid::GenerateName(keyword, pin));
  Mid mid(mid_name, encrypted_tmid_name, session_.passport().Get<Anmid>(true));
  PutFob<Tmid>(tmid);
  PutFob<Mid>(mid);
}

void ClientMaid::DeleteSession(const Keyword& keyword, const Pin& pin) {
  Mid::name_type mid_name(Mid::GenerateName(keyword, pin));
  std::future<Mid> mid_future(maidsafe::nfs::Get<Mid>(*client_nfs_, mid_name));
  Mid mid(mid_future.get());
  passport::EncryptedTmidName encrypted_tmid_name(mid.encrypted_tmid_name());
  Tmid::name_type tmid_name(passport::DecryptTmidName(keyword, pin, encrypted_tmid_name));
  DeleteFob<Tmid>(tmid_name);
  DeleteFob<Mid>(mid_name);
}

void ClientMaid::GetSession(const Keyword& keyword, const Pin& pin, const Password& password) {
  Mid::name_type mid_name(Mid::GenerateName(keyword, pin));
  std::future<Mid> mid_future(maidsafe::nfs::Get<Mid>(*client_nfs_, mid_name));
  Mid mid(mid_future.get());
  passport::EncryptedTmidName encrypted_tmid_name(mid.encrypted_tmid_name());
  Tmid::name_type tmid_name(passport::DecryptTmidName(keyword, pin, encrypted_tmid_name));
  std::future<Tmid> tmid_future(maidsafe::nfs::Get<Tmid>(*client_nfs_, tmid_name));
  Tmid tmid(tmid_future.get());
  passport::EncryptedSession encrypted_session(tmid.encrypted_session());
  NonEmptyString serialised_session(passport::DecryptSession(
                                      keyword, pin, password, encrypted_session));
  session_.Parse(serialised_session);
  session_.set_initialised();
}

void ClientMaid::JoinNetwork(const Maid& maid) {
  PublicKeyRequestFunction public_key_request(
      [this](const NodeId& node_id, const GivePublicKeyFunctor& give_key) {
        PublicKeyRequest(node_id, give_key);
      });
  routing_handler_.reset(new RoutingHandler(maid, public_key_request));
  EndPointVector endpoints;
  client_controller_.GetBootstrapNodes(endpoints);
  routing_handler_->Join(endpoints);
}

void ClientMaid::RegisterPmid(const Maid& maid, const Pmid& pmid) {
  PmidRegistration pmid_registration(maid, pmid, false);
  PmidRegistration::serialised_type serialised_pmid_registration(pmid_registration.Serialise());
  client_nfs_->RegisterPmid(serialised_pmid_registration,
                      [this](std::string response) {
                        NonEmptyString serialised_response(response);
                        nfs::Reply::serialised_type serialised_reply(serialised_response);
                        nfs::Reply reply(serialised_reply);
                        if (!reply.IsSuccess())
                          ThrowError(VaultErrors::failed_to_handle_request);
                        this->slots_.network_health(std::stoi(reply.data().string()));
                      });
  return;
}

void ClientMaid::UnregisterPmid(const Maid& maid, const Pmid& pmid) {
  PmidRegistration pmid_unregistration(maid, pmid, true);
  PmidRegistration::serialised_type serialised_pmid_unregistration(pmid_unregistration.Serialise());
  client_nfs_->UnregisterPmid(serialised_pmid_unregistration, [](std::string) {});
  return;
}

void ClientMaid::UnCreateUser(bool fobs_confirmed, bool drive_mounted) {
  Maid maid(session_.passport().Get<Maid>(fobs_confirmed));
  Pmid pmid(session_.passport().Get<Pmid>(fobs_confirmed));
  UnregisterPmid(maid, pmid);
  // client_controller_.StopVault(); get params!!!!!!!!!
  client_nfs_.reset();
  if (drive_mounted)
    try { UnMountDrive(); } catch(...) { /* consume exception */ }
  return;
}

template<typename Fob>
void ClientMaid::PutFob(const Fob& fob) {
  ReplyFunction reply([this] (maidsafe::nfs::Reply reply) {
                        if (!reply.IsSuccess()) {
                          ThrowError(LifeStuffErrors::kStoreFailure);
                        }
                      });
  passport::Pmid::name_type pmid_name(session_.passport().Get<Pmid>(true).name());
  maidsafe::nfs::Put<Fob>(*client_nfs_, fob, pmid_name, 3, reply);
  return;
}

template<typename Fob>
void ClientMaid::DeleteFob(const typename Fob::name_type& fob_name) {
  ReplyFunction reply([this] (maidsafe::nfs::Reply reply) {
                        if (!reply.IsSuccess()) {
                          ThrowError(LifeStuffErrors::kDeleteFailure);
                        }
                      });
  maidsafe::nfs::Delete<Fob>(*client_nfs_, fob_name, 3, reply);
  return;
}

template<typename Fob>
Fob ClientMaid::GetFob(const typename Fob::name_type& fob_name) {
  std::future<Fob> fob_future(maidsafe::nfs::Get<Fob>(*client_nfs_, fob_name));
  return fob_future.get();
}

ReturnCode ClientMaid::PutFreeFobs() {
  ReturnCode result(kSuccess);
  ReplyFunction reply([this, &result] (maidsafe::nfs::Reply reply) {
                        if (!reply.IsSuccess()) {
                          result = kStartupFailure;
                        }
                      });
  detail::PutFobs<Free>()(*client_nfs_, session_.passport(), reply);
  return result;
}

ReturnCode ClientMaid::PutPaidFobs() {
  ReturnCode result(kSuccess);
  ReplyFunction reply([this, &result] (maidsafe::nfs::Reply reply) {
                        if (!reply.IsSuccess()) {
                          result = kStartupFailure;
                        }
                      });
  detail::PutFobs<Paid>()(*client_nfs_, session_.passport(), reply);
  return result;
}

void ClientMaid::PublicKeyRequest(const NodeId& node_id, const GivePublicKeyFunctor& give_key) {
  if (client_nfs_) {
    typedef passport::PublicPmid PublicPmid;
    PublicPmid::name_type pmid_name(Identity(node_id.string()));
    std::future<PublicPmid> pmid_future(maidsafe::nfs::Get<PublicPmid>(*client_nfs_, pmid_name));
    give_key(pmid_future.get().public_key());
  } else {
    ThrowError(CommonErrors::uninitialised);
  }
  return;
}

}  // lifestuff
}  // maidsafe
