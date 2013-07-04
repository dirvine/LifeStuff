/* Copyright 2013 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

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

void ClientMaid::CreateUser(const Keyword& keyword,
                            const Pin& pin,
                            const Password& password,
                            const boost::filesystem::path& vault_path,
                            ReportProgressFunction& report_progress) {
  bool fobs_confirmed(false), drive_mounted(false);
  try {
    report_progress(kCreateUser, kCreatingUserCredentials);
    session_.passport().CreateFobs();
    Maid maid(session_.passport().Get<Maid>(false));
    Pmid pmid(session_.passport().Get<Pmid>(false));
    report_progress(kCreateUser, kJoiningNetwork);
    JoinNetwork(maid);
    PutFreeFobs();
    report_progress(kCreateUser, kInitialisingClientComponents);
    client_nfs_.reset(new ClientNfs(routing_handler_->routing(), maid));
    report_progress(kCreateUser, kCreatingVault);
    session_.set_vault_path(vault_path);
    client_controller_.StartVault(pmid, maid.name(), vault_path);
    RegisterPmid(maid, pmid);
    report_progress(kCreateUser, kCreatingUserCredentials);
    session_.passport().ConfirmFobs();
    fobs_confirmed = true;
    PutPaidFobs();
    session_.set_unique_user_id(Identity(RandomAlphaNumericString(64)));
    MountDrive();
    drive_mounted = true;
    UnMountDrive();
    drive_mounted = false;
    session_.set_initialised();
    report_progress(kCreateUser, kStoringUserCredentials);
    PutSession(keyword, pin, password);
  }
  catch(const std::exception& e) {
    UnCreateUser(fobs_confirmed, drive_mounted);
    boost::throw_exception(e);
  }
  return;
}

void ClientMaid::LogIn(const Keyword& keyword,
                       const Pin& pin,
                       const Password& password,
                       ReportProgressFunction& report_progress) {
  try {
    Anmaid anmaid;
    Maid maid(anmaid);
    report_progress(kLogin, kJoiningNetwork);
    JoinNetwork(maid);
    report_progress(kLogin, kInitialisingClientComponents);
    client_nfs_.reset(new ClientNfs(routing_handler_->routing(), maid));
    report_progress(kLogin, kRetrievingUserCredentials);
    GetSession(keyword, pin, password);
    maid = session_.passport().Get<Maid>(true);
    Pmid pmid(session_.passport().Get<Pmid>(true));
    report_progress(kLogin, kJoiningNetwork);
    JoinNetwork(maid);
    report_progress(kLogin, kInitialisingClientComponents);
    client_nfs_.reset(new ClientNfs(routing_handler_->routing(), maid));
    report_progress(kLogin, kStartingVault);
    client_controller_.StartVault(pmid, maid.name(), session_.vault_path());
  }
  catch(const std::exception& e) {
    // client_controller_.StopVault(); get params!!!!!!!!!
    client_nfs_.reset();
    boost::throw_exception(e);
  }
  return;
}

void ClientMaid::LogOut() {
  //  client_controller_.StopVault(  );  parameters???
  UnMountDrive();
}

void ClientMaid::MountDrive() {
  user_storage_.MountDrive(*client_nfs_, session_);
  return;
}

void ClientMaid::UnMountDrive() {
  user_storage_.UnMountDrive(session_);
  return;
}

void ClientMaid::ChangeKeyword(const Keyword& old_keyword,
                               const Keyword& new_keyword,
                               const Pin& pin,
                               const Password& password,
                               ReportProgressFunction& report_progress) {
  report_progress(kChangeKeyword, kStoringUserCredentials);
  PutSession(new_keyword, pin, password);
  DeleteSession(old_keyword, pin);
  return;
}

void ClientMaid::ChangePin(const Keyword& keyword,
                           const Pin& old_pin,
                           const Pin& new_pin,
                           const Password& password,
                           ReportProgressFunction& report_progress) {
  report_progress(kChangePin, kStoringUserCredentials);
  PutSession(keyword, new_pin, password);
  DeleteSession(keyword, old_pin);
  return;
}

void ClientMaid::ChangePassword(const Keyword& keyword,
                                const Pin& pin,
                                const Password& new_password,
                                ReportProgressFunction& report_progress) {
  report_progress(kChangePassword, kStoringUserCredentials);
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
    ThrowError(CommonErrors::uninitialised);
  if (!slots.network_health)
    ThrowError(CommonErrors::uninitialised);
  if (!slots.operations_pending)
    ThrowError(CommonErrors::uninitialised);
  return slots;
}

void ClientMaid::PutSession(const Keyword& keyword, const Pin& pin, const Password& password) {
  NonEmptyString serialised_session(session_.Serialise());
  passport::EncryptedSession encrypted_session(passport::EncryptSession(
                                                  keyword, pin, password, serialised_session));
  Tmid tmid(encrypted_session, session_.passport().Get<Antmid>(true));
  passport::EncryptedTmidName encrypted_tmid_name(passport::EncryptTmidName(
                                                    keyword, pin, tmid.name()));
  Mid::name_type mid_name(passport::MidName(keyword, pin));
  Mid mid(mid_name, encrypted_tmid_name, session_.passport().Get<Anmid>(true));
  PutFob<Tmid>(tmid);
  PutFob<Mid>(mid);
}

void ClientMaid::DeleteSession(const Keyword& keyword, const Pin& pin) {
  Mid::name_type mid_name(Mid::GenerateName(keyword, pin));
  auto mid_future(maidsafe::nfs::Get<Mid>(*client_nfs_, mid_name));
  Mid mid(*mid_future.get());
  passport::EncryptedTmidName encrypted_tmid_name(mid.encrypted_tmid_name());
  Tmid::name_type tmid_name(passport::DecryptTmidName(keyword, pin, encrypted_tmid_name));
  DeleteFob<Tmid>(tmid_name);
  DeleteFob<Mid>(mid_name);
}

void ClientMaid::GetSession(const Keyword& keyword, const Pin& pin, const Password& password) {
  Mid::name_type mid_name(Mid::GenerateName(keyword, pin));
  auto mid_future(maidsafe::nfs::Get<Mid>(*client_nfs_, mid_name));
  Mid mid(*mid_future.get());
  passport::EncryptedTmidName encrypted_tmid_name(mid.encrypted_tmid_name());
  Tmid::name_type tmid_name(passport::DecryptTmidName(keyword, pin, encrypted_tmid_name));
  auto tmid_future(maidsafe::nfs::Get<Tmid>(*client_nfs_, tmid_name));
  Tmid tmid(*tmid_future.get());
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

  std::vector<boost::asio::ip::udp::endpoint> bootstrap_endpoints;
  client_controller_.GetBootstrapNodes(bootstrap_endpoints);
  EndPointVector endpoints;
  for (auto& endpoint : bootstrap_endpoints)
    endpoints.push_back(std::make_pair(endpoint.address().to_string(), endpoint.port()));

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
  if (fobs_confirmed) {
    Maid maid(session_.passport().Get<Maid>(fobs_confirmed));
    Pmid pmid(session_.passport().Get<Pmid>(fobs_confirmed));
    UnregisterPmid(maid, pmid);
  }
  // client_controller_.StopVault(); get params!!!!!!!!!
  if (drive_mounted)
    try { UnMountDrive(); } catch(...) { /* consume exception */ }
  client_nfs_.reset();
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

void ClientMaid::PutFreeFobs() {
  ReplyFunction reply([this] (maidsafe::nfs::Reply reply) {
                        if (!reply.IsSuccess()) {
                          ThrowError(VaultErrors::failed_to_handle_request);
                        }
                      });
  detail::PutFobs<Free>()(*client_nfs_, session_.passport(), reply);
  return;
}

void ClientMaid::PutPaidFobs() {
  ReplyFunction reply([this] (maidsafe::nfs::Reply reply) {
                        if (!reply.IsSuccess()) {
                          ThrowError(VaultErrors::failed_to_handle_request);
                        }
                      });
  detail::PutFobs<Paid>()(*client_nfs_, session_.passport(), reply);
  return;
}

void ClientMaid::PublicKeyRequest(const NodeId& node_id, const GivePublicKeyFunctor& give_key) {
  if (client_nfs_) {
    typedef passport::PublicPmid PublicPmid;
    PublicPmid::name_type pmid_name(Identity(node_id.string()));
    auto pmid_future(maidsafe::nfs::Get<PublicPmid>(*client_nfs_, pmid_name));
    give_key(pmid_future.get()->public_key());
  } else {
    ThrowError(CommonErrors::uninitialised);
  }
  return;
}

}  // lifestuff
}  // maidsafe
