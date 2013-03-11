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

ClientMaid::ClientMaid(UpdateAvailableFunction update_available_function)
  : client_controller_(update_available_function),
    session_(),
    user_storage_(),
    routing_handler_(),
    client_nfs_() {
}

void ClientMaid::CreateUser(const Keyword& keyword, const Pin& pin, const Password& password) {
  CheckInputs(keyword, pin, password);
  session_.passport().CreateFobs();
  Maid maid(session_.passport().Get<Maid>(false));
  Pmid pmid(session_.passport().Get<Pmid>(false));
  JoinNetwork(maid);
  PutFreeFobs();
  client_nfs_.reset(new ClientNfs(routing_handler_->routing(), maid));
  client_controller_.StartVault(pmid, maid.name(), boost::filesystem::path());  // Pass a vaild path!
  RegisterPmid(maid, pmid);
  session_.passport().ConfirmFobs();
  PutPaidFobs();
  session_.set_unique_user_id(Identity(RandomAlphaNumericString(64)));
  MountDrive();
  UnMountDrive();
  PutSession(keyword, pin, password);
  return;
}

void ClientMaid::LogIn(const Keyword& keyword, const Pin& pin, const Password& password) {
  CheckInputs(keyword, pin, password);
  Anmaid anmaid;
  Maid maid(anmaid);
  JoinNetwork(maid);
  client_nfs_.reset(new ClientNfs(routing_handler_->routing(), maid));
  GetSession(keyword, pin, password);
  maid = session_.passport().Get<Maid>(true);
  Pmid pmid(session_.passport().Get<Pmid>(true));
  JoinNetwork(maid);
  client_nfs_.reset(new ClientNfs(routing_handler_->routing(), maid));
  client_controller_.StartVault(pmid, maid.name(), boost::filesystem::path());  // Pass a vaild path!
  return;
}

void ClientMaid::LogOut() {
  UnMountDrive();
//  client_controller_.StopVault(  );  parameters???
}

void ClientMaid::MountDrive() {
  user_storage_.MountDrive(*client_nfs_, session_);
  return;
}

void ClientMaid::UnMountDrive() {
  user_storage_.UnMountDrive(session_);
  return;
}

void ClientMaid::CheckInputs(const Keyword& keyword, const Pin& pin, const Password& password) {
  CheckKeywordValidity(keyword);
  CheckPinValidity(pin);
  CheckPasswordValidity(password);
  return;
}

void ClientMaid::CheckKeywordValidity(const Keyword& keyword) {
  if (!AcceptableWordSize(keyword.data))
    ThrowError(LifeStuffErrors::kKeywordSizeInvalid);
  if (!AcceptableWordPattern(keyword.data))
    ThrowError(LifeStuffErrors::kKeywordPatternInvalid);
  return;
}

void ClientMaid::CheckPinValidity(const Pin& pin) {
  if (pin.data.string().size() != kPinSize)
    ThrowError(LifeStuffErrors::kPinSizeInvalid);
  if (boost::lexical_cast<int>(pin.data.string()) < 1)
    ThrowError(LifeStuffErrors::kPinPatternInvalid);
  return;
}

void ClientMaid::CheckPasswordValidity(const Password& password) {
  if (!AcceptableWordSize(password.data))
    ThrowError(LifeStuffErrors::kPasswordSizeInvalid);
  if (!AcceptableWordPattern(password.data))
    ThrowError(LifeStuffErrors::kPasswordPatternInvalid);
  return;
}

bool ClientMaid::AcceptableWordSize(const Identity& word) {
  return word.string().size() >= kMinWordSize && word.string().size() <= kMaxWordSize;
}

bool ClientMaid::AcceptableWordPattern(const Identity& word) {
  boost::regex space(" ");
  return !boost::regex_search(word.string().begin(), word.string().end(), space);
}

void ClientMaid::GetSession(const Keyword& keyword, const Pin& pin, const Password& password) {
  uint32_t user_pin(std::stoul(pin.data.string()));
  UserKeyword user_keyword(keyword.data);
  UserPassword user_password(password.data);
  Mid::name_type mid_name(Mid::GenerateName(user_keyword, user_pin));
  std::future<Mid> mid_future(maidsafe::nfs::Get<Mid>(*client_nfs_, mid_name));
  Mid mid(mid_future.get());
  passport::EncryptedTmidName encrypted_tmid_name(mid.encrypted_tmid_name());
  Tmid::name_type tmid_name(passport::DecryptTmidName(
                              user_keyword, user_pin, encrypted_tmid_name));
  std::future<Tmid> tmid_future(maidsafe::nfs::Get<Tmid>(*client_nfs_, tmid_name));
  Tmid tmid(tmid_future.get());
  passport::EncryptedSession encrypted_session(tmid.encrypted_session());
  NonEmptyString serialised_session(passport::DecryptSession(
                                      user_keyword, user_pin, user_password, encrypted_session));
  session_.Parse(serialised_session);
}

void ClientMaid::PutSession(const Keyword& keyword, const Pin& pin, const Password& password) {
  uint32_t user_pin(std::stoul(pin.data.string()));
  UserKeyword user_keyword(keyword.data);
  UserPassword user_password(password.data);
  NonEmptyString serialised_session(session_.Serialise());
  passport::EncryptedSession encrypted_session(passport::EncryptSession(
                                  user_keyword, user_pin, user_password, serialised_session));
  Tmid tmid(encrypted_session, session_.passport().Get<Antmid>(true));
  Tmid::name_type tmid_name(tmid.name());
  passport::EncryptedTmidName encrypted_tmid_name(passport::EncryptTmidName(
                                                    user_keyword, user_pin, tmid_name));
  Mid::name_type mid_name(Mid::GenerateName(user_keyword, user_pin));
  Mid mid(mid_name, encrypted_tmid_name, session_.passport().Get<Anmid>(true));
  PutFob<Tmid>(tmid);
  PutFob<Mid>(mid);
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

void ClientMaid::PutFreeFobs() {
  ReplyFunction reply([this] (maidsafe::nfs::Reply reply) {
                        if (!reply.IsSuccess()) {
                          this->HandlePutFreeFobsFailure();
                        }
                      });
  detail::PutFobs<Free>()(*client_nfs_, session_.passport(), reply);
  return;
}

void ClientMaid::HandlePutFreeFobsFailure() {
  session_.passport().CreateFobs();
  JoinNetwork(session_.passport().Get<Maid>(false));
  PutFreeFobs();
  return;
}

void ClientMaid::PutPaidFobs() {
  ReplyFunction reply([this] (maidsafe::nfs::Reply reply) {
                        if (!reply.IsSuccess()) {
                          this->HandlePutPaidFobsFailure();
                        }
                      });
  detail::PutFobs<Paid>()(*client_nfs_, session_.passport(), reply);
  return;
}

void ClientMaid::HandlePutPaidFobsFailure() {
  Maid maid(session_.passport().Get<Maid>(false));
  Pmid pmid(session_.passport().Get<Pmid>(false));
  UnregisterPmid(maid, pmid);
//  client_controller_.StopVault();  // TODO Determine parameters to pass
  session_.passport().CreateFobs();
  maid = session_.passport().Get<Maid>(false);
  pmid = session_.passport().Get<Pmid>(false);
  JoinNetwork(maid);
  PutFreeFobs();
  client_nfs_.reset(new ClientNfs(routing_handler_->routing(), maid));
  client_controller_.StartVault(pmid, maid.name(), boost::filesystem::path());  // Pass a vaild path!
  RegisterPmid(maid, pmid);
  session_.passport().ConfirmFobs();
  PutPaidFobs();
  return;
}

template<typename Fob>
void ClientMaid::PutFob(const Fob& fob) {
  ReplyFunction reply([this] (maidsafe::nfs::Reply reply) {
                        if (!reply.IsSuccess()) {
                          this->HandlePutFobFailure();
                        }
                      });
  passport::Pmid::name_type pmid_name(session_.passport().Get<Pmid>(true).name());
  maidsafe::nfs::Put<Fob>(*client_nfs_, fob, pmid_name, 3, reply);
  return;
}

void ClientMaid::HandlePutFobFailure() {
  ThrowError(LifeStuffErrors::kStoreFailure);
  return;
}

template<typename Fob>
void ClientMaid::DeleteFob(const typename Fob::name_type& fob_name) {
  ReplyFunction reply([this] (maidsafe::nfs::Reply reply) {
                        if (!reply.IsSuccess()) {
                          this->HandleDeleteFobFailure();
                        }
                      });
  maidsafe::nfs::Delete<Fob>(*client_nfs_, fob_name, 3, reply);
  return;
}

void ClientMaid::HandleDeleteFobFailure() {
  ThrowError(LifeStuffErrors::kDeleteFailure);
  return;
}

template<typename Fob>
Fob ClientMaid::GetFob(const typename Fob::name_type& fob_name) {
  std::future<Fob> fob_future(maidsafe::nfs::Get<Fob>(*client_nfs_, fob_name));
  return fob_future.get();
}

void ClientMaid::RegisterPmid(const Maid& maid, const Pmid& pmid) {
  PmidRegistration pmid_registration(maid, pmid, false);
  PmidRegistration::serialised_type serialised_pmid_registration(pmid_registration.Serialise());
  client_nfs_->RegisterPmid(serialised_pmid_registration,
                      [](std::string response) {
                        NonEmptyString serialised_response(response);
                        nfs::Reply::serialised_type serialised_reply(serialised_response);
                        nfs::Reply reply(serialised_reply);
                        if (!reply.IsSuccess())
                          ThrowError(VaultErrors::failed_to_handle_request);
                      });
  return;
}

void ClientMaid::UnregisterPmid(const Maid& maid, const Pmid& pmid) {
  PmidRegistration pmid_unregistration(maid, pmid, true);
  PmidRegistration::serialised_type serialised_pmid_unregistration(pmid_unregistration.Serialise());
  client_nfs_->UnregisterPmid(serialised_pmid_unregistration, [](std::string) {});
  return;
}

void ClientMaid::PublicKeyRequest(const NodeId& node_id, const GivePublicKeyFunctor& give_key) {
  if(client_nfs_) {
    typedef passport::PublicPmid PublicPmid;
    PublicPmid::name_type pmid_name(Identity(node_id.string()));
    std::future<PublicPmid> pmid_future(maidsafe::nfs::Get<PublicPmid>(*client_nfs_, pmid_name));
    give_key(pmid_future.get().public_key());
  } else {
    ThrowError(CommonErrors::uninitialised);
  }
}

}  // lifestuff
}  // maidsafe
