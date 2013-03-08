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

ClientMaid::ClientMaid(UpdateAvailableFunction update_available_slot)
  : client_controller_(update_available_slot),
    passport_(),
    session_(),
    user_storage_(),
    routing_(),
    client_nfs_(),
    user_credentials_(),
    network_health_(),
    asio_service_(2) {
  asio_service_.Start();
}

void ClientMaid::CreateUser(const Keyword& keyword, const Pin& pin, const Password& password) {
  CheckInputs(keyword, pin, password);
  // create keys...
  passport_.CreateFobs();
  Maid maid(passport_.Get<Maid>(false));
  Pmid pmid(passport_.Get<Pmid>(false));
  // join network...
  Join(maid);
  // store free keys...
  PutFreeFobs();
  // start vault...
  client_controller_.StartVault(pmid, maid.name(), boost::filesystem::path());  // Pass a vaild path!
  // start client...
  client_nfs_.reset(new ClientNfs(*routing_, maid));
  user_credentials_.reset(new UserCredentials(*client_nfs_));
  passport_.ConfirmFobs();
  // register vault...
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
  // store remaining keys...
  PutPaidFobs();  // 
  // generate and store Mid and Tmid...
  uint32_t user_pin(std::stoul(pin.data.string()));
  UserKeyword user_keyword(keyword.data);
  UserPassword user_password(password.data);
  NonEmptyString serialised_session(passport_.Serialise());
  passport::EncryptedSession encrypted_session(passport::EncryptSession(
                                  user_keyword, user_pin, user_password, serialised_session));
  Tmid tmid(encrypted_session, passport_.Get<Antmid>(true));
  Tmid::name_type tmid_name(tmid.name());
  passport::EncryptedTmidName encrypted_tmid_name(passport::EncryptTmidName(
                                                    user_password, user_pin, tmid_name));
  Mid::name_type mid_name(Mid::GenerateName(user_keyword, user_pin));
  Mid mid(mid_name, encrypted_tmid_name, passport_.Get<Anmid>(true));
  PutFob<Tmid>(tmid);
  PutFob<Mid>(mid);
  return;
}

void ClientMaid::LogIn(const Keyword& keyword, const Pin& pin, const Password& password) {
  CheckInputs(keyword, pin, password);
  // join unauthorised...
  Anmaid anmaid;
  Maid raid(anmaid);
  Join(raid);
  client_nfs_.reset(new ClientNfs(*routing_, raid));
  // get Mid...
  uint32_t user_pin(std::stoul(pin.data.string()));
  UserKeyword user_keyword(keyword.data);
  UserPassword user_password(password.data);
  Mid::name_type mid_name(Mid::GenerateName(user_keyword, user_pin));
  std::future<Mid> mid_future(maidsafe::nfs::Get<Mid>(*client_nfs_, mid_name));
  Mid mid(mid_future.get());
  // get Tmid...
  passport::EncryptedTmidName encrypted_tmid_name(mid.encrypted_tmid_name());
  Tmid::name_type tmid_name(passport::DecryptTmidName(user_password, user_pin, encrypted_tmid_name));
  std::future<Tmid> tmid_future(maidsafe::nfs::Get<Tmid>(*client_nfs_, tmid_name));
  Tmid tmid(tmid_future.get());
  // recover session keys...
  passport::EncryptedSession encrypted_session(tmid.encrypted_session());
  NonEmptyString serialised_session(passport::DecryptSession(user_keyword, user_pin, user_password, encrypted_session));
  passport_.Parse(serialised_session);
  Maid maid(passport_.Get<Maid>(true));
  Pmid pmid(passport_.Get<Pmid>(true));
  // join authorised...
  Join(maid);
  // start vault...
  client_controller_.StartVault(pmid, maid.name(), boost::filesystem::path());  // Pass a vaild path!
  // reset client details, etc.,...
  client_nfs_.reset(new ClientNfs(*routing_, maid));
  user_credentials_.reset(new UserCredentials(*client_nfs_));
  return;
}

void ClientMaid::LogOut() {
  
}

void ClientMaid::MountDrive() {
  boost::filesystem::path data_store_path(
      GetHomeDir() / kAppHomeDirectory / session_.session_name().string());
  user_storage_.MountDrive(*client_nfs_,
                           passport_.Get<Maid>(true),
                           session_,
                           data_store_path,
                           DiskUsage(10995116277760));  // arbitrary 10GB
  return;
}

void ClientMaid::UnMountDrive() {
  int64_t max_space(0), used_space(0);
  user_storage_.UnMountDrive(max_space, used_space);
  session_.set_max_space(max_space);
  session_.set_used_space(used_space);
  return;
}

//int ClientMaid::UnMountDrive() {
//  if ((kCredentialsLoggedIn & logged_in_state_) != kCredentialsLoggedIn ||
//      (kDriveMounted & logged_in_state_) != kDriveMounted ||
//      (kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted) {
//    LOG(kError) << "In unsuitable state to unmount drive: " <<
//                   "make sure user_credentials are logged in, drive is mounted and "
//                   "messages and intros have been stopped.";
//    return kWrongLoggedInState;
//  }
//
//  logged_in_components_->storage.UnMountDrive();
//  if (logged_in_components_->storage.mount_status()) {
//    LOG(kError) << "Failed to un-mount.";
//    return kUnMountDriveError;
//  }
//
//  // Delete mount directory
//  boost::system::error_code error_code;
//  fs::remove_all(mount_path(), error_code);
//  if (error_code)
//    LOG(kWarning) << "Failed to delete mount directory: " << mount_path();
//
//  if ((kDriveMounted & logged_in_state_) == kDriveMounted)
//    logged_in_state_ = logged_in_state_ ^ kDriveMounted;
//  return kSuccess;
//}

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

void ClientMaid::Join(const Maid& maid) {
  routing_.reset(new Routing(maid));
  routing::Functors functors(InitialiseRoutingFunctors());
  std::vector<EndPoint> bootstrap_endpoints;
  client_controller_.GetBootstrapNodes(bootstrap_endpoints);
  routing_->Join(functors, UdpEndpoints(bootstrap_endpoints));
  return;
}

void ClientMaid::PutFreeFobs() {
  ReplyFunction reply([this] (maidsafe::nfs::Reply reply) {
                        if (!reply.IsSuccess()) {
                          this->HandlePutFreeFobsFailure();
                        }
                      });
  detail::PutFobs<Free>()(*client_nfs_, passport_, reply);
  return;
}

void ClientMaid::HandlePutFreeFobsFailure() {
  passport_.CreateFobs();
  Join(passport_.Get<Maid>(false));
  PutFreeFobs();
  return;
}

void ClientMaid::PutPaidFobs() {
  ReplyFunction reply([this] (maidsafe::nfs::Reply reply) {
                        if (!reply.IsSuccess()) {
                          this->HandlePutPaidFobsFailure();
                        }
                      });
  detail::PutFobs<Paid>()(*client_nfs_, passport_, reply);
  return;
}

void ClientMaid::HandlePutPaidFobsFailure() {
  Maid maid(passport_.Get<Maid>(false));
  Pmid pmid(passport_.Get<Pmid>(false));
  // unregister vault...
  PmidRegistration pmid_unregistration(maid, pmid, true);
  PmidRegistration::serialised_type serialised_pmid_unregistration(pmid_unregistration.Serialise());
  client_nfs_->UnregisterPmid(serialised_pmid_unregistration, [](std::string response) {});
//  client_controller_.StopVault();  // TODO Determine parameters to pass
  // retry...
  passport_.CreateFobs();
  Join(passport_.Get<Maid>(false));
  PutFreeFobs();
  client_controller_.StartVault(pmid, maid.name(), boost::filesystem::path());  // Pass a vaild path!
  // start client...
  client_nfs_.reset(new ClientNfs(*routing_, maid));
  user_credentials_.reset(new UserCredentials(*client_nfs_));
  passport_.ConfirmFobs();
  // register vault...
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
  PutPaidFobs();
  return;
}

template <typename Fob>
void ClientMaid::PutFob(const Fob& fob) {
  ReplyFunction reply([this] (maidsafe::nfs::Reply reply) {
                        if (!reply.IsSuccess()) {
                          this->HandlePutFobFailure();
                        }
                      });
  passport::Pmid::name_type pmid_name(passport_.Get<Pmid>(true).name());
  maidsafe::nfs::Put<Fob>(*client_nfs_, fob, pmid_name, 3, reply);
  return;
}

void ClientMaid::HandlePutFobFailure() {
  ThrowError(LifeStuffErrors::kStoreFailure);  // ???
  return;
}

std::vector<ClientMaid::UdpEndPoint>
      ClientMaid::UdpEndpoints(const std::vector<EndPoint>& bootstrap_endpoints) {
  std::vector<UdpEndPoint> endpoints;
  for (auto& endpoint : bootstrap_endpoints) {
    UdpEndPoint udp_endpoint;
    udp_endpoint.address(boost::asio::ip::address::from_string(endpoint.first));
    udp_endpoint.port(endpoint.second);
    endpoints.push_back(udp_endpoint);
  }
  return endpoints;
}

routing::Functors ClientMaid::InitialiseRoutingFunctors() {
  routing::Functors functors;
  functors.message_received = [this](const std::string& message,
                                     bool /*cache_lookup*/,
                                     const routing::ReplyFunctor& reply_functor) {
                                  OnMessageReceived(message, reply_functor);
                              };
  functors.network_status = [this](const int& network_health) {
                                OnNetworkStatusChange(network_health);
                            };
  functors.close_node_replaced = [this](const std::vector<routing::NodeInfo>& new_close_nodes) {
                                     OnCloseNodeReplaced(new_close_nodes);
                                 };
  functors.request_public_key = [this](const NodeId& node_id,
                                       const routing::GivePublicKeyFunctor& give_key) {
                                    OnPublicKeyRequested(node_id, give_key);
                                };
  functors.new_bootstrap_endpoint = [this](const boost::asio::ip::udp::endpoint& endpoint) {
                                        OnNewBootstrapEndpoint(endpoint);
                                    };
  functors.store_cache_data = [this](const std::string& message) { OnStoreInCache(message); };
  functors.have_cache_data = [this](std::string& message) { return OnGetFromCache(message); };
  return functors;
}

void ClientMaid::OnMessageReceived(const std::string& message,
                                      const routing::ReplyFunctor& reply_functor) {
  asio_service_.service().post([=] { DoOnMessageReceived(message, reply_functor); });
}

void ClientMaid::DoOnMessageReceived(const std::string& /*message*/,
                                        const routing::ReplyFunctor& /*reply_functor*/) {
}

void ClientMaid::OnNetworkStatusChange(const int& network_health) {
  asio_service_.service().post([=] { DoOnNetworkStatusChange(network_health); });
}

void ClientMaid::DoOnNetworkStatusChange(const int& network_health) {
  if (network_health >= 0) {
    if (network_health >= network_health_)
      LOG(kVerbose) << "Init - " << DebugId(routing_->kNodeId())
                    << " - Network health is " << network_health
                    << "% (was " << network_health_ << "%)";
    else
      LOG(kWarning) << "Init - " << DebugId(routing_->kNodeId())
                    << " - Network health is " << network_health
                    << "% (was " << network_health_ << "%)";
  } else {
    LOG(kWarning) << "Init - " << DebugId(routing_->kNodeId())
                  << " - Network is down (" << network_health << ")";
  }
  network_health_ = network_health;
}

void ClientMaid::OnPublicKeyRequested(const NodeId& node_id,
                                         const routing::GivePublicKeyFunctor& give_key) {
  asio_service_.service().post([=] { DoOnPublicKeyRequested(node_id, give_key); });
}

void ClientMaid::DoOnPublicKeyRequested(const NodeId& node_id,
                                           const routing::GivePublicKeyFunctor& give_key) {
  typedef passport::PublicPmid PublicPmid;
  PublicPmid::name_type pmid_name(Identity(node_id.string()));
  std::future<PublicPmid> pmid_future(maidsafe::nfs::Get<PublicPmid>(*client_nfs_, pmid_name));
  give_key(pmid_future.get().public_key());
}

void ClientMaid::OnCloseNodeReplaced(const std::vector<routing::NodeInfo>& /*new_close_nodes*/) {
}

bool ClientMaid::OnGetFromCache(std::string& /*message*/) {  // Need to be on routing's thread
  return true;
}

void ClientMaid::OnStoreInCache(const std::string& message) {  // post/move data?
  asio_service_.service().post([=] { DoOnStoreInCache(message); });
}

void ClientMaid::DoOnStoreInCache(const std::string& /*message*/) {
}

void ClientMaid::OnNewBootstrapEndpoint(const boost::asio::ip::udp::endpoint& endpoint) {
  asio_service_.service().post([=] { DoOnNewBootstrapEndpoint(endpoint); });
}

void ClientMaid::DoOnNewBootstrapEndpoint(const boost::asio::ip::udp::endpoint& /*endpoint*/) {
}

}  // lifestuff
}  // maidsafe
