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

#include "maidsafe/lifestuff/detail/client_mpid.h"

#include "maidsafe/nfs/client_utils.h"

namespace maidsafe {
namespace lifestuff {

ClientMpid::ClientMpid(const NonEmptyString& public_id,
                       const passport::Anmpid& anmpid,
                       const passport::Mpid& mpid,
                       const EndPointVector& bootstrap_endpoints)
  : routing_handler_(),
    client_nfs_(),
    public_id_(public_id),
    anmpid_(anmpid),
    mpid_(mpid) {
  JoinNetwork(mpid_, bootstrap_endpoints);
  client_nfs_.reset(new ClientNfs(routing_handler_->routing(), mpid_));
}

void ClientMpid::LogIn() {
  client_nfs_->GoOnline([](std::string response) {
                          NonEmptyString serialised_response(response);
                          nfs::Reply::serialised_type serialised_reply(serialised_response);
                          nfs::Reply reply(serialised_reply);
                          if (!reply.IsSuccess())
                            ThrowError(VaultErrors::failed_to_handle_request);
                        });
}

void ClientMpid::LogOut() {
  client_nfs_->GoOffline([](std::string /*response*/) {});
}

void ClientMpid::JoinNetwork(const Mpid& mpid,
                             const EndPointVector& bootstrap_endpoints) {
  PublicKeyRequestFunction public_key_request(
      [this](const NodeId& node_id, const GivePublicKeyFunctor& give_key) {
        PublicKeyRequest(node_id, give_key);
      });
  routing_handler_.reset(new RoutingHandler(mpid, public_key_request));
  routing_handler_->Join(bootstrap_endpoints);
}

void ClientMpid::PublicKeyRequest(const NodeId& node_id, const GivePublicKeyFunctor& give_key) {
  if ((mpid_.name().data.IsInitialised()) &&
      (mpid_.name().data.string() == node_id.string())) {
    give_key(mpid_.public_key());
  } else {
    ThrowError(CommonErrors::uninitialised);
  }
  return;
}

void ClientMpid::RegisterMpid(const Anmpid& anmpid, const Mpid& mpid) {
  MpidRegistration mpid_registration(anmpid, mpid, false);
  MpidRegistration::serialised_type serialised_mpid_registration(mpid_registration.Serialise());
  client_nfs_->RegisterMpid(serialised_mpid_registration,
                      [](std::string response) {
                        NonEmptyString serialised_response(response);
                        nfs::Reply::serialised_type serialised_reply(serialised_response);
                        nfs::Reply reply(serialised_reply);
                        if (!reply.IsSuccess())
                          ThrowError(VaultErrors::failed_to_handle_request);
                      });
  return;
}

void ClientMpid::UnregisterMpid(const Anmpid& anmpid, const Mpid& mpid) {
  MpidRegistration mpid_unregistration(anmpid, mpid, true);
  MpidRegistration::serialised_type serialised_mpid_unregistration(mpid_unregistration.Serialise());
  client_nfs_->UnregisterMpid(serialised_mpid_unregistration, [](std::string) {});
  return;
}
}  // lifestuff
}  // maidsafe
