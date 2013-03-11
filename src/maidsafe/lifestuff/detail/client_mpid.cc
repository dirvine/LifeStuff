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

ClientMpid::ClientMpid(RoutingPtr routing,
                       const NonEmptyString& public_id,
                       const passport::Anmpid& anmpid,
                       const passport::Mpid& mpid)
  : routing_(routing),
    client_nfs_(new ClientNfs(*routing_, mpid)),
    public_id_(public_id),
    anmpid_(anmpid),
    mpid_(mpid),
    asio_service_(2) {
  asio_service_.Start();
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
}  // lifestuff
}  // maidsafe
