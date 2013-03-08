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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MPID_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MPID_H_

#include <string>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/types.h"

namespace maidsafe {
namespace lifestuff {

class ClientMpid {
 public:
  typedef passport::Passport Passport;
  typedef maidsafe::routing::Routing Routing;
  typedef std::shared_ptr<Routing> RoutingPtr;
  typedef maidsafe::nfs::ClientMpidNfs ClientNfs;
  typedef std::unique_ptr<ClientNfs> ClientNfsPtr;
  typedef passport::Anmpid Anmpid;
  typedef passport::Mpid Mpid;

  ClientMpid(RoutingPtr routing,
             const NonEmptyString& public_id,
             const passport::Mpid& mpid);
  ~ClientMpid();

  void LogIn();
  void LogOut();

 private:
  RoutingPtr routing_;
  ClientNfsPtr client_nfs_;
  NonEmptyString public_id_;
  Anmpid anmpid_;
  Mpid mpid_;
  AsioService asio_service_;
};
}  // lifestuff
}  // maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MPID_H_
