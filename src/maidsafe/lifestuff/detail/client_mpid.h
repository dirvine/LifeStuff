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

#include "maidsafe/nfs/nfs.h"

#include "maidsafe/lifestuff/detail/routing_handler.h"

namespace maidsafe {
namespace lifestuff {

class ClientMpid {
 public:
  typedef std::unique_ptr<RoutingHandler> RoutingHandlerPtr;
  typedef RoutingHandler::EndPointVector EndPointVector;
  typedef maidsafe::nfs::ClientMpidNfs ClientNfs;
  typedef std::unique_ptr<ClientNfs> ClientNfsPtr;
  typedef passport::Anmpid Anmpid;
  typedef passport::Mpid Mpid;

  ClientMpid(const NonEmptyString& public_id,
             const passport::Anmpid& anmpid,
             const passport::Mpid& mpid,
             const EndPointVector& bootstrap_endpoints);
  ClientMpid();
  ~ClientMpid() {}

  void LogIn();
  void LogOut();

  NonEmptyString PublicId() { return public_id_; }

 private:
  void JoinNetwork(const Mpid& Mpid, const EndPointVector& bootstrap_endpoints);
  void PublicKeyRequest(const NodeId& node_id, const GivePublicKeyFunctor& give_key);

  RoutingHandlerPtr routing_handler_;
  ClientNfsPtr client_nfs_;
  NonEmptyString public_id_;
  Anmpid anmpid_;
  Mpid mpid_;
};
}  // lifestuff
}  // maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MPID_H_
