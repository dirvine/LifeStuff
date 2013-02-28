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

#ifndef MAIDSAFE_LIFESTUFF_CLIENT_MAID_H_
#define MAIDSAFE_LIFESTUFF_CLIENT_MAID_H_

#include "maidsafe/lifestuff/lifestuff.h"

#include "maidsafe/routing/routing_api.h"
#include "maidsafe/nfs/nfs.h"

namespace maidsafe {
namespace lifestuff {

class ClientMaid {
 public:
  typedef maidsafe::nfs::ClientMaidNfs ClientNfs;
  
  ClientMaid(ClientNfs& client_nfs_);

  void CreateUser(const Keyword& keyword, const Pin& pin, const Password& password);
  void MountDrive();

 private:

  ClientNfs& client_nfs_;
};

}  // lifestuff
}  // maidsafe

#endif  // MAIDSAFE_LIFESTUFF_CLIENT_MAID_H_