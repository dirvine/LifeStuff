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

#ifndef MAIDSAFE_LIFESTUFF_CLIENT_MPID_H_
#define MAIDSAFE_LIFESTUFF_CLIENT_MPID_H_

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

namespace maidsafe {
namespace lifestuff {

class ClientMpid {
 public:
  
  ClientMpid();
  ~ClientMpid();

  void CreatePublicId(const NonEmptyString& public_id);

 private:

};

}  // lifestuff
}  // maidsafe

#endif  // MAIDSAFE_LIFESTUFF_CLIENT_MPID_H_
