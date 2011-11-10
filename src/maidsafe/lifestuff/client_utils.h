/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Utility Functions
* Version:      1.0
* Created:      2010-04-29-13.26.25
* Revision:     none
* Compiler:     gcc
* Author:       Team, dev@maidsafe.net
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef MAIDSAFE_LIFESTUFF_CLIENT_UTILS_H_
#define MAIDSAFE_LIFESTUFF_CLIENT_UTILS_H_

#include <string>
#include "maidsafe/passport/passport.h"
#include "maidsafe/lifestuff/maidsafe.h"

namespace kad { class Contact; }

namespace maidsafe {

namespace lifestuff {

class Session;

class ClientUtils {
 public:
  explicit ClientUtils(std::shared_ptr<Session> session)
      : session_(session) {}
  ~ClientUtils() {}
  void GetChunkSignatureKeys(DirType dir_type,
                             const std::string &msid,
                             std::string *key_id,
                             std::string *public_key,
                             std::string *public_key_sig,
                             std::string *private_key);
  void GetPacketSignatureKeys(passport::PacketType packet_type,
                              DirType dir_type,
                              const std::string &msid,
                              std::string *key_id,
                              std::string *public_key,
                              std::string *public_key_sig,
                              std::string *private_key,
                              bool *hashable);
 private:
  ClientUtils &operator=(const ClientUtils&);
  ClientUtils(const ClientUtils&);

  std::shared_ptr<Session> session_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_CLIENT_UTILS_H_
