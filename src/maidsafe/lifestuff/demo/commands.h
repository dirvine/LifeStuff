/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Version:      1.0
* Created:      2011-04-22
* Author:       Team
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
#ifndef MAIDSAFE_LIFESTUFF_DEMO_COMMANDS_H_
#define MAIDSAFE_LIFESTUFF_DEMO_COMMANDS_H_

#include <memory>
#include <string>

#include "maidsafe/lifestuff/client_controller.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/user_storage.h"

namespace maidsafe {

namespace lifestuff {

namespace commandline_demo {

class Commands {
 public:
  typedef std::shared_ptr<ClientController> UserCredentialPtr;
  typedef std::shared_ptr<Session> SessionPtr;
  Commands(SessionPtr session, UserCredentialPtr user_credential);
  virtual ~Commands() {}
  void Run();
  bool LoginUser();
  void PrintUsage();
  void ProcessCommand(const std::string &cmdline, bool *wait_for_cb);

 private:
  bool result_arrived_, finish_;
  SessionPtr session_;
  UserCredentialPtr user_credential_;
  UserStorage user_storage_;
  std::string username_, pin_;
  bool logged_in_;
};

}  // namespace commandline_demo

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DEMO_COMMANDS_H_
