/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Version:      1.0
* Created:      2011-04-19
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

#include <iostream> //NOLINT
#include <memory>
#include <string>

#include "maidsafe/lifestuff/client/clientcontroller.h"
#include "maidsafe/lifestuff/client/tests/demo/commands.h"
#include "maidsafe/lifestuff/client/user_credentials_api.h"


int main(int argc, char *argv[]) {
  std::cout << "LifeStuff Demo" << std::endl;

  std::shared_ptr<maidsafe::lifestuff::UserCredentials> user_credential;

  user_credential.reset(new maidsafe::lifestuff::ClientController());
  maidsafe::lifestuff::lifestuff_demo::Commands commands(user_credential);
  commands.Run();
}
