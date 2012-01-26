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

#include <iostream>  // NOLINT (Dan)
#include <memory>
#include <string>

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/client_controller.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/demo/commands.h"
#if defined REMOTE_STORE
#  include "maidsafe/lifestuff/store_components/remote_store_manager.h"
#else
#  include "maidsafe/lifestuff/store_components/local_store_manager.h"
#endif

int main(int /*argc*/, char *argv[]) {
  // Initialising logging
  google::InitGoogleLogging(argv[0]);
  // Choose to direct output to stderr or not.
  FLAGS_logtostderr = true;
  // If Google logging is linked in, log messages at or above this level.
  // Severity levels are INFO, WARNING, ERROR, and FATAL (0 to 3 respectively).
  FLAGS_ms_logging_common = google::FATAL;
  FLAGS_ms_logging_pki = google::FATAL;
  FLAGS_ms_logging_passport = google::INFO;
  FLAGS_ms_logging_encrypt = google::INFO;
  FLAGS_ms_logging_lifestuff = google::INFO;
  std::cout << "LifeStuff Demo" << std::endl;

  std::shared_ptr<maidsafe::lifestuff::Session> session(
      new maidsafe::lifestuff::Session);
  std::shared_ptr<maidsafe::lifestuff::ClientController> cc(
      new maidsafe::lifestuff::ClientController(session));
#if defined REMOTE_STORE
  cc->Init<maidsafe::lifestuff::RemoteStoreManager>();
#else
  cc->Init<maidsafe::lifestuff::LocalStoreManager>();
#endif
  maidsafe::lifestuff::commandline_demo::Commands commands(session, cc);

  commands.Run();
  return 0;
}
