/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  none
* Version:      1.0
* Created:      2009-08-13-01.01.27
* Revision:     none
* Compiler:     gcc
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

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"

int main(int argc, char** argv) {
  maidsafe::log::Logging::instance().AddFilter("common", maidsafe::log::kFatal);
  maidsafe::log::Logging::instance().AddFilter("private", maidsafe::log::kFatal);
  maidsafe::log::Logging::instance().AddFilter("encrypt", maidsafe::log::kFatal);
  maidsafe::log::Logging::instance().AddFilter("drive", maidsafe::log::kFatal);
  maidsafe::log::Logging::instance().AddFilter("passport", maidsafe::log::kFatal);
#ifndef LOCAL_TARGETS_ONLY
  maidsafe::log::Logging::instance().AddFilter("rudp", maidsafe::log::kFatal);
  maidsafe::log::Logging::instance().AddFilter("routing", maidsafe::log::kFatal);
  maidsafe::log::Logging::instance().AddFilter("pd", maidsafe::log::kFatal);
#endif
  maidsafe::log::Logging::instance().AddFilter("lifestuff", maidsafe::log::kInfo);
  maidsafe::log::Logging::instance().SetColour(maidsafe::log::ColourMode::kFullLine);

  testing::FLAGS_gtest_catch_exceptions = false;
  testing::InitGoogleTest(&argc, argv);
  int result(RUN_ALL_TESTS());
  int test_count = testing::UnitTest::GetInstance()->test_to_run_count();
  return (test_count == 0) ? -1 : result;
}
