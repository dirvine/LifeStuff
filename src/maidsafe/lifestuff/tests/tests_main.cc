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
  maidsafe::log::FilterMap filter;
  filter["common"] = maidsafe::log::kFatal;
  filter["private"] = maidsafe::log::kFatal;
  filter["encrypt"] = maidsafe::log::kFatal;
  filter["private"] = maidsafe::log::kFatal;
  filter["drive"] = maidsafe::log::kFatal;
  filter["passport"] = maidsafe::log::kFatal;
  filter["rudp"] = maidsafe::log::kFatal;
  filter["routing"] = maidsafe::log::kFatal;
  filter["pd"] = maidsafe::log::kError;
  filter["lifestuff"] = maidsafe::log::kInfo;
  return ExecuteMain(argc, argv, filter, false, maidsafe::log::ColourMode::kPartialLine);
}
