/*
* ============================================================================
*
* Copyright [2012] maidsafe.net limited
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

#ifndef MAIDSAFE_LIFESTUFF_TESTS_NETWORK_HELPER_H_
#define MAIDSAFE_LIFESTUFF_TESTS_NETWORK_HELPER_H_

#include <memory>
#include <vector>

#include "boost/filesystem/path.hpp"
#include "boost/process/child.hpp"

#include "maidsafe/common/test.h"


namespace maidsafe {

namespace lifestuff {

namespace test {

class NetworkHelper {
 public:
  NetworkHelper(); 
  testing::AssertionResult StartLocalNetwork(std::shared_ptr<boost::filesystem::path> test_root,
                                             int vault_count);
  testing::AssertionResult StopLocalNetwork();

 private:
   std::vector<boost::process::child> vault_processes_;
};

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_TESTS_NETWORK_HELPER_H_
