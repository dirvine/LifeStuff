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
#include <utility>
#include <vector>

#include "boost/filesystem/path.hpp"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4702)
#endif
#include "boost/iostreams/device/file_descriptor.hpp"
#include "boost/iostreams/stream.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "boost/process/child.hpp"

#include "maidsafe/common/test.h"


namespace maidsafe {

namespace lifestuff {

namespace test {

class NetworkHelper {
 public:
  NetworkHelper(); 
  testing::AssertionResult StartLocalNetwork(std::shared_ptr<boost::filesystem::path> test_root,
                                             int vault_count, bool start_invigilator = false);
  testing::AssertionResult StopLocalNetwork();

 private:
   typedef std::unique_ptr<boost::iostreams::stream<boost::iostreams::file_descriptor_source>>
      InStreamPtr;
      std::vector<boost::process::child> zero_state_processes_;
   std::vector<std::pair<boost::process::child, InStreamPtr>> vault_processes_;
   std::vector<boost::process::child> invigilator_processes_;
};

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_TESTS_NETWORK_HELPER_H_
