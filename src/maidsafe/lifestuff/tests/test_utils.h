/*
* ============================================================================
*
* Copyright [2012] maidsafe.net limited
*
* Version:      1.0
* Created:      2011-04-18
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

#ifndef MAIDSAFE_LIFESTUFF_TESTS_TEST_UTILS_H_
#define MAIDSAFE_LIFESTUFF_TESTS_TEST_UTILS_H_

#include <memory>
#include <vector>
#include "boost/filesystem/path.hpp"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace dht { class Contact; }
namespace pd { class ClientContainer; }

namespace lifestuff {

namespace test {

typedef std::shared_ptr<pd::ClientContainer> ClientContainerPtr;

int RetrieveBootstrapContacts(const fs::path &download_dir,
                              std::vector<dht::Contact> *bootstrap_contacts);

ClientContainerPtr SetUpClientContainer(const fs::path &test_dir);

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_TESTS_TEST_UTILS_H_
