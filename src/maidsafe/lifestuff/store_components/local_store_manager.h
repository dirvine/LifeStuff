/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Manages data storage to local database (for testing)
* Version:      1.0
* Created:      2009-01-29-00.06.15
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#ifndef MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_LOCAL_STORE_MANAGER_H_
#define MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_LOCAL_STORE_MANAGER_H_

#include <memory>
#include <string>

#include "boost/filesystem/path.hpp"

#include "maidsafe/lifestuff/store_components/fake_store_manager.h"

namespace maidsafe {

namespace lifestuff {

class Session;

class LocalStoreManager : public FakeStoreManager {
 public:
  LocalStoreManager(std::shared_ptr<Session> session,
                    const std::string &db_directory = "");
  ~LocalStoreManager();
  void Init(VoidFuncOneInt callback);
 private:
  LocalStoreManager &operator=(const LocalStoreManager&);
  LocalStoreManager(const LocalStoreManager&);
  boost::filesystem::path local_store_manager_dir_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_LOCAL_STORE_MANAGER_H_
