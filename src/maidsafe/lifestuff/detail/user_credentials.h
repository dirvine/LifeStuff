/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Singleton class which controls all maidsafe client operations
* Version:      1.0
* Created:      2009-01-28-11.09.12
* Revision:     none
* Compiler:     gcc
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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_USER_CREDENTIALS_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_USER_CREDENTIALS_H_

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "boost/function.hpp"
#include "boost/signals2.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/filesystem/path.hpp"
#include "boost/thread/thread.hpp"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/return_codes.h"

namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {
namespace chunk_store {
class RemoteChunkStore;
}  // namespace chunk_store
}  // namespace priv

namespace pcs = maidsafe::priv::chunk_store;

namespace lifestuff {

namespace test {
class UserCredentialsTest;
class UserStorageTest;
}  // namespace test

class Authentication;
class Session;

class UserCredentials {
 public:
  UserCredentials(std::shared_ptr<pcs::RemoteChunkStore> chunk_store,
                  std::shared_ptr<Session> session);

  ~UserCredentials();
  void Init(const fs::path &chunk_store_dir);

  // User credential operations
  int CheckUserExists(const std::string &username,
                      const std::string &pin);
  bool ValidateUser(const std::string &password);
  bool CreateUser(const std::string &username,
                  const std::string &pin,
                  const std::string &password);
  bool Logout();
  int SaveSession();
//   void DoSaveSession();
  bool ChangeUsername(const std::string &new_username);
  bool ChangePin(const std::string &new_pin);
  bool ChangePassword(const std::string &new_password);

  friend class test::UserCredentialsTest;
  friend class test::UserStorageTest;

 private:
  UserCredentials &operator=(const UserCredentials&);
  UserCredentials(const UserCredentials&);

  std::shared_ptr<Session> session_;
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store_;
  std::shared_ptr<Authentication> authentication_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_USER_CREDENTIALS_H_
