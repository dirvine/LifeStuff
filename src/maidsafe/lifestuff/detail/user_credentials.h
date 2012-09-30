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
namespace chunk_store { class RemoteChunkStore; }
}  // namespace priv

namespace lifestuff {

class RoutingsHandler;
class Session;
class UserCredentialsImpl;

class UserCredentials {
 public:
  UserCredentials(priv::chunk_store::RemoteChunkStore& chunk_store,
                  Session& session,
                  boost::asio::io_service& service,
                  RoutingsHandler& routings_handler);

  ~UserCredentials();

  // User credential operations
  int LogIn(const std::string& keyword, const std::string& pin, const std::string& password);
  int CreateUser(const std::string& keyword, const std::string& pin, const std::string& password);
  int Logout();
  int SaveSession();

  int ChangeKeyword(const std::string& new_keyword);
  int ChangePin(const std::string& new_pin);
  int ChangePassword(const std::string& new_password);

  int DeleteUserCredentials();

  bs2::connection ConnectToImmediateQuitRequiredSignal(
      const ImmediateQuitRequiredFunction& immediate_quit_required_slot);

  void LogoutCompletedArrived(const std::string& session_marker);

 private:
  UserCredentials &operator=(const UserCredentials&);
  UserCredentials(const UserCredentials&);

  std::unique_ptr<UserCredentialsImpl> impl_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_USER_CREDENTIALS_H_
