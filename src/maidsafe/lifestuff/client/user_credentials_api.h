/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
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

#ifndef MAIDSAFE_LIFESTUFF_CLIENT_USER_CREDENTIALS_API_H_
#define MAIDSAFE_LIFESTUFF_CLIENT_USER_CREDENTIALS_API_H_

#include <string>
#include "maidsafe/lifestuff/shared/version.h"

#if MAIDSAFE_LIFESTUFF_CLIENT_VERSION != 106
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif


namespace maidsafe {

namespace lifestuff {

// Credentials operation interface
class UserCredentials {
 public:
  UserCredentials() {}
  virtual ~UserCredentials() {}
  virtual int CheckUserExists(const std::string &username,
                              const std::string &pin) = 0;
  virtual bool ValidateUser(const std::string &password) = 0;
  virtual bool CreateUser(const std::string &username,
                          const std::string &pin,
                          const std::string &password) = 0;
  virtual bool Logout() = 0;
  virtual int SaveSession() = 0;
  virtual bool ChangeUsername(const std::string &new_username) = 0;
  virtual bool ChangePin(const std::string &new_pin) = 0;
  virtual bool ChangePassword(const std::string &new_password) = 0;
  virtual bool LeaveMaidsafeNetwork() = 0;

  virtual std::string Username() = 0;
  virtual std::string Pin() = 0;
  virtual std::string Password() = 0;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_CLIENT_USER_CREDENTIALS_API_H_
