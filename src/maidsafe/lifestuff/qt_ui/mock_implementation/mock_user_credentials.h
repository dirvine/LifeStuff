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
#ifndef MAIDSAFE_LIFESTUFF_QT_UI_MOCK_USER_CREDENTIALS_H_
#define MAIDSAFE_LIFESTUFF_QT_UI_MOCK_USER_CREDENTIALS_H_

#include <string>
#include "maidsafe/lifestuff/client/user_credentials_api.h"

namespace maidsafe {

namespace lifestuff {

// Mock Credentials operation implementation
// Methods will validate only if the parameters contain substring - "valid"
class MockUserCredentials : public UserCredentials {
 public:
  MockUserCredentials();
  virtual ~MockUserCredentials() {}
  virtual int CheckUserExists(const std::string &username,
                              const std::string &pin);
  virtual bool ValidateUser(const std::string &password);
  virtual bool CreateUser(const std::string &username,
                          const std::string &pin,
                          const std::string &password);
  virtual bool Logout();
  virtual int SaveSession();
  virtual bool ChangeUsername(const std::string &new_username);
  virtual bool ChangePin(const std::string &new_pin);
  virtual bool ChangePassword(const std::string &new_password);
  virtual bool LeaveMaidsafeNetwork();
 private:
  std::string username_;
  std::string pin_;
  std::string password_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_QT_UI_MOCK_USER_CREDENTIALS_H_
