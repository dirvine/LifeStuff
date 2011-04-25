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

#include "maidsafe/lifestuff/qt_ui/mock_implementation/mock_user_credentials.h"
#include <string>
#include"boost/thread.hpp"
#include "maidsafe/lifestuff/shared/returncodes.h"

namespace maidsafe {

namespace lifestuff {

MockUserCredentials::MockUserCredentials()
    : username_("valid_user"), pin_("valid_pin"),
      password_("valid_password") {}

int MockUserCredentials::CheckUserExists(const std::string &username,
                                         const std::string &pin) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  if ((username == username_) && (pin == pin_))
    return kUserExists;
  if ((username == username_) && (pin != pin_))
    return kAuthenticationError;
  else
    return kUserDoesntExist;
}

bool MockUserCredentials::ValidateUser(const std::string &password) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  if (password == password_)
    return true;
  return false;
}

bool MockUserCredentials::CreateUser(const std::string &username,
                                     const std::string &pin,
                                     const std::string &password) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  if (username.empty() || pin.empty() || password.empty())
    return false;
  if ((username.find("valid") == std::string::npos) ||
      (pin.find("valid") == std::string::npos) ||
      (password.find("valid") == std::string::npos))
    return false;

  username_ = username;
  pin_ = pin;
  password_ = password;
  return true;
}

bool MockUserCredentials::Logout() {
  boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  return true;
}

int MockUserCredentials::SaveSession() {
  boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  return kSuccess;
}

bool MockUserCredentials::ChangeUsername(const std::string &new_username) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  if (new_username.empty() || (new_username.find("valid") == std::string::npos))
    return false;

  username_ = new_username;
  return true;
}

bool MockUserCredentials::ChangePin(const std::string &new_pin) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  if (new_pin.empty() || (new_pin.find("valid") == std::string::npos))
    return false;
  pin_ = new_pin;
  return true;
}

bool MockUserCredentials::ChangePassword(const std::string &new_password) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  if (new_password.empty() || (new_password.find("valid") == std::string::npos))
    return false;
  password_ = new_password;
  return true;
}

bool MockUserCredentials::LeaveMaidsafeNetwork() {
  boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  return true;
}

}  // namespace lifestuff

}  // namespace maidsafe
