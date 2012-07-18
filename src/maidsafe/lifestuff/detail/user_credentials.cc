/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  class which controls all maidsafe client operations
* Version:      1.0
* Created:      2009-01-28-10.59.46
* Revision:     none
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENCE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include "maidsafe/lifestuff/detail/user_credentials.h"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/detail/user_credentials_impl.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace args = std::placeholders;

namespace maidsafe {

namespace lifestuff {

UserCredentials::UserCredentials(pcs::RemoteChunkStore& chunk_store,
                                 Session& session,
                                 boost::asio::io_service& service)
    : session_(session),
      impl_(new UserCredentialsImpl(chunk_store, session, service)) {}

UserCredentials::~UserCredentials() {}

int UserCredentials::CreateUser(const std::string &keyword,
                                const std::string &pin,
                                const std::string &password) {
  int result(CheckKeywordValidity(keyword));
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid keyword: " << keyword << "    Return code: " << result << ")";
    return result;
  }
  result = CheckPinValidity(pin);
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid pin: " << pin << "    Return code: " << result << ")";
    return result;
  }
  result = CheckPasswordValidity(password);
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid password: " << password << "    (Return code: " << result << ")";
    return result;
  }

  return impl_->CreateUser(keyword, pin, password);
}

int UserCredentials::LogIn(const std::string &keyword,
                           const std::string &pin,
                           const std::string &password) {
  int result(CheckKeywordValidity(keyword));
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid keyword: " << keyword << "    Return code: " << result << ")";
    return result;
  }
  result = CheckPinValidity(pin);
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid pin: " << pin << "    Return code: " << result << ")";
    return result;
  }
  result = CheckPasswordValidity(password);
  if (result != kSuccess) {
    LOG(kInfo) << "Invalid password: " << password << "    Return code: " << result << ")";
    return result;
  }

  return impl_->GetUserInfo(keyword, pin, password);
}

int UserCredentials::Logout() {
  int result(impl_->SaveSession(true));
  if (result == kSuccess)
    session_.Reset();

  if (result == kSuccess) {
    session_.Reset();
    return kSuccess;
  } else {
    return result;
  }
}

int UserCredentials::SaveSession() { return impl_->SaveSession(false); }

int UserCredentials::ChangeKeyword(const std::string &new_keyword) {
  int result(CheckKeywordValidity(new_keyword));
  if (result != kSuccess) {
    LOG(kError) << "Incorrect input.";
    return result;
  }

  return impl_->ChangeKeyword(new_keyword);
}

int UserCredentials::ChangePin(const std::string &new_pin) {
  int result(CheckPinValidity(new_pin));
  if (result != kSuccess) {
    LOG(kError) << "Incorrect input.";
    return result;
  }

  return impl_->ChangePin(new_pin);
}

int UserCredentials::ChangePassword(const std::string &new_password) {
  int result(CheckPasswordValidity(new_password));
  if (result != kSuccess) {
    LOG(kError) << "Incorrect input.";
    return result;
  }

  return impl_->ChangePassword(new_password);
}

int UserCredentials::DeleteUserCredentials() {
  return impl_->DeleteUserCredentials();
}

}  // namespace lifestuff

}  // namespace maidsafe
