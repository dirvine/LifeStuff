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

#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/detail/authentication.h"
#include "maidsafe/lifestuff/detail/new_auth.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace args = std::placeholders;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

UserCredentials::UserCredentials(
    std::shared_ptr<pcs::RemoteChunkStore> chunk_store,
    std::shared_ptr<Session> session)
    : session_(session),
      remote_chunk_store_(chunk_store),
      authentication_(new Authentication(chunk_store, session)),
      impl_(new NewAuthentication(chunk_store, session)) {}

UserCredentials::~UserCredentials() {}

int UserCredentials::CreateUser(const std::string &keyword,
                                const std::string &pin,
                                const std::string &password) {
  if (!CheckKeywordValidity(keyword) ||
      !CheckPinValidity(pin) ||
      !CheckPasswordValidity(password)) {
    DLOG(ERROR) << "Incorrect inputs.";
    return kCredentialValidityFailure;
  }

  return impl_->CreateUser(keyword, pin, password);
}

int UserCredentials::LogIn(const std::string &keyword,
                           const std::string &pin,
                           const std::string &password) {
  if (!CheckKeywordValidity(keyword) ||
      !CheckPinValidity(pin) ||
      !CheckPasswordValidity(password)) {
    DLOG(ERROR) << "Incorrect inputs.";
    return kCredentialValidityFailure;
  }

  return impl_->GetUserInfo(keyword, pin, password);
}

int UserCredentials::Logout() { return impl_->SaveSession(); }

int UserCredentials::SaveSession() { return impl_->SaveSession(); }

int UserCredentials::ChangeKeyword(const std::string &new_keyword) {
  if (!CheckKeywordValidity(new_keyword)) {
    DLOG(ERROR) << "Incorrect input.";
    return kChangeUsernamePinFailure;
  }

  return impl_->ChangeUsernamePin(new_keyword, session_->pin());
}

int UserCredentials::ChangePin(const std::string &new_pin) {
  if (!CheckPinValidity(new_pin)) {
    DLOG(ERROR) << "Incorrect input.";
    return kChangeUsernamePinFailure;
  }

  return impl_->ChangeUsernamePin(session_->keyword(), new_pin);
}

int UserCredentials::ChangePassword(const std::string &new_password) {
  if (!CheckPasswordValidity(new_password)) {
    DLOG(ERROR) << "Incorrect input.";
    return kChangeUsernamePinFailure;
  }

  return impl_->ChangePassword(new_password);
}

}  // namespace lifestuff

}  // namespace maidsafe
