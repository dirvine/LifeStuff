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

namespace args = std::placeholders;

namespace maidsafe {

namespace lifestuff {

UserCredentials::UserCredentials(priv::chunk_store::RemoteChunkStore& chunk_store,
                                 Session& session,
                                 boost::asio::io_service& service,
                                 RoutingsHandler& routings_handler)
    : impl_(new UserCredentialsImpl(chunk_store, session, service, routings_handler)) {}

UserCredentials::~UserCredentials() {}

void UserCredentials::set_remote_chunk_store(priv::chunk_store::RemoteChunkStore& chunk_store) {
  impl_->set_remote_chunk_store(chunk_store);
}


int UserCredentials::CreateUser(const NonEmptyString& keyword,
                                const NonEmptyString& pin,
                                const NonEmptyString& password) {
  return impl_->CreateUser(keyword, pin, password);
}

int UserCredentials::LogIn(const NonEmptyString& keyword,
                           const NonEmptyString& pin,
                           const NonEmptyString& password) {
  return impl_->LogIn(keyword, pin, password);
}

int UserCredentials::Logout() { return impl_->LogOut(); }

int UserCredentials::SaveSession() { return impl_->SaveSession(false); }

int UserCredentials::ChangeKeyword(const NonEmptyString& new_keyword) {
  return impl_->ChangeKeyword(new_keyword);
}

int UserCredentials::ChangePin(const NonEmptyString& new_pin) {
  return impl_->ChangePin(new_pin);
}

int UserCredentials::ChangePassword(const NonEmptyString& new_password) {
  return impl_->ChangePassword(new_password);
}

int UserCredentials::DeleteUserCredentials() { return impl_->DeleteUserCredentials(); }

void UserCredentials::LogoutCompletedArrived(const std::string& session_marker) {
  impl_->LogoutCompletedArrived(session_marker);
}

bool UserCredentials::IsOwnSessionTerminationMessage(const std::string& session_marker) {
  return impl_->IsOwnSessionTerminationMessage(session_marker);
}

}  // namespace lifestuff

}  // namespace maidsafe
