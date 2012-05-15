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

#ifdef MAIDSAFE_WIN32
#  include <shlwapi.h>
#endif

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4308)
#endif
#include "boost/archive/text_oarchive.hpp"
#include "boost/archive/text_iarchive.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/detail/authentication.h"
#include "maidsafe/lifestuff/detail/contacts.h"
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
      authentication_(new Authentication(chunk_store, session)) {}

UserCredentials::~UserCredentials() {}

bool UserCredentials::CreateUser(const std::string &username,
                                 const std::string &pin,
                                 const std::string &password) {
  if (!CheckKeywordValidity(username) ||
      !CheckPinValidity(pin) ||
      !CheckPasswordValidity(password)) {
    DLOG(ERROR) << "Incorrect inputs.";
    return false;
  }
  session_->Reset();
  int result = authentication_->CreateUserSysPackets(username, pin);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to create user system packets.";
    session_->Reset();
    return false;
  } else {
    DLOG(INFO) << "authentication_->CreateUserSysPackets DONE.";
  }
  std::string serialised_data_atlas, surrogate_serialised_data_atlas;
  int n = session_->SerialiseDataAtlas(&serialised_data_atlas);
  if (n != 0) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return false;
  }
  session_->set_uc_serialised_data_atlas(serialised_data_atlas);
  // Need different timestamps
  Sleep(boost::posix_time::milliseconds(1));
  n = session_->SerialiseDataAtlas(&surrogate_serialised_data_atlas);
  if (n != 0) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return false;
  }
  session_->set_surrogate_serialised_data_atlas(
      surrogate_serialised_data_atlas);
  result = authentication_->CreateTmidPacket(password,
                                             serialised_data_atlas,
                                             surrogate_serialised_data_atlas);
  if (result != kSuccess) {
    DLOG(ERROR) << "Cannot create tmid packet.";
    session_->Reset();
    return false;
  }
  session_->set_session_name();
  session_->set_logged_in(true);
  return true;
}

int UserCredentials::CheckUserExists(const std::string &username,
                                     const std::string &pin) {
  if (!CheckKeywordValidity(username) || !CheckPinValidity(pin)) {
    DLOG(ERROR) << "Incorrect inputs.";
    return false;
  }
  session_->Reset();
  session_->set_def_con_level(kDefCon1);

  return authentication_->GetUserInfo(username, pin);
}

bool UserCredentials::ValidateUser(const std::string &password) {
  if (!CheckPasswordValidity(password)) {
    DLOG(ERROR) << "Incorrect input.";
    return false;
  }

  std::string serialised_data_atlas, surrogate_serialised_data_atlas;

  authentication_->GetMasterDataMap(password,
                                    &serialised_data_atlas,
                                    &surrogate_serialised_data_atlas);

  if (serialised_data_atlas.empty() &&
      surrogate_serialised_data_atlas.empty()) {
    DLOG(INFO) << "UserCredentials::ValidateUser - Invalid password";
    return false;
  }

  session_->set_uc_serialised_data_atlas(serialised_data_atlas);
  session_->set_surrogate_serialised_data_atlas(
      surrogate_serialised_data_atlas);

  int result(0);
  if (!serialised_data_atlas.empty())
    result = session_->ParseDataAtlas(serialised_data_atlas);
  else
    result = session_->ParseDataAtlas(surrogate_serialised_data_atlas);
  if (result != kSuccess) {
    DLOG(INFO) << "UserCredentials::ValidateUser - Can't parse DA";
    return false;
  }

  session_->set_password(password);
  result = authentication_->SetLoggedInData(serialised_data_atlas,
                                            surrogate_serialised_data_atlas);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed SetLoggedInData: " << result;
    return false;
  }

  session_->set_session_name();
  session_->set_logged_in(true);

  return true;
}

bool UserCredentials::Logout() {
  session_->set_logging_out(true);
  int result = SaveSession();
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to save session " << result;
    return false;
  }

  session_->Reset();
  return true;
}

int UserCredentials::SaveSession() {
  std::string serialised_data_atlas;
  int result(session_->SerialiseDataAtlas(&serialised_data_atlas));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return result;
  }

  session_->set_uc_serialised_data_atlas(serialised_data_atlas);

  result = authentication_->SaveSession(serialised_data_atlas);
  if (result != kSuccess) {
    if (result == kFailedToDeleteOldPacket) {
      DLOG(WARNING) << "Failed to delete old TMID otherwise saved session OK.";
    } else {
      DLOG(ERROR) << "Failed to Save Session.";
      return result;
    }
  }
  return kSuccess;
}

bool UserCredentials::ChangeUsername(const std::string &new_username) {
  if (!CheckKeywordValidity(new_username)) {
    DLOG(ERROR) << "Incorrect input.";
    return false;
  }
  std::string serialised_data_atlas;
  int result(session_->SerialiseDataAtlas(&serialised_data_atlas));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to serialise session elements: " << result;
    return false;
  }
  session_->set_uc_serialised_data_atlas(serialised_data_atlas);

  result = authentication_->ChangeUsername(serialised_data_atlas,
                                           new_username);
  if (result != kSuccess) {
    if (result == kFailedToDeleteOldPacket) {
      DLOG(WARNING) << "Failed to delete old packets, changed username OK.";
      return true;
    } else {
      DLOG(ERROR) << "Failed to change username: " << result;
      return false;
    }
  }
  return true;
}

bool UserCredentials::ChangePin(const std::string &new_pin) {
  if (!CheckPinValidity(new_pin)) {
    DLOG(ERROR) << "Incorrect input.";
    return false;
  }

  std::string serialised_data_atlas;
  int result(session_->SerialiseDataAtlas(&serialised_data_atlas));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to serialise session elements: " << result;
    return false;
  }

  session_->set_uc_serialised_data_atlas(serialised_data_atlas);

  result = authentication_->ChangePin(serialised_data_atlas, new_pin);
  if (result != kSuccess) {
    if (result == kFailedToDeleteOldPacket) {
      DLOG(WARNING) <<
          "Failed to delete old packets, otherwise changed PIN OK.";
      return true;
    } else {
      DLOG(ERROR) << "Failed to change PIN: " << result;
      return false;
    }
  }
  return true;
}

bool UserCredentials::ChangePassword(const std::string &new_password) {
  if (!CheckPasswordValidity(new_password)) {
    DLOG(ERROR) << "Incorrect input.";
    return false;
  }

  std::string serialised_data_atlas;
  int result(session_->SerialiseDataAtlas(&serialised_data_atlas));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to serialise session elements: " << result;
    return false;
  }

  session_->set_uc_serialised_data_atlas(serialised_data_atlas);

  result = authentication_->ChangePassword(serialised_data_atlas,
                                           new_password);
  if (result != kSuccess) {
    DLOG(ERROR) << " change password failed: " << result;
    return false;
  }
  return true;
}

}  // namespace lifestuff

}  // namespace maidsafe
