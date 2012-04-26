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

#include "maidsafe/lifestuff/user_credentials.h"

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

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/pd/client/client_container.h"
#endif

#include "maidsafe/lifestuff/authentication.h"
#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/data_atlas_pb.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/utils.h"

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
      serialised_da_(),
      surrogate_serialised_da_(),
      logging_out_(false),
      logged_in_(false) {}

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

  int n = session_->SerialiseDataAtlas(&serialised_data_atlas_);
  if (n != 0) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return false;
  }

  // Need different timestamps
  Sleep(boost::posix_time::milliseconds(1));
  n = session_->SerialiseDataAtlas(&surrogate_serialised_data_atlas_);
  if (n != 0) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return false;
  }

  result = authentication_->CreateTmidPacket(password,
                                             serialised_data_atlas_,
                                             surrogate_serialised_data_atlas_);
  if (result != kSuccess) {
    DLOG(ERROR) << "Cannot create tmid packet.";
    session_->Reset();
    return false;
  } else {
    DLOG(INFO) << "authentication_->CreateTmidPacket DONE.";
  }

  session_->set_session_name(false);
  logged_in_ = true;
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

  authentication_->GetMasterDataMap(password,
                                    &serialised_data_atlas_,
                                    &surrogate_serialised_data_atlas_);

  if (serialised_data_atlas_.empty() &&
      surrogate_serialised_data_atlas_.empty()) {
    DLOG(INFO) << "UserCredentials::ValidateUser - Invalid password";
    return false;
  } else if (!serialised_data_atlas_.empty()) {

  }

  session_->set_password(password);
  session_->set_session_name(false);

  if (ParseDa() != 0) {
    DLOG(INFO) << "UserCredentials::ValidateUser - Cannot parse DA";
    return false;
  }
  logged_in_ = true;
  return true;
}

bool UserCredentials::Logout() {
  logging_out_ = true;
//  clear_messages_thread_.join();
  int result = SaveSession();
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to save session " << result;
    return false;
  }

  serialised_da_.clear();
  logging_out_ = false;
  logged_in_ = false;
  session_->Reset();
  return true;
}

int UserCredentials::SaveSession() {
  int n = SerialiseDa();
  if (n != kSuccess) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return n;
  }

  n = authentication_->SaveSession(serialised_da_);
  if (n != kSuccess) {
    if (n == kFailedToDeleteOldPacket) {
      DLOG(WARNING) << "Failed to delete old TMID otherwise saved session OK.";
    } else {
      DLOG(ERROR) << "Failed to Save Session.";
      return n;
    }
  }
  return kSuccess;
}

bool UserCredentials::ChangeUsername(const std::string &new_username) {
  if (!CheckKeywordValidity(new_username)) {
    DLOG(ERROR) << "Incorrect input.";
    return false;
  }

  SerialiseDa();

  int result = authentication_->ChangeUsername(serialised_da_, new_username);
  if (result != kSuccess) {
    if (result == kFailedToDeleteOldPacket) {
      DLOG(WARNING) << "Failed to delete old packets, changed username OK.";
      return true;
    } else {
      DLOG(ERROR) << "Failed to change username.";
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

  SerialiseDa();

  int result = authentication_->ChangePin(serialised_da_, new_pin);
  if (result != kSuccess) {
    if (result == kFailedToDeleteOldPacket) {
      DLOG(WARNING) <<
          "Failed to delete old packets, otherwise changed PIN OK.";
      return true;
    } else {
      DLOG(ERROR) << "Failed to change PIN.";
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

  SerialiseDa();

  int result = authentication_->ChangePassword(serialised_da_, new_password);
  if (result != kSuccess) {
    DLOG(ERROR) << " Authentication failed: " << result;
    return false;
  }
  return true;
}

}  // namespace lifestuff

}  // namespace maidsafe
