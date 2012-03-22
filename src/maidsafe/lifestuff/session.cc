/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Singleton for setting/getting session info
* Version:      1.0
* Created:      2009-01-28-16.56.20
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#include "maidsafe/lifestuff/session.h"

#include <memory>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/data_atlas_pb.h"
#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/return_codes.h"

namespace maidsafe {

namespace lifestuff {

struct UserDetails {
  UserDetails()
      : defconlevel(kDefCon3),
        username(),
        pin(),
        password(),
        session_name(),
        unique_user_id(),
        root_parent_id(),
        profile_picture_data_map() {}
  DefConLevels defconlevel;
  std::string username, pin, password, session_name, unique_user_id,
              root_parent_id, profile_picture_data_map;
};

Session::Session()
    : user_details_(new UserDetails),
      passport_(new passport::Passport),
      contact_handler_map_() {}

Session::~Session() {}

bool Session::Reset() {
  user_details_->defconlevel = kDefCon3;
  user_details_->username.clear();
  user_details_->pin.clear();
  user_details_->password.clear();
  user_details_->session_name.clear();
  user_details_->unique_user_id.clear();
  user_details_->root_parent_id.clear();
  user_details_->profile_picture_data_map.clear();
  // TODO(Fraser#5#): 2011-11-17 - Implement in passport
  passport_->ClearKeyChain(true, true, true);
  contact_handler_map_.clear();
  return true;
}

ContactHandlerMap& Session::contact_handler_map() {
  return contact_handler_map_;
}

DefConLevels Session::def_con_level() const {
  return user_details_->defconlevel;
}
std::string Session::username() const { return user_details_->username; }
std::string Session::pin() const { return user_details_->pin; }
std::string Session::password() const { return user_details_->password; }
std::string Session::session_name() const {
  return user_details_->session_name;
}
std::string Session::unique_user_id() const {
  return user_details_->unique_user_id;
}
std::string Session::root_parent_id() const {
  return user_details_->root_parent_id;
}
std::string Session::profile_picture_data_map() const {
  return user_details_->profile_picture_data_map;
}

void Session::set_def_con_level(DefConLevels defconlevel) {
  user_details_->defconlevel = defconlevel;
}
void Session::set_username(const std::string &username) {
  user_details_->username = username;
}
void Session::set_pin(const std::string &pin) { user_details_->pin = pin; }
void Session::set_password(const std::string &password) {
  user_details_->password = password;
}
bool Session::set_session_name(bool clear) {
  if (clear) {
    user_details_->session_name.clear();
  } else {
    if (username().empty() || pin().empty())
      return false;
    user_details_->session_name = EncodeToHex(crypto::Hash<crypto::SHA1>(pin() +
                                                              username()));
  }
  return true;
}
void Session::set_unique_user_id(const std::string &unique_user_id) {
  user_details_->unique_user_id = unique_user_id;
}
void Session::set_root_parent_id(const std::string &root_parent_id) {
  user_details_->root_parent_id = root_parent_id;
}
void Session::set_profile_picture_data_map(
    const std::string &profile_picture_data_map) {
  user_details_->profile_picture_data_map = profile_picture_data_map;
}

int Session::ParseKeyChain(const std::string &serialised_keyring,
                           const std::string &serialised_selectables) {
  return passport_->ParseKeyChain(serialised_keyring, serialised_selectables);
}
void Session::SerialiseKeyChain(std::string *serialised_keyring,
                                std::string *serialised_selectables) {
  passport_->SerialiseKeyChain(serialised_keyring, serialised_selectables);
}

bool Session::CreateTestPackets() {
  if (passport_->CreateSigningPackets() != kSuccess)
    return false;
  if (passport_->ConfirmSigningPackets() != kSuccess)
    return false;
  return true;
}

}  // namespace lifestuff

}  // namespace maidsafe


