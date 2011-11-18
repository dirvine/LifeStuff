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

namespace maidsafe {

namespace lifestuff {

Session::Session()
    : user_details_(),
      passport_(new passport::Passport),
      contacts_handler_(new ContactsHandler),
      private_share_handler_(new PrivateShareHandler) {}

Session::~Session() {}

bool Session::ResetSession() {
  user_details_.defconlevel = kDefCon3;
  user_details_.da_modified = false;
  user_details_.username.clear();
  user_details_.pin.clear();
  user_details_.password.clear();
  user_details_.session_name.clear();
  user_details_.root_db_key.clear();
  user_details_.mounted = 0;
  user_details_.win_drive = '\0';
  user_details_.connection_status = 1;
  // TODO(Fraser#5#): 2011-11-17 - Implement in passport
//  passport_->ClearKeyring();
  contacts_handler_->ClearContacts();
  private_share_handler_->ClearPrivateShares();
  return true;
}


std::shared_ptr<ContactsHandler> Session::contacts_handler() const {
  return contacts_handler_;
}

std::shared_ptr<PrivateShareHandler> Session::private_share_handler() const {
  return private_share_handler_;
}

DefConLevels Session::def_con_level() const {
  return user_details_.defconlevel;
}
bool Session::da_modified() const { return user_details_.da_modified; }
std::string Session::username() const { return user_details_.username; }
std::string Session::pin() const { return user_details_.pin; }
std::string Session::password() const { return user_details_.password; }
std::string Session::public_username() const {
  return user_details_.public_username;
}
std::string Session::session_name() const { return user_details_.session_name; }
std::string Session::root_db_key() const { return user_details_.root_db_key; }
int Session::mounted() const { return user_details_.mounted; }
char Session::win_drive() const { return user_details_.win_drive; }
int Session::connection_status() const {
  return user_details_.connection_status;
}

void Session::set_def_con_level(DefConLevels defconlevel) {
  user_details_.defconlevel = defconlevel;
}
void Session::set_da_modified(bool da_modified) {
  user_details_.da_modified = da_modified;
}
void Session::set_username(const std::string &username) {
  user_details_.username = username;
}
void Session::set_pin(const std::string &pin) { user_details_.pin = pin; }
void Session::set_password(const std::string &password) {
  user_details_.password = password;
}
bool Session::set_session_name(bool clear) {
  if (clear) {
    user_details_.session_name.clear();
  } else {
    if (username().empty() || pin().empty())
      return false;
    user_details_.session_name = EncodeToHex(crypto::Hash<crypto::SHA1>(pin() +
                                                              username()));
  }
  return true;
}
void Session::set_root_db_key(const std::string &root_db_key) {
  user_details_.root_db_key = root_db_key;
}
void Session::set_mounted(int mounted) { user_details_.mounted = mounted; }
void Session::set_win_drive(char win_drive) {
  user_details_.win_drive = win_drive;
}
void Session::set_connection_status(int status) {
  user_details_.connection_status = status;
}

int Session::ParseKeyring(const std::string &serialised_keyring) {
  return passport_->ParseKeyring(serialised_keyring);
}

std::string Session::SerialiseKeyring() {
  return passport_->SerialiseKeyring();
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


