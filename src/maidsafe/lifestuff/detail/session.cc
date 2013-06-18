/***************************************************************************************************
 *  Copyright 2013 MaidSafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use.  The use of this code is governed by the licence file licence.txt found in the root of    *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit         *
 *  written permission of the board of directors of MaidSafe.net.                                  *
 **************************************************************************************************/

#include "maidsafe/lifestuff/detail/session.h"

#include <memory>
#include <vector>
#include <limits>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/detail/data_atlas.pb.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace maidsafe {
namespace lifestuff {

Session::Session()
    : passport_(),
      bootstrap_endpoints_(),
      user_details_(),
      initialised_(false),
      keyword_(),
      pin_(),
      password_() {}

Session::~Session() {}

Session::Passport& Session::passport() {
  return passport_;
}

NonEmptyString Session::session_name() const {
  return user_details_.session_name;
}

Identity Session::unique_user_id() const {
  return user_details_.unique_user_id;
}

std::string Session::root_parent_id() const {
  return user_details_.root_parent_id;
}

boost::filesystem::path Session::vault_path() const {
  return user_details_.vault_path;
}

int64_t Session::max_space() const {
  return user_details_.max_space;
}

int64_t Session::used_space() const {
  return user_details_.used_space;
}

bool Session::initialised() {
  return initialised_;
}

const Keyword& Session::keyword() const {
  return *keyword_;
}

const Pin& Session::pin() const {
  return *pin_;
}

const Password& Session::password() const {
  return *password_;
}

void Session::set_session_name() {
  NonEmptyString random(RandomAlphaNumericString(64));
  user_details_.session_name = NonEmptyString(EncodeToHex(crypto::Hash<crypto::SHA1>(random)));
}

void Session::set_unique_user_id(const Identity& unique_user_id) {
  user_details_.unique_user_id = unique_user_id;
}

void Session::set_root_parent_id(const std::string& root_parent_id) {
  user_details_.root_parent_id = root_parent_id;
}

void Session::set_vault_path(const boost::filesystem::path& vault_path) {
  user_details_.vault_path = vault_path;
}

void Session::set_max_space(const int64_t& max_space) {
  user_details_.max_space = max_space;
}

void Session::set_used_space(const int64_t& used_space) {
  user_details_.used_space = used_space;
}

void Session::set_initialised() {
  initialised_ = true;
}

void Session::set_keyword(const Keyword& keyword) {  
  keyword_.reset(new Keyword(keyword.string()));
  return;
}

void Session::set_pin(const Pin& pin) {
  pin_.reset(new Pin(pin.string()));
  return;
}

void Session::set_password(const Password& password) {
  password_.reset(new Password(password.string()));
  return;
}

void Session::set_keyword_pin_password(const Keyword& keyword,
                                       const Pin& pin,
                                       const Password& password) {
  set_keyword(keyword);
  set_pin(pin);
  set_password(password);
  return;
}

void Session::set_bootstrap_endpoints(const std::vector<Endpoint>& bootstrap_endpoints) {
  bootstrap_endpoints_ = bootstrap_endpoints;
}

std::vector<std::pair<std::string, uint16_t> > Session::bootstrap_endpoints() const {
  return bootstrap_endpoints_;
}

void Session::Parse(const NonEmptyString& serialised_data_atlas) {
  DataAtlas data_atlas;
  data_atlas.ParseFromString(serialised_data_atlas.string());

  if (data_atlas.user_data().unique_user_id().empty()) {
    LOG(kError) << "Unique user ID is empty.";
    return;
  }

  set_unique_user_id(Identity(data_atlas.user_data().unique_user_id()));
  set_root_parent_id(data_atlas.user_data().root_parent_id());
  set_vault_path(data_atlas.user_data().vault_path());
  set_max_space(data_atlas.user_data().max_space());
  set_used_space(data_atlas.user_data().used_space());

  passport_.Parse(NonEmptyString(data_atlas.passport_data().serialised_keyring()));

  return;
}

NonEmptyString Session::Serialise() {
  DataAtlas data_atlas;

  UserData* user_data(data_atlas.mutable_user_data());
  user_data->set_unique_user_id(unique_user_id().string());
  user_data->set_root_parent_id(root_parent_id());
  user_data->set_vault_path(vault_path().string());
  user_data->set_max_space(max_space());
  user_data->set_used_space(used_space());

  data_atlas.set_timestamp(boost::lexical_cast<std::string>(
      GetDurationSinceEpoch().total_microseconds()));

  NonEmptyString serialised_keyring(passport_.Serialise());
  PassportData* passport_data(data_atlas.mutable_passport_data());
  passport_data->set_serialised_keyring(serialised_keyring.string());

  return NonEmptyString(data_atlas.SerializeAsString());
}

}  // namespace lifestuff
}  // namespace maidsafe
