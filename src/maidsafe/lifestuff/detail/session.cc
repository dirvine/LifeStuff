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

#include "maidsafe/lifestuff/detail/session.h"

#include <memory>
#include <vector>
#include <limits>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace maidsafe {

namespace lifestuff {

SocialInfo::SocialInfo(const NonEmptyString& picture_datamap,
                       const Identity& the_card_address)
    : profile_picture_datamap(picture_datamap),
      card_address(the_card_address) {}

PublicIdDetails::PublicIdDetails() : social_info(std::make_shared<SocialInfo>(kBlankProfilePicture,
                                                                              Identity())),
                                     contacts_handler(std::make_shared<ContactsHandler>()),
                                     social_info_mutex(std::make_shared<std::mutex>()) {}

PublicIdDetails::PublicIdDetails(const Identity& card_address)
    : social_info(std::make_shared<SocialInfo>(kBlankProfilePicture, card_address)),
      contacts_handler(std::make_shared<ContactsHandler>()),
      social_info_mutex(std::make_shared<std::mutex>()) {}

PublicIdDetails& PublicIdDetails::operator=(const PublicIdDetails& other) {
  this->social_info = other.social_info;
  this->contacts_handler = other.contacts_handler;
  this->social_info_mutex = other.social_info_mutex;
  return *this;
}

PublicIdDetails::PublicIdDetails(const PublicIdDetails& other)
    : social_info(other.social_info),
      contacts_handler(other.contacts_handler),
      social_info_mutex(other.social_info_mutex) {}

Session::Session()
    : passport_(),
      user_details_(),
      user_details_mutex_(),
      public_id_details_(),
      public_id_details_mutex_() {}

Session::~Session() {}

void Session::Reset() {
  {
    std::unique_lock<std::mutex> lock(user_details_mutex_);
    user_details_.defconlevel = DefConLevels::kDefCon3;
    user_details_.keyword = NonEmptyString();
    user_details_.pin = NonEmptyString();
    user_details_.password = NonEmptyString();
    user_details_.session_name = NonEmptyString();
    user_details_.unique_user_id = Identity();
    user_details_.root_parent_id.clear();
    user_details_.max_space = 1073741824;
    user_details_.used_space = 0;
    user_details_.serialised_data_atlas = NonEmptyString();
    user_details_.changed = false;
    user_details_.has_drive_data = false;
    user_details_.session_access_level = kNoAccess;
  }

  passport_.Clear(true, true, true);
  {
    std::unique_lock<std::mutex> lock(public_id_details_mutex_);
    public_id_details_.clear();
  }
}

passport::Passport& Session::passport() { return passport_; }

int Session::AddPublicId(const NonEmptyString& public_id, const Identity& pointer_to_card) {
  {
    std::unique_lock<std::mutex> lock(public_id_details_mutex_);
    auto result(public_id_details_.insert(std::make_pair(public_id,
                                                         PublicIdDetails(pointer_to_card))));
    if (!result.second) {
      LOG(kError) << "Failure to add public id to session: " << public_id.string();
      return kPublicIdInsertionFailure;
    }
  }

  {
    std::unique_lock<std::mutex> lock(user_details_mutex_);
    user_details_.changed = true;
  }

  return kSuccess;
}

int Session::DeletePublicId(const NonEmptyString& public_id) {
  {
    std::unique_lock<std::mutex> lock(user_details_mutex_);
    user_details_.changed = true;
  }

  std::unique_lock<std::mutex> lock(public_id_details_mutex_);
  return public_id_details_.erase(public_id) == size_t(1) ? kSuccess : kPublicIdNotFoundFailure;
}

bool Session::OwnPublicId(const NonEmptyString& public_id) {
  std::unique_lock<std::mutex> lock(public_id_details_mutex_);
  return public_id_details_.find(public_id) != public_id_details_.end();
}

const ContactsHandlerPtr Session::contacts_handler(const NonEmptyString& public_id) {
  std::unique_lock<std::mutex> lock(public_id_details_mutex_);
  auto it(public_id_details_.find(public_id));
  if (it == public_id_details_.end()) {
    LOG(kError) << "Failure to find public id: " << public_id.string();
    return ContactsHandlerPtr();
  }

  return (*it).second.contacts_handler;
}

const SocialInfoDetail Session::social_info(const NonEmptyString& public_id) {
  SocialInfoDetail social_info_detail;
  {
    std::unique_lock<std::mutex> lock(public_id_details_mutex_);
    auto it(public_id_details_.find(public_id));
    if (it == public_id_details_.end()) {
      LOG(kError) << "Failure to find public id: " << public_id.string();
      return social_info_detail;
    }

    social_info_detail.first = (*it).second.social_info_mutex;
    social_info_detail.second = (*it).second.social_info;
  }

  return social_info_detail;
}

DefConLevels Session::def_con_level() const {
  return user_details_.defconlevel;
}

NonEmptyString Session::keyword() const {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  return user_details_.keyword;
}

NonEmptyString Session::pin() const {
  return user_details_.pin;
}

NonEmptyString Session::password() const {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  return user_details_.password;
}

NonEmptyString Session::session_name() const {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  return user_details_.session_name;
}

Identity Session::unique_user_id() const {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  return user_details_.unique_user_id;
}

std::string Session::root_parent_id() const {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  return user_details_.root_parent_id;
}

int64_t Session::max_space() const {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  return user_details_.max_space;
}

int64_t Session::used_space() const {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  return user_details_.used_space;
}

NonEmptyString Session::serialised_data_atlas() const {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  return user_details_.serialised_data_atlas;
}

bool Session::changed() const {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  return user_details_.changed;
}

bool Session::has_drive_data() const {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  return user_details_.has_drive_data;
}

SessionAccessLevel Session::session_access_level() const {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  return user_details_.session_access_level;
}

void Session::set_def_con_level(DefConLevels defconlevel) {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  user_details_.defconlevel = defconlevel;
}

void Session::set_keyword(const NonEmptyString& keyword) {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  user_details_.keyword = keyword;
}

void Session::set_pin(const NonEmptyString& pin) {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  user_details_.pin = pin;
}

void Session::set_password(const NonEmptyString& password) {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  user_details_.password = password;
}

void Session::set_session_name() {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  user_details_.session_name =
      NonEmptyString(EncodeToHex(crypto::Hash<crypto::SHA1>(
                                     user_details_.pin +
                                     user_details_.keyword +
                                     NonEmptyString(RandomAlphaNumericString(8)))));
}

void Session::clear_session_name() {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  user_details_.session_name = NonEmptyString();
}

void Session::set_unique_user_id(const Identity& unique_user_id) {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  user_details_.unique_user_id = unique_user_id;
}

void Session::set_root_parent_id(const std::string& root_parent_id) {
  if (root_parent_id.empty())
    LOG(kWarning) << "Passed empty root parent ID.";

  std::unique_lock<std::mutex> lock(user_details_mutex_);
  user_details_.root_parent_id = root_parent_id;
}

void Session::set_max_space(const int64_t& max_space) {
  if (max_space == 0)
    LOG(kWarning) << "Passed zero maximum space.";

  std::unique_lock<std::mutex> lock(user_details_mutex_);
  user_details_.max_space = max_space;
}

void Session::set_used_space(const int64_t& used_space) {
  if (used_space > user_details_.max_space)
    LOG(kWarning) << "Passed used space greater than maximum.";

  std::unique_lock<std::mutex> lock(user_details_mutex_);
  user_details_.used_space = used_space;
}

void Session::set_serialised_data_atlas(const NonEmptyString& serialised_data_atlas) {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  user_details_.serialised_data_atlas = serialised_data_atlas;
}

void Session::set_changed(bool state) {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  user_details_.changed = state;
}

void Session::set_has_drive_data(bool has_drive_data) {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  user_details_.has_drive_data = has_drive_data;
}

void Session::set_session_access_level(SessionAccessLevel session_access_level) {
  std::unique_lock<std::mutex> lock(user_details_mutex_);
  user_details_.session_access_level = session_access_level;
}

int Session::ParseDataAtlas(const NonEmptyString& serialised_data_atlas) {
  DataAtlas data_atlas;
  if (!data_atlas.ParseFromString(serialised_data_atlas.string())) {
    LOG(kError) << "TMID doesn't parse.";
    return kParseDataAtlasTmidDoesNotParse;
  }

  if (data_atlas.has_drive_data()) {
    set_has_drive_data(true);
    if (data_atlas.drive_data().unique_user_id().empty()) {
      LOG(kError) << "Unique user ID is empty.";
      return kTryAgainLater;
    }
    if (data_atlas.drive_data().root_parent_id().empty()) {
      LOG(kError) << "Root parent id is empty.";
      return kTryAgainLater;
    }

    set_unique_user_id(Identity(data_atlas.drive_data().unique_user_id()));
    set_root_parent_id(data_atlas.drive_data().root_parent_id());
    set_max_space(data_atlas.drive_data().max_space());
    set_used_space(data_atlas.drive_data().used_space());
  }

  int result(passport_.Parse(NonEmptyString(data_atlas.passport_data().serialised_keyring())));
  if (result != kSuccess) {
    LOG(kError) << "Failed ParseKeyChain: " << result;
    return kParseDataAtlasKeyringDoesNotParse;
  }

  NonEmptyString pub_id;
  for (int id_count(0); id_count < data_atlas.public_ids_size(); ++id_count) {
    pub_id = NonEmptyString(data_atlas.public_ids(id_count).public_id());
    PublicIdDetails public_id_details;
    public_id_details.social_info->profile_picture_datamap =
        NonEmptyString(data_atlas.public_ids(id_count).profile_picture_data_map());
    public_id_details.social_info->card_address =
        Identity(data_atlas.public_ids(id_count).pointer_to_info());

    for (int contact_count(0);
         contact_count < data_atlas.public_ids(id_count).contacts_size();
         ++contact_count) {
      Contact contact(data_atlas.public_ids(id_count).contacts(contact_count));
      contact.mpid_public_key =
          asymm::DecodeKey(asymm::EncodedPublicKey(
              data_atlas.public_ids(id_count).contacts(contact_count).mpid_public_key()));
      contact.inbox_public_key =
          asymm::DecodeKey(asymm::EncodedPublicKey(
              data_atlas.public_ids(id_count).contacts(contact_count).inbox_public_key()));
      int add_contact_result(public_id_details.contacts_handler->AddContact(contact));
      LOG(kInfo) << "Result of adding " << contact.public_id.string()
                 << " to " << pub_id.string() << ":  " << add_contact_result;
    }

    public_id_details_[pub_id] = public_id_details;
  }

  return kSuccess;
}

NonEmptyString Session::SerialiseDataAtlas() {
  DataAtlas data_atlas;

  if (has_drive_data()) {
    DriveData* drive_data(data_atlas.mutable_drive_data());
    drive_data->set_unique_user_id(unique_user_id().string());
    drive_data->set_root_parent_id(root_parent_id());
    drive_data->set_max_space(max_space());
    drive_data->set_used_space(used_space());
  }

  data_atlas.set_timestamp(boost::lexical_cast<std::string>(
      GetDurationSinceEpoch().total_microseconds()));

  NonEmptyString serialised_keyring(passport_.Serialise());
  PassportData* passport_data(data_atlas.mutable_passport_data());
  passport_data->set_serialised_keyring(serialised_keyring.string());

  std::vector<Contact> contacts;
  for (auto it(public_id_details_.begin()); it != public_id_details_.end(); ++it) {
    PublicIdentity* pub_id(data_atlas.add_public_ids());
    pub_id->set_public_id((*it).first.string());
    {
      std::unique_lock<std::mutex> lock(*(*it).second.social_info_mutex);
      pub_id->set_profile_picture_data_map(
          (*it).second.social_info->profile_picture_datamap.string());
      pub_id->set_pointer_to_info((*it).second.social_info->card_address.string());
    }
    (*it).second.contacts_handler->OrderedContacts(&contacts, kAlphabetical, kRequestSent |
                                                                             kPendingResponse |
                                                                             kConfirmed |
                                                                             kBlocked);
    for (size_t n(0); n < contacts.size(); ++n) {
      PublicContact* pc(pub_id->add_contacts());
      pc->set_public_id(contacts[n].public_id.string());
      pc->set_mpid_name(contacts[n].mpid_name.string());
      pc->set_inbox_name(contacts[n].inbox_name.string());
      asymm::EncodedPublicKey serialised_mpid_public_key(
                                  asymm::EncodeKey(contacts[n].mpid_public_key)),
                              serialised_inbox_public_key(
                                  asymm::EncodeKey(contacts[n].inbox_public_key));
      pc->set_mpid_public_key(serialised_mpid_public_key.string());
      pc->set_inbox_public_key(serialised_inbox_public_key.string());
      pc->set_status(contacts[n].status);
      pc->set_rank(contacts[n].rank);
      pc->set_last_contact(contacts[n].last_contact);
      pc->set_profile_picture_data_map(contacts[n].profile_picture_data_map.string());
      pc->set_pointer_to_info(contacts[n].pointer_to_info.string());
      LOG(kInfo) << "Added contact " << contacts[n].public_id.string()
                 << " to " << (*it).first.string() << " map.";
    }
  }

  return NonEmptyString(data_atlas.SerializeAsString());
}

bool Session::CreateTestPackets(bool with_public_ids, std::vector<NonEmptyString>& public_ids) {
  passport_.CreateSigningPackets();
  if (passport_.ConfirmSigningPackets() != kSuccess)
    return false;

  if (with_public_ids) {
    for (size_t n(0); n < 5; ++n) {
      NonEmptyString public_id((RandomAlphaNumericString(5)));
      passport_.CreateSelectableIdentity(public_id);
      if (passport_.ConfirmSelectableIdentity(public_id) != kSuccess)
        return false;
      public_ids.push_back(public_id);
    }
  }

  return true;
}

std::vector<NonEmptyString> Session::PublicIdentities() const {
  std::vector<NonEmptyString> public_identities;
  typedef std::map<NonEmptyString, PublicIdDetails> PublicIdDetailsMap;
  std::for_each(public_id_details_.begin(),
                public_id_details_.end(),
                [&public_identities] (const PublicIdDetailsMap::value_type &el) {
                  public_identities.push_back(el.first);
                });
  return public_identities;
}

}  // namespace lifestuff

}  // namespace maidsafe


