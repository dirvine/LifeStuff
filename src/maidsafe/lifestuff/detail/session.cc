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

PublicIdDetails::PublicIdDetails() : social_info(new SocialInfo),
                                     contacts_handler(new ContactsHandler),
                                     share_information(new ShareInformation),
                                     social_info_mutex(new std::mutex),
                                     share_information_mutex(new std::mutex) {
  social_info->push_back(kBlankProfilePicture);
  social_info->push_back("");
}

PublicIdDetails::PublicIdDetails(const std::string& card_address)
    : social_info(new SocialInfo),
      contacts_handler(new ContactsHandler),
      share_information(new ShareInformation),
      social_info_mutex(new std::mutex),
      share_information_mutex(new std::mutex) {
  social_info->push_back(kBlankProfilePicture);
  social_info->push_back(card_address);
}

PublicIdDetails& PublicIdDetails::operator=(const PublicIdDetails& other) {
  this->social_info = other.social_info;
  this->contacts_handler = other.contacts_handler;
  this->share_information = other.share_information;
  this->social_info_mutex = other.social_info_mutex;
  this->share_information_mutex = other.share_information_mutex;
  return *this;
}

PublicIdDetails::PublicIdDetails(const PublicIdDetails& other)
    : social_info(other.social_info),
      contacts_handler(other.contacts_handler),
      share_information(other.share_information),
      social_info_mutex(other.social_info_mutex),
      share_information_mutex(other.share_information_mutex) {}

Session::Session()
    : passport_(),
      user_details_(),
      user_details_mutex_(),
      public_id_details_(),
      public_id_details_mutex_() {}

Session::~Session() {}

void Session::Reset() {
  {
    std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
    user_details_.defconlevel = DefConLevels::kDefCon3;
    user_details_.keyword.clear();
    user_details_.pin.clear();
    user_details_.password.clear();
    user_details_.session_name.clear();
    user_details_.unique_user_id.clear();
    user_details_.root_parent_id.clear();
    user_details_.max_space = 1073741824;
    user_details_.used_space = 0;
    user_details_.serialised_data_atlas.clear();
    user_details_.changed = false;
    user_details_.session_access_level = kNoAccess;
  }

  passport_.Clear(true, true, true);
  {
    std::unique_lock<std::mutex> arran_coire_fhionn_lochan(public_id_details_mutex_);
    public_id_details_.clear();
  }
}

passport::Passport& Session::passport() { return passport_; }

int Session::AddPublicId(const std::string& public_id, const std::string& pointer_to_card) {
  {
    std::unique_lock<std::mutex> arran_coire_fhionn_lochan(public_id_details_mutex_);
    auto result(public_id_details_.insert(std::make_pair(public_id,
                                                         PublicIdDetails(pointer_to_card))));
    if (!result.second) {
      LOG(kError) << "Failure to add public id to session: " << public_id;
      return kPublicIdInsertionFailure;
    }
  }

  {
    std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
    user_details_.changed = true;
  }

  return kSuccess;
}

int Session::DeletePublicId(const std::string& public_id) {
  {
    std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
    user_details_.changed = true;
  }

  std::unique_lock<std::mutex> arran_coire_fhionn_lochan(public_id_details_mutex_);
  return public_id_details_.erase(public_id) == size_t(1) ? kSuccess : kPublicIdNotFoundFailure;
}

bool Session::OwnPublicId(const std::string& public_id) {
  std::unique_lock<std::mutex> arran_coire_fhionn_lochan(public_id_details_mutex_);
  return public_id_details_.find(public_id) != public_id_details_.end();
}

const ContactsHandlerPtr Session::contacts_handler(const std::string& public_id) {
  std::unique_lock<std::mutex> arran_coire_fhionn_lochan(public_id_details_mutex_);
  auto it(public_id_details_.find(public_id));
  if (it == public_id_details_.end()) {
    LOG(kError) << "Failure to find public id: " << public_id;
    return ContactsHandlerPtr();
  }

  return (*it).second.contacts_handler;
}

const ShareInformationDetail Session::share_information(const std::string& public_id) {
  ShareInformationDetail share_information_detail;
  {
    std::unique_lock<std::mutex> arran_coire_fhionn_lochan(public_id_details_mutex_);
    auto it(public_id_details_.find(public_id));
    if (it == public_id_details_.end()) {
      LOG(kError) << "Failure to find public id: " << public_id;
      return share_information_detail;
    }

    share_information_detail.first = (*it).second.share_information_mutex;
    share_information_detail.second = (*it).second.share_information;
  }

  return share_information_detail;
}

const SocialInfoDetail Session::social_info(const std::string& public_id) {
  SocialInfoDetail social_info_detail;
  {
    std::unique_lock<std::mutex> arran_coire_fhionn_lochan(public_id_details_mutex_);
    auto it(public_id_details_.find(public_id));
    if (it == public_id_details_.end()) {
      LOG(kError) << "Failure to find public id: " << public_id;
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

std::string Session::keyword() const {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  return user_details_.keyword;
}

std::string Session::pin() const {
  return user_details_.pin;
}

std::string Session::password() const {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  return user_details_.password;
}

std::string Session::session_name() const {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  return user_details_.session_name;
}

std::string Session::unique_user_id() const {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  return user_details_.unique_user_id;
}

std::string Session::root_parent_id() const {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  return user_details_.root_parent_id;
}

int64_t Session::max_space() const {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  return user_details_.max_space;
}

int64_t Session::used_space() const {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  return user_details_.used_space;
}

std::string Session::serialised_data_atlas() const {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  return user_details_.serialised_data_atlas;
}

bool Session::changed() const {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  return user_details_.changed;
}

SessionAccessLevel Session::session_access_level() const {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  return user_details_.session_access_level;
}

void Session::set_def_con_level(DefConLevels defconlevel) {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  user_details_.defconlevel = defconlevel;
}

void Session::set_keyword(const std::string& keyword) {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  user_details_.keyword = keyword;
}

void Session::set_pin(const std::string& pin) {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  user_details_.pin = pin;
}

void Session::set_password(const std::string& password) {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  user_details_.password = password;
}

bool Session::set_session_name() {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  if (user_details_.keyword.empty() || user_details_.pin.empty()) {
    LOG(kError) << "keyword: " << std::boolalpha << user_details_.keyword.empty()
                << ", pin: " << std::boolalpha << user_details_.pin.empty();
    return false;
  }

  user_details_.session_name = EncodeToHex(crypto::Hash<crypto::SHA1>(user_details_.pin +
                                                                      user_details_.keyword +
                                                                      RandomAlphaNumericString(8)));
  return true;
}

void Session::clear_session_name() {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  user_details_.session_name.clear();
}

void Session::set_unique_user_id(const std::string& unique_user_id) {
  if (unique_user_id.empty())
    LOG(kWarning) << "Passed empty unique user ID.";

  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  user_details_.unique_user_id = unique_user_id;
}

void Session::set_root_parent_id(const std::string& root_parent_id) {
  if (root_parent_id.empty())
    LOG(kWarning) << "Passed empty root parent ID.";

  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  user_details_.root_parent_id = root_parent_id;
}

void Session::set_max_space(const int64_t& max_space) {
  if (max_space == 0)
    LOG(kWarning) << "Passed zero maximum space.";

  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  user_details_.max_space = max_space;
}

void Session::set_used_space(const int64_t& used_space) {
  if (used_space > user_details_.max_space)
    LOG(kWarning) << "Passed used space greater than maximum.";

  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  user_details_.used_space = used_space;
}

void Session::set_serialised_data_atlas(const std::string& serialised_data_atlas) {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  user_details_.serialised_data_atlas = serialised_data_atlas;
}

void Session::set_changed(bool state) {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  user_details_.changed = state;
}

void Session::set_session_access_level(SessionAccessLevel session_access_level) {
  std::unique_lock<std::mutex> arran_lochan_am_hill(user_details_mutex_);
  user_details_.session_access_level = session_access_level;
}

int Session::ParseDataAtlas(const std::string& serialised_data_atlas) {
  DataAtlas data_atlas;
  if (serialised_data_atlas.empty()) {
    LOG(kError) << "TMID brought is empty.";
    return kParseDataAtlasTmidEmpty;
  }
  if (!data_atlas.ParseFromString(serialised_data_atlas)) {
    LOG(kError) << "TMID doesn't parse.";
    return kParseDataAtlasTmidDoesNotParse;
  }

  if (data_atlas.drive_data().unique_user_id().empty()) {
    LOG(kError) << "Unique user ID is empty.";
    return kTryAgainLater;
  }
  if (data_atlas.drive_data().root_parent_id().empty()) {
    LOG(kError) << "Root parent id is empty.";
    return kTryAgainLater;
  }

  set_unique_user_id(data_atlas.drive_data().unique_user_id());
  set_root_parent_id(data_atlas.drive_data().root_parent_id());
  set_max_space(data_atlas.drive_data().max_space());
  set_used_space(data_atlas.drive_data().used_space());

  int result(passport_.Parse(data_atlas.passport_data().serialised_keyring()));
  if (result != kSuccess) {
    LOG(kError) << "Failed ParseKeyChain: " << result;
    return kParseDataAtlasKeyringDoesNotParse;
  }

  std::string pub_id;
  for (int id_count(0); id_count < data_atlas.public_ids_size(); ++id_count) {
    pub_id = data_atlas.public_ids(id_count).public_id();
    PublicIdDetails public_id_details;
    public_id_details.social_info->at(kPicture) =
        data_atlas.public_ids(id_count).profile_picture_data_map();
    public_id_details.social_info->at(kInfoPointer) =
        data_atlas.public_ids(id_count).pointer_to_info();

    for (int contact_count(0);
         contact_count < data_atlas.public_ids(id_count).contacts_size();
         ++contact_count) {
      Contact contact(data_atlas.public_ids(id_count).contacts(contact_count));
      asymm::DecodePublicKey(
          data_atlas.public_ids(id_count).contacts(contact_count).mpid_public_key(),
          &contact.mpid_public_key);
      asymm::DecodePublicKey(
          data_atlas.public_ids(id_count).contacts(contact_count).inbox_public_key(),
          &contact.inbox_public_key);
      int add_contact_result(public_id_details.contacts_handler->AddContact(contact));
      LOG(kInfo) << "Result of adding " << contact.public_id << " to " << pub_id << ":  "
                 << add_contact_result;
    }

    for (int share_count(0);
         share_count < data_atlas.public_ids(id_count).shares_size();
         ++share_count) {
      public_id_details.share_information->insert(
          std::make_pair(
              data_atlas.public_ids(id_count).shares(share_count).share_name(),
              ShareDetails(data_atlas.public_ids(id_count).shares(share_count).share_type())));
    }

    public_id_details_[pub_id] = public_id_details;
  }

  return kSuccess;
}

int Session::SerialiseDataAtlas(std::string* serialised_data_atlas) {
  BOOST_ASSERT(serialised_data_atlas);
  DataAtlas data_atlas;
  DriveData* drive_data(data_atlas.mutable_drive_data());
  drive_data->set_unique_user_id(unique_user_id());
  drive_data->set_root_parent_id(root_parent_id());
  drive_data->set_max_space(max_space());
  drive_data->set_used_space(used_space());

  data_atlas.set_timestamp(boost::lexical_cast<std::string>(
      GetDurationSinceEpoch().total_microseconds()));

  std::string serialised_keyring(passport_.Serialise());
  if (serialised_keyring.empty()) {
    LOG(kError) << "Serialising keyring failed.";
    return kSerialiseDataAtlasKeyringFailure;
  }

  PassportData* passport_data(data_atlas.mutable_passport_data());
  passport_data->set_serialised_keyring(serialised_keyring);

  std::vector<Contact> contacts;
  for (auto it(public_id_details_.begin()); it != public_id_details_.end(); ++it) {
    PublicIdentity* pub_id(data_atlas.add_public_ids());
    pub_id->set_public_id((*it).first);
    {
      std::unique_lock<std::mutex> loch(*(*it).second.social_info_mutex);
      pub_id->set_profile_picture_data_map((*it).second.social_info->at(kPicture));
      pub_id->set_pointer_to_info((*it).second.social_info->at(kInfoPointer));
    }
    (*it).second.contacts_handler->OrderedContacts(&contacts, kAlphabetical, kRequestSent |
                                                                             kPendingResponse |
                                                                             kConfirmed |
                                                                             kBlocked);
    for (size_t n(0); n < contacts.size(); ++n) {
      PublicContact* pc(pub_id->add_contacts());
      pc->set_public_id(contacts[n].public_id);
      pc->set_mpid_name(contacts[n].mpid_name);
      pc->set_inbox_name(contacts[n].inbox_name);
      std::string serialised_mpid_public_key, serialised_inbox_public_key;
      asymm::EncodePublicKey(contacts[n].mpid_public_key, &serialised_mpid_public_key);
      pc->set_mpid_public_key(serialised_mpid_public_key);
      asymm::EncodePublicKey(contacts[n].inbox_public_key, &serialised_inbox_public_key);
      pc->set_inbox_public_key(serialised_inbox_public_key);
      pc->set_status(contacts[n].status);
      pc->set_rank(contacts[n].rank);
      pc->set_last_contact(contacts[n].last_contact);
      pc->set_profile_picture_data_map(contacts[n].profile_picture_data_map);
      pc->set_pointer_to_info(contacts[n].pointer_to_info);
      LOG(kInfo) << "Added contact " << contacts[n].public_id << " to " << (*it).first << " map.";
    }

    ShareInformationPtr share_information((*it).second.share_information);
    for (auto& share_it : *share_information) {
      ShareInformationContainer* sic(pub_id->add_shares());
      sic->set_share_name(share_it.first);
      sic->set_share_type(share_it.second.share_type);
    }
  }

  if (!data_atlas.SerializeToString(serialised_data_atlas)) {
    LOG(kError) << "Failed to serialise.";
    return kSerialiseDataAtlasToStringFailure;
  }

  return kSuccess;
}

bool Session::CreateTestPackets(bool with_public_ids) {
  if (passport_.CreateSigningPackets() != kSuccess)
    return false;
  if (passport_.ConfirmSigningPackets() != kSuccess)
    return false;

  if (with_public_ids) {
    for (size_t n(0); n < 5; ++n) {
      std::string public_id(RandomAlphaNumericString(5));
      if (passport_.CreateSelectableIdentity(public_id) != kSuccess)
        return false;
      if (passport_.ConfirmSelectableIdentity(public_id) != kSuccess)
        return false;
    }
  }

  return true;
}


std::vector<std::string> Session::PublicIdentities() const {
  std::vector<std::string> public_identities;
  typedef std::map<std::string, PublicIdDetails> PublicIdDetailsMap;
  std::for_each(public_id_details_.begin(),
                public_id_details_.end(),
                [&public_identities] (const PublicIdDetailsMap::value_type &el) {
                  public_identities.push_back(el.first);
                });
  return public_identities;
}

}  // namespace lifestuff

}  // namespace maidsafe


