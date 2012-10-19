/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Nov 13, 2008
 *      Author: Team
 */

#ifdef __MSVC__
#  pragma warning(disable: 4503)
#endif

#include "maidsafe/lifestuff/detail/contacts.h"

#include "boost/filesystem.hpp"
#include "boost/lexical_cast.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

//  Contacts
Contact::Contact()
    : public_id(),
      profile_picture_data_map(),
      mpid_name(),
      inbox_name(),
      pointer_to_info(),
      mpid_public_key(),
      inbox_public_key(),
      status(kUninitialised),
      rank(0),
      last_contact(0),
      presence(kOffline) {}

Contact::Contact(const NonEmptyString& public_name_in,
                 const Identity& mpid_name_in,
                 const Identity& inbox_name_in,
                 const NonEmptyString& profile_picture_data_map_in,
                 const Identity& pointer_to_info_in,
                 const asymm::PublicKey& mpid_public_key_in,
                 const asymm::PublicKey& inbox_public_key_in,
                 ContactStatus status)
    : public_id(public_name_in),
      profile_picture_data_map(profile_picture_data_map_in),
      mpid_name(mpid_name_in),
      inbox_name(inbox_name_in),
      pointer_to_info(pointer_to_info_in),
      mpid_public_key(mpid_public_key_in),
      inbox_public_key(inbox_public_key_in),
      status(status),
      rank(0),
      last_contact(0),
      presence(kOffline) {}

Contact::Contact(const PublicContact& contact)
    : public_id(contact.public_id()),
      profile_picture_data_map(contact.profile_picture_data_map()),
      mpid_name(contact.mpid_name()),
      inbox_name(contact.inbox_name()),
      pointer_to_info(contact.pointer_to_info()),
      mpid_public_key(),
      inbox_public_key(),
      status(static_cast<ContactStatus>(contact.status())),
      rank(contact.rank()),
      last_contact(contact.last_contact()),
      presence(kOffline) {}

bool Contact::Equals(const Contact& other) {
  if (public_id != other.public_id ||
      mpid_name != other.mpid_name ||
      inbox_name != other.inbox_name ||
      profile_picture_data_map != other.profile_picture_data_map ||
      pointer_to_info != other.pointer_to_info ||
      status != other.status ||
      rank != other.rank ||
      last_contact != other.last_contact ||
      presence != other.presence) {
    return false;
  }

  bool valid_public(asymm::ValidateKey(mpid_public_key)),
       other_valid_public(asymm::ValidateKey(other.mpid_public_key));
  if ((valid_public && !other_valid_public) || (!valid_public && other_valid_public)) {
    return false;
  }
  if (valid_public && other_valid_public) {
    if (!asymm::MatchingKeys(mpid_public_key, other.mpid_public_key))
      return false;
  }

  valid_public = asymm::ValidateKey(inbox_public_key);
  other_valid_public = asymm::ValidateKey(other.inbox_public_key);
  if ((valid_public && !other_valid_public) || (!valid_public && other_valid_public)) {
    return false;
  }
  if (valid_public && other_valid_public) {
    if (!asymm::MatchingKeys(inbox_public_key, other.inbox_public_key))
      return false;
  }

  return true;
}

//  ContactsHandler
int ContactsHandler::AddContact(const NonEmptyString& public_id,
                                const Identity& mpid_name,
                                const Identity& inbox_name,
                                const NonEmptyString& profile_picture_data_map,
                                const Identity& pointer_to_info,
                                const asymm::PublicKey& mpid_public_key,
                                const asymm::PublicKey& inbox_public_key,
                                ContactStatus status,
                                const uint32_t& rank,
                                const uint32_t& last_contact) {
  Contact contact(public_id,
                  mpid_name,
                  inbox_name,
                  profile_picture_data_map,
                  pointer_to_info,
                  mpid_public_key,
                  inbox_public_key,
                  status);
  if (last_contact == 0)
    contact.last_contact = static_cast<uint32_t>(GetDurationSinceEpoch().total_milliseconds());
  else
    contact.last_contact = last_contact;
  contact.rank = rank;

  auto result(contact_set_.insert(contact));
  if (!result.second) {
    LOG(kError) << "Failed to insert contact " << contact.public_id.string();
    return kContactInsertionFailure;
  }

  return kSuccess;
}

int ContactsHandler::AddContact(const Contact& contact) {
  auto result(contact_set_.insert(contact));
  if (!result.second) {
    LOG(kError) << "Failed to insert contact " << contact.public_id.string();
    return kContactInsertionFailure;
  }

  return kSuccess;
}

int ContactsHandler::DeleteContact(const NonEmptyString& public_id) {
  auto erased(contact_set_.erase(public_id));
  return erased == 1U ? kSuccess : kContactErasureFailure;
}

int ContactsHandler::UpdateContact(const Contact& contact) {
  ContactSet::iterator it = contact_set_.find(contact.public_id);
  if (it == contact_set_.end()) {
    LOG(kError) << "Contact(" << contact.public_id.string() << ") not present in list.";
    return kContactNotPresentFailure;
  }

  Contact local_contact = *it;
  local_contact.public_id = contact.public_id;
  local_contact.mpid_name = contact.mpid_name;
  local_contact.inbox_name = contact.inbox_name;
  local_contact.mpid_public_key = contact.mpid_public_key;
  local_contact.inbox_public_key = contact.inbox_public_key;
  local_contact.status = contact.status;
  local_contact.rank = contact.rank;
  local_contact.last_contact = contact.last_contact;
  local_contact.profile_picture_data_map = contact.profile_picture_data_map;
  local_contact.pointer_to_info = contact.pointer_to_info;

  if (!contact_set_.replace(it, local_contact)) {
    LOG(kError) << "Failed to replace contact in set " << contact.public_id.string();
    return kContactReplacementFailure;
  }

  it = contact_set_.find(contact.public_id);
  return kSuccess;
}

int ContactsHandler::UpdateProfilePictureDataMap(const NonEmptyString& public_id,
                                                 const NonEmptyString& profile_picture_data_map) {
  ContactSet::iterator it = contact_set_.find(public_id);
  if (it == contact_set_.end()) {
    LOG(kError) << "Contact(" << public_id.string() << ") not present in list.";
    return kContactNotPresentFailure;
  }

  Contact contact = *it;
  contact.profile_picture_data_map = profile_picture_data_map;
  if (!contact_set_.replace(it, contact)) {
    LOG(kError) << "Failed to replace contact in set " << contact.public_id.string();
    return kContactReplacementFailure;
  }

  return kSuccess;
}

int ContactsHandler::UpdatePointerToInfo(const NonEmptyString& public_id,
                                         const Identity& pointer_to_info) {
  ContactSet::iterator it = contact_set_.find(public_id);
  if (it == contact_set_.end()) {
    LOG(kError) << "Contact(" << public_id.string() << ") not present in list.";
    return kContactNotPresentFailure;
  }

  Contact contact = *it;
  contact.pointer_to_info = pointer_to_info;
  if (!contact_set_.replace(it, contact)) {
    LOG(kError) << "Failed to replace contact in set " << contact.public_id.string();
    return kContactReplacementFailure;
  }

  return kSuccess;
}

int ContactsHandler::UpdateStatus(const NonEmptyString& public_id, const ContactStatus& status) {
  ContactSet::iterator it = contact_set_.find(public_id);
  if (it == contact_set_.end()) {
    LOG(kError) << "Contact(" << public_id.string() << ") not present in list.";
    return kContactNotPresentFailure;
  }

  Contact contact = *it;
  contact.status = status;

  if (!contact_set_.replace(it, contact)) {
    LOG(kError) << "Failed to replace contact in set " << contact.public_id.string();
    return kContactReplacementFailure;
  }

  return kSuccess;
}

int ContactsHandler::UpdatePresence(const NonEmptyString& public_id, const ContactPresence& presence) {
  ContactSet::iterator it = contact_set_.find(public_id);
  if (it == contact_set_.end()) {
    LOG(kError) << "Contact(" << public_id.string() << ") not present in list.";
    return kContactNotPresentFailure;
  }

  Contact contact = *it;
  contact.presence = presence;

  if (!contact_set_.replace(it, contact)) {
    LOG(kError) << "Failed to replace contact in set " << contact.public_id.string();
    return kContactReplacementFailure;
  }

  return kSuccess;
}

int ContactsHandler::TouchContact(const NonEmptyString& public_id) {
  ContactSet::iterator it = contact_set_.find(public_id);
  if (it == contact_set_.end()) {
    LOG(kError) << "Contact(" << public_id.string() << ") not present in contact list.";
    return kContactNotPresentFailure;
  }

  Contact contact = *it;
  ++contact.rank;
  contact.last_contact = static_cast<uint32_t>(GetDurationSinceEpoch().total_milliseconds());

  if (!contact_set_.replace(it, contact)) {
    LOG(kError) << "Failed to replace contact in set " << contact.public_id.string();
    return kContactReplacementFailure;
  }

  return kSuccess;
}

int ContactsHandler::ContactInfo(const NonEmptyString& public_id, Contact* contact) {
  ContactSet::iterator it = contact_set_.find(public_id);
  if (it == contact_set_.end()) {
    LOG(kError) << "Contact(" << public_id.string() << ") not present in contact list.";
    return kContactNotPresentFailure;
  }
  *contact = *it;

  return kSuccess;
}

void ContactsHandler::OrderedContacts(std::vector<Contact>* contacts,
                                      ContactOrder type,
                                      uint16_t bitwise_status) {
  BOOST_ASSERT(contacts);
  contacts->clear();
  ContactSet* enquiry_pool = &contact_set_;
  ContactSet contacts_set;
  if (bitwise_status != 0x00) {
    if (kUninitialised & bitwise_status)
      GetContactsByStatus(&contacts_set, kUninitialised);
    if (kRequestSent & bitwise_status)
      GetContactsByStatus(&contacts_set, kRequestSent);
    if (kPendingResponse & bitwise_status)
      GetContactsByStatus(&contacts_set, kPendingResponse);
    if (kConfirmed & bitwise_status)
      GetContactsByStatus(&contacts_set, kConfirmed);
    if (kBlocked & bitwise_status)
      GetContactsByStatus(&contacts_set, kBlocked);
    enquiry_pool = &contacts_set;
  }
  switch (type) {
    case kAlphabetical:
        GetContactsByOrder<Alphabetical>(enquiry_pool, contacts);
        break;
    case kPopular:
        GetContactsByOrder<Popular>(enquiry_pool, contacts);
        break;
    case kLastContacted:
        GetContactsByOrder<LastContacted>(enquiry_pool, contacts);
        break;
  }
}

void ContactsHandler::OnlineContacts(std::vector<Contact>* online_contacts) {
  online_contacts->clear();
  auto it_pair(contact_set_.get<Presence>().equal_range(kOnline));
  online_contacts->assign(it_pair.first, it_pair.second);
}

ContactMap ContactsHandler::GetContacts(uint16_t bitwise_status) {
  ContactMap contact_map;

  ContactSet contacts;
  if (kUninitialised & bitwise_status)
    GetContactsByStatus(&contacts, kUninitialised);
  if (kRequestSent & bitwise_status)
    GetContactsByStatus(&contacts, kRequestSent);
  if (kPendingResponse & bitwise_status)
    GetContactsByStatus(&contacts, kPendingResponse);
  if (kConfirmed & bitwise_status)
    GetContactsByStatus(&contacts, kConfirmed);
  if (kBlocked & bitwise_status)
    GetContactsByStatus(&contacts, kBlocked);
  ContactSet* enquiry_pool = &contacts;

  for (auto it(enquiry_pool->begin()); it != enquiry_pool->end(); ++it) {
    contact_map.insert(std::make_pair((*it).public_id,
                                      std::make_pair((*it).status, (*it).presence)));
  }

  return contact_map;
}

template <typename T>
void ContactsHandler::GetContactsByOrder(ContactSet* contacts, std::vector<Contact>* list) {
  for (auto it(contacts->get<T>().begin()); it != contacts->get<T>().end(); ++it)
    list->push_back(*it);
}

void ContactsHandler::GetContactsByStatus(ContactSet* contacts, ContactStatus status) {
  auto pit = contact_set_.get<Status>().equal_range(status);
  auto it_begin = pit.first;
  auto it_end = pit.second;
  while (it_begin != it_end) {
    contacts->insert(*it_begin);
    ++it_begin;
  }
}

void ContactsHandler::ClearContacts() { contact_set_.clear(); }

}  // namespace lifestuff

}  // namespace maidsafe
