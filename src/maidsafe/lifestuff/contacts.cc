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

#include "maidsafe/lifestuff/contacts.h"

#include "boost/filesystem.hpp"
#include "boost/lexical_cast.hpp"

#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/data_atlas_pb.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/return_codes.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

//  Contacts
Contact::Contact()
    : public_id(),
      mpid_name(),
      inbox_name(),
      profile_picture_data_map(),
      mpid_public_key(),
      mmid_public_key(),
      status(kUnitialised),
      rank(0),
      last_contact(0),
      presence(kOffline) {}

Contact::Contact(const std::string &public_name_in,
                 const std::string &mpid_name_in,
                 const std::string &inbox_name_in,
                 const std::string &profile_picture_data_map_in,
                 const asymm::PublicKey &mpid_public_key_in,
                 const asymm::PublicKey &mmid_public_key_in,
                 ContactStatus status)
    : public_id(public_name_in),
      mpid_name(mpid_name_in),
      inbox_name(inbox_name_in),
      profile_picture_data_map(profile_picture_data_map_in),
      mpid_public_key(mpid_public_key_in),
      mmid_public_key(mmid_public_key_in),
      status(status),
      rank(0),
      last_contact(0),
      presence(kOffline) {}
Contact::Contact(const PublicContact &contact)
    : public_id(contact.public_id()),
      mpid_name(),
      inbox_name(contact.inbox_name()),
      profile_picture_data_map(contact.profile_picture_data_map()),
      mpid_public_key(),
      mmid_public_key(),
      status(static_cast<ContactStatus>(contact.status())),
      rank(contact.rank()),
      last_contact(contact.last_contact()),
      presence(kOffline) {}

//  ContactsHandler
int ContactsHandler::AddContact(const std::string &public_id,
                                const std::string &mpid_name,
                                const std::string &inbox_name,
                                const std::string &profile_picture_data_map,
                                const asymm::PublicKey &mpid_public_key,
                                const asymm::PublicKey &mmid_public_key,
                                ContactStatus status,
                                const uint32_t &rank,
                                const uint32_t &last_contact) {
  Contact contact(public_id,
                  mpid_name,
                  inbox_name,
                  profile_picture_data_map,
                  mpid_public_key,
                  mmid_public_key,
                  status);
  if (last_contact == 0)
    contact.last_contact =
        static_cast<uint32_t>(GetDurationSinceEpoch().total_milliseconds());
  else
    contact.last_contact = last_contact;
  contact.rank = rank;

  auto result(contact_set_.insert(contact));
  if (!result.second) {
    DLOG(ERROR) << "Failed to insert contact " << contact.public_id;
    return -77;
  }

  return kSuccess;
}

int ContactsHandler::AddContact(const Contact &contact) {
  auto result(contact_set_.insert(contact));
  if (!result.second) {
    DLOG(ERROR) << "Failed to insert contact " << contact.public_id;
    return -77;
  }

  return kSuccess;
}

int ContactsHandler::DeleteContact(const std::string &public_id) {
  auto erased(contact_set_.erase(public_id));
  return erased == 1U ? kSuccess : -78;
}

int ContactsHandler::UpdateContact(const Contact &contact) {
  ContactSet::iterator it = contact_set_.find(contact.public_id);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << contact.public_id
                << ") not present in list.";
    return -79;
  }

  Contact local_contact = *it;
  local_contact.public_id = contact.public_id;
  local_contact.mpid_name = contact.mpid_name;
  local_contact.inbox_name = contact.inbox_name;
  local_contact.mpid_public_key = contact.mpid_public_key;
  local_contact.mmid_public_key = contact.mmid_public_key;
  local_contact.status = contact.status;
  local_contact.rank = contact.rank;
  local_contact.last_contact = contact.last_contact;
  local_contact.profile_picture_data_map = contact.profile_picture_data_map;

  if (!contact_set_.replace(it, local_contact)) {
    DLOG(ERROR) << "Failed to replace contact in set "
                << contact.public_id;
    return -79;
  }

  it = contact_set_.find(contact.public_id);
  return kSuccess;
}

int ContactsHandler::UpdateMpidName(const std::string &public_id,
                                    const std::string &new_mpid_name) {
  ContactSet::iterator it = contact_set_.find(public_id);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << public_id << ") not present in list.";
    return -79;
  }

  Contact contact = *it;
  contact.mpid_name = new_mpid_name;

  if (!contact_set_.replace(it, contact)) {
    DLOG(ERROR) << "Failed to replace contact in set "
                << contact.public_id;
    return -79;
  }

  return kSuccess;
}

int ContactsHandler::UpdateMmidName(const std::string &public_id,
                                    const std::string &new_inbox_name) {
  ContactSet::iterator it = contact_set_.find(public_id);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << public_id << ") not present in list.";
    return -79;
  }

  Contact contact = *it;
  contact.inbox_name = new_inbox_name;

  if (!contact_set_.replace(it, contact)) {
    DLOG(ERROR) << "Failed to replace contact in set "
                << contact.public_id;
    return -79;
  }

  return kSuccess;
}

int ContactsHandler::UpdateProfilePictureDataMap(
    const std::string &public_id,
    const std::string &profile_picture_data_map) {
  ContactSet::iterator it = contact_set_.find(public_id);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << public_id << ") not present in list.";
    return -79;
  }

  Contact contact = *it;
  contact.profile_picture_data_map = profile_picture_data_map;
  if (!contact_set_.replace(it, contact)) {
    DLOG(ERROR) << "Failed to replace contact in set "
                << contact.public_id;
    return -79;
  }

  return kSuccess;
}

int ContactsHandler::UpdateMpidPublicKey(
    const std::string &public_id,
    const asymm::PublicKey &new_mpid_public_key) {
  ContactSet::iterator it = contact_set_.find(public_id);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << public_id << ") not present in list.";
    return -79;
  }

  Contact contact = *it;
  contact.mpid_public_key = new_mpid_public_key;

  if (!contact_set_.replace(it, contact)) {
    DLOG(ERROR) << "Failed to replace contact in set "
                << contact.public_id;
    return -79;
  }

  return kSuccess;
}

int ContactsHandler::UpdateMmidPublicKey(
    const std::string &public_id,
    const asymm::PublicKey &new_mmid_public_key) {
  ContactSet::iterator it = contact_set_.find(public_id);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << public_id << ") not present in list.";
    return -79;
  }

  Contact contact = *it;
  contact.mmid_public_key = new_mmid_public_key;

  if (!contact_set_.replace(it, contact)) {
    DLOG(ERROR) << "Failed to replace contact in set "
                << contact.public_id;
    return -79;
  }

  return kSuccess;
}

int ContactsHandler::UpdateStatus(const std::string &public_id,
                                  const ContactStatus &status) {
  ContactSet::iterator it = contact_set_.find(public_id);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << public_id << ") not present in list.";
    return -79;
  }

  Contact contact = *it;
  contact.status = status;

  if (!contact_set_.replace(it, contact)) {
    DLOG(ERROR) << "Failed to replace contact in set "
                << contact.public_id;
    return -79;
  }

  return kSuccess;
}

int ContactsHandler::UpdatePresence(const std::string &public_id,
                                    const ContactPresence &presence) {
  ContactSet::iterator it = contact_set_.find(public_id);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << public_id << ") not present in list.";
    return -79;
  }

  Contact contact = *it;
  contact.presence = presence;

  if (!contact_set_.replace(it, contact)) {
    DLOG(ERROR) << "Failed to replace contact in set "
                << contact.public_id;
    return -79;
  }

  return kSuccess;
}

int ContactsHandler::TouchContact(const std::string &public_id) {
  ContactSet::iterator it = contact_set_.find(public_id);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << public_id
                << ") not present in contact list.";
    return -79;
  }

  Contact contact = *it;
  ++contact.rank;
  contact.last_contact =
      static_cast<uint32_t>(GetDurationSinceEpoch().total_milliseconds());

  if (!contact_set_.replace(it, contact)) {
    DLOG(ERROR) << "Failed to replace contact in set "
                << contact.public_id;
    return -79;
  }

  return kSuccess;
}

int ContactsHandler::ContactInfo(const std::string &public_id,
                                 Contact *contact) {
  ContactSet::iterator it = contact_set_.find(public_id);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << public_id
                << ") not present in contact list.";
    return -80;
  }
  *contact = *it;

  return kSuccess;
}

void ContactsHandler::OrderedContacts(std::vector<Contact> *list,
                                      ContactOrder type,
                                      uint16_t bitwise_status) {
  list->clear();
  ContactSet *enquiry_pool = &contact_set_;
  ContactSet contacts;
  if (bitwise_status != 0x00) {
    if (kUnitialised & bitwise_status)
      GetContactsByStatus(&contacts, kUnitialised);
    if (kRequestSent & bitwise_status)
      GetContactsByStatus(&contacts, kRequestSent);
    if (kPendingResponse & bitwise_status)
      GetContactsByStatus(&contacts, kPendingResponse);
    if (kConfirmed & bitwise_status)
      GetContactsByStatus(&contacts, kConfirmed);
    if (kBlocked & bitwise_status)
      GetContactsByStatus(&contacts, kBlocked);
    enquiry_pool = &contacts;
  }
  switch (type) {
    case kAlphabetical:
        GetContactsByOrder<Alphabetical>(enquiry_pool, list);
        break;
    case kPopular:
        GetContactsByOrder<Popular>(enquiry_pool, list);
        break;
    case kLastContacted:
        GetContactsByOrder<LastContacted>(enquiry_pool, list);
        break;
  }
}

void ContactsHandler::OnlineContacts(std::vector<Contact> *online_contacts) {
  online_contacts->clear();
  auto it_pair(contact_set_.get<Presence>().equal_range(kOnline));
  online_contacts->assign(it_pair.first, it_pair.second);
}

ContactMap ContactsHandler::GetContacts(uint16_t bitwise_status) {
  ContactMap contact_map;

  ContactSet *enquiry_pool = &contact_set_;
  ContactSet contacts;
  if (kUnitialised & bitwise_status)
    GetContactsByStatus(&contacts, kUnitialised);
  if (kRequestSent & bitwise_status)
    GetContactsByStatus(&contacts, kRequestSent);
  if (kPendingResponse & bitwise_status)
    GetContactsByStatus(&contacts, kPendingResponse);
  if (kConfirmed & bitwise_status)
    GetContactsByStatus(&contacts, kConfirmed);
  if (kBlocked & bitwise_status)
    GetContactsByStatus(&contacts, kBlocked);
  enquiry_pool = &contacts;

  for (auto it(enquiry_pool->begin()); it != enquiry_pool->end(); ++it) {
    contact_map.insert(std::make_pair((*it).public_id,
                                      std::make_pair((*it).status,
                                                     (*it).presence)));
  }

  return contact_map;
}

template <typename T>
void ContactsHandler::GetContactsByOrder(ContactSet *contacts,
                                         std::vector<Contact> *list) {
  for (auto it(contacts->get<T>().begin());
       it != contacts->get<T>().end();
       ++it) {
    list->push_back(*it);
  }
}

void ContactsHandler::GetContactsByStatus(ContactSet *contacts,
                                          ContactStatus status) {
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
