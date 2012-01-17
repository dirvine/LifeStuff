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
    : public_username(),
      mpid_name(),
      mmid_name(),
      mpid_public_key(),
      mmid_public_key(),
      status(kUnitialised),
      rank(0),
      last_contact(0) {}

Contact::Contact(const std::string &public_name_in,
        const std::string &mpid_name_in,
        const std::string &mmid_name_in,
        const asymm::PublicKey &mpid_public_key_in,
        const asymm::PublicKey &mmid_public_key_in,
        Status status)
    : public_username(public_name_in),
      mpid_name(mpid_name_in),
      mmid_name(mmid_name_in),
      mpid_public_key(mpid_public_key_in),
      mmid_public_key(mmid_public_key_in),
      status(status),
      rank(0),
      last_contact(0) {}
Contact::Contact(const PublicContact &contact)
    : public_username(contact.public_username()),
      mpid_name(contact.mpid_name()),
      mmid_name(contact.mmid_name()),
      mpid_public_key(),
      mmid_public_key(),
      status(static_cast<Status>(contact.status())),
      rank(contact.rank()),
      last_contact(contact.last_contact()) {
  asymm::PublicKey mpid_key, mmid_key;
  asymm::DecodePublicKey(contact.mpid_public_key(), &mpid_key);
  if (!asymm::ValidateKey(mpid_key))
    DLOG(ERROR) << "Error decoding MPID public key";
  asymm::DecodePublicKey(contact.mmid_public_key(), &mmid_key);
  if (!asymm::ValidateKey(mmid_key))
    DLOG(ERROR) << "Error decoding MMID public key";
}

//  ContactsHandler
int ContactsHandler::AddContact(const std::string &public_username,
                                const std::string &mpid_name,
                                const std::string &mmid_name,
                                const asymm::PublicKey &mpid_public_key,
                                const asymm::PublicKey &mmid_public_key,
                                Contact::Status status,
                                const uint32_t &rank,
                                const uint32_t &last_contact) {
  Contact contact(public_username,
                  mpid_name,
                  mmid_name,
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
    DLOG(ERROR) << "Failed to insert contact " << contact.public_username;
    return -77;
  }

  return kSuccess;
}

int ContactsHandler::AddContact(const Contact &contact) {
  auto result(contact_set_.insert(contact));
  if (!result.second) {
    DLOG(ERROR) << "Failed to insert contact " << contact.public_username;
    return -77;
  }

  return kSuccess;
}

int ContactsHandler::DeleteContact(const std::string &public_username) {
  auto erased(contact_set_.erase(public_username));
  return erased == 1U ? kSuccess : -78;
}

int ContactsHandler::UpdateContact(const Contact &contact) {
  ContactSet::iterator it = contact_set_.find(contact.public_username);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << contact.public_username
                << ") not present in list.";
    return -79;
  }

  Contact local_contact = *it;
  local_contact.public_username = contact.public_username;
  local_contact.mpid_name = contact.mpid_name;
  local_contact.mmid_name = contact.mmid_name;
  local_contact.mpid_public_key = contact.mpid_public_key;
  local_contact.mmid_public_key = contact.mmid_public_key;
  local_contact.status = contact.status;
  local_contact.rank = contact.rank;
  local_contact.last_contact = contact.last_contact;

  if (!contact_set_.replace(it, local_contact)) {
    DLOG(ERROR) << "Failed to replace contact in set "
                << contact.public_username;
    return -79;
  }

  return kSuccess;
}
/*
  int UpdateMpidName(const std::string &public_username,
                     const std::string &new_mpid_name);
  int UpdateMmidName(const std::string &public_username,
                     const std::string &new_mmid_name);
  int UpdateMpidPublicKey(const std::string &public_username,
                          const asymm::PublicKey &new_mpid_public_key);
  int UpdateMmidPublicKey(const std::string &public_username,
                          const asymm::PublicKey &new_mmid_public_key);
  int UpdateStatus(const std::string &public_username,
                   const Contact::Status &status);
  int TouchContact(const std::string &public_username);
  int GetContactInfo(const std::string &public_username, Contact *contact);
  int OrderedContacts(std::vector<Contact> *list, Order type = 0);
*/
int ContactsHandler::UpdateMpidName(const std::string &public_username,
                                    const std::string &new_mpid_name) {
  ContactSet::iterator it = contact_set_.find(public_username);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << public_username << ") not present in list.";
    return -79;
  }

  Contact contact = *it;
  contact.mpid_name = new_mpid_name;

  if (!contact_set_.replace(it, contact)) {
    DLOG(ERROR) << "Failed to replace contact in set "
                << contact.public_username;
    return -79;
  }

  return kSuccess;
}

int ContactsHandler::UpdateMmidName(const std::string &public_username,
                                    const std::string &new_mmid_name) {
  ContactSet::iterator it = contact_set_.find(public_username);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << public_username << ") not present in list.";
    return -79;
  }

  Contact contact = *it;
  contact.mmid_name = new_mmid_name;

  if (!contact_set_.replace(it, contact)) {
    DLOG(ERROR) << "Failed to replace contact in set "
                << contact.public_username;
    return -79;
  }

  return kSuccess;
}

int ContactsHandler::UpdateMpidPublicKey(
    const std::string &public_username,
    const asymm::PublicKey &new_mpid_public_key) {
  ContactSet::iterator it = contact_set_.find(public_username);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << public_username << ") not present in list.";
    return -79;
  }

  Contact contact = *it;
  contact.mpid_public_key = new_mpid_public_key;

  if (!contact_set_.replace(it, contact)) {
    DLOG(ERROR) << "Failed to replace contact in set "
                << contact.public_username;
    return -79;
  }

  return kSuccess;
}

int ContactsHandler::UpdateMmidPublicKey(
    const std::string &public_username,
    const asymm::PublicKey &new_mmid_public_key) {
  ContactSet::iterator it = contact_set_.find(public_username);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << public_username << ") not present in list.";
    return -79;
  }

  Contact contact = *it;
  contact.mmid_public_key = new_mmid_public_key;

  if (!contact_set_.replace(it, contact)) {
    DLOG(ERROR) << "Failed to replace contact in set "
                << contact.public_username;
    return -79;
  }

  return kSuccess;
}

int ContactsHandler::UpdateStatus(const std::string &public_username,
                                  const Contact::Status &status) {
  ContactSet::iterator it = contact_set_.find(public_username);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << public_username << ") not present in list.";
    return -79;
  }

  Contact contact = *it;
  contact.status = status;

  if (!contact_set_.replace(it, contact)) {
    DLOG(ERROR) << "Failed to replace contact in set "
                << contact.public_username;
    return -79;
  }

  return kSuccess;
}

int ContactsHandler::TouchContact(const std::string &public_username) {
  ContactSet::iterator it = contact_set_.find(public_username);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << public_username
                << ") not present in contact list.";
    return -79;
  }

  Contact contact = *it;
  ++contact.rank;
  contact.last_contact =
      static_cast<uint32_t>(GetDurationSinceEpoch().total_milliseconds());

  if (!contact_set_.replace(it, contact)) {
    DLOG(ERROR) << "Failed to replace contact in set "
                << contact.public_username;
    return -79;
  }

  return kSuccess;
}

int ContactsHandler::ContactInfo(const std::string &public_username,
                                 Contact *contact) {
  ContactSet::iterator it = contact_set_.find(public_username);
  if (it == contact_set_.end()) {
    DLOG(ERROR) << "Contact(" << public_username
                << ") not present in contact list.";
    return -80;
  }

  *contact = *it;

  return kSuccess;
}

int ContactsHandler::OrderedContacts(std::vector<Contact> *list, Order type) {
  list->clear();
  switch (type) {
    case kAlphabetical:
        for (auto it(contact_set_.get<alphabetical>().begin());
             it != contact_set_.get<alphabetical>().end();
             ++it) {
          Contact contact = *it;
          list->push_back(contact);
        }
        break;
    case kPopular:
        for (auto it(contact_set_.get<popular>().begin());
             it != contact_set_.get<popular>().end();
             ++it) {
          Contact contact = *it;
          list->push_back(contact);
        }
        break;
    case kLastContacted:
        for (auto it(contact_set_.get<last_contacted>().begin());
             it != contact_set_.get<last_contacted>().end();
             ++it) {
          Contact contact = *it;
          list->push_back(contact);
        }
        break;
  }
  return 0;
}

void ContactsHandler::ClearContacts() { contact_set_.clear(); }

}  // namespace lifestuff

}  // namespace maidsafe
