/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Handles user's list of maidsafe contacts
* Version:      1.0
* Created:      2009-01-28-23.19.56
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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_CONTACTS_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_CONTACTS_H_

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif

#include "boost/multi_index_container.hpp"
#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index/identity.hpp"
#include "boost/multi_index/member.hpp"

#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "maidsafe/common/rsa.h"

#include "maidsafe/lifestuff/lifestuff.h"

namespace maidsafe {

namespace lifestuff {

// TODO(Team#5#): 2009-07-22 - Language and country lists to be decided on and
//                             incorporated to the logic.

class PublicContact;

struct Contact {
  Contact();
  Contact(const NonEmptyString& public_id_in,
          const Identity& mpid_name_in,
          const Identity& inbox_name_in,
          const NonEmptyString& profile_picture_data_map,
          const Identity& pointer_to_info,
          const asymm::PublicKey& mpid_public_key_in,
          const asymm::PublicKey& inbox_public_key_in,
          ContactStatus status);
  explicit Contact(const PublicContact& contact);
  bool Equals(const Contact& other);

  NonEmptyString public_id, profile_picture_data_map;
  Identity mpid_name, inbox_name, pointer_to_info;
  asymm::PublicKey mpid_public_key, inbox_public_key;
  ContactStatus status;
  uint32_t rank;
  uint32_t last_contact;
  ContactPresence presence;
};

/* Tags */
struct Alphabetical {};
struct LastContacted {};
struct Popular {};
struct Presence {};
struct Status {};

typedef boost::multi_index::multi_index_container<
  Contact,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<Alphabetical>,
      BOOST_MULTI_INDEX_MEMBER(Contact, NonEmptyString, public_id)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<Popular>,
      BOOST_MULTI_INDEX_MEMBER(Contact, uint32_t, rank),
      std::greater<uint32_t>
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<LastContacted>,
      BOOST_MULTI_INDEX_MEMBER(Contact, uint32_t, last_contact),
      std::greater<uint32_t>
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<Status>,
      BOOST_MULTI_INDEX_MEMBER(Contact, ContactStatus, status)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<Presence>,
      BOOST_MULTI_INDEX_MEMBER(Contact, ContactPresence, presence)
    >
  >
> ContactSet;

class ContactsHandler {
 public:
  ContactsHandler() : contact_set_() { }
  int AddContact(const NonEmptyString& public_id,
                 const Identity& mpid_name,
                 const Identity& inbox_name,
                 const NonEmptyString& profile_picture_data_map,
                 const Identity& pointer_to_info,
                 const asymm::PublicKey& mpid_public_key,
                 const asymm::PublicKey& inbox_public_key,
                 ContactStatus status,
                 const uint32_t& rank,
                 const uint32_t& last_contact);
  int AddContact(const Contact& contact);
  int DeleteContact(const NonEmptyString& public_id);
  int UpdateContact(const Contact& contact);
  int UpdateProfilePictureDataMap(const NonEmptyString& public_id,
                                  const NonEmptyString& profile_picture_data_map);
  int UpdatePointerToInfo(const NonEmptyString& public_id, const Identity& pointer_to_info);
  int UpdateStatus(const NonEmptyString& public_id, const ContactStatus& status);
  int UpdatePresence(const NonEmptyString& public_id, const ContactPresence& presence);
  int TouchContact(const NonEmptyString& public_id);
  int ContactInfo(const NonEmptyString& public_id, Contact* contact);
  void OrderedContacts(std::vector<Contact>* contacts,
                       ContactOrder type = kAlphabetical,
                       uint16_t bitwise_status = 0x00);
  void OnlineContacts(std::vector<Contact>* online_contacts);
  void ClearContacts();
  ContactMap GetContacts(uint16_t bitwise_status);

 private:
  template <typename T>
  void GetContactsByOrder(ContactSet* contacts, std::vector<Contact>* list);
  void GetContactsByStatus(ContactSet* contacts, ContactStatus status);

  ContactSet contact_set_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_CONTACTS_H_
