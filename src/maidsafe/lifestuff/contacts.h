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

#ifndef MAIDSAFE_LIFESTUFF_CONTACTS_H_
#define MAIDSAFE_LIFESTUFF_CONTACTS_H_

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
  Contact(const std::string &public_username_in,
          const std::string &mpid_name_in,
          const std::string &mmid_name_in,
          const std::string &profile_picture_data_map,
          const asymm::PublicKey &mpid_public_key_in,
          const asymm::PublicKey &mmid_public_key_in,
          ContactStatus status);
  explicit Contact(const PublicContact &contact);

  std::string public_username, mpid_name, mmid_name, profile_picture_data_map;
  asymm::PublicKey mpid_public_key, mmid_public_key;
  ContactStatus status;
  uint32_t rank;
  uint32_t last_contact;
  ContactPresence presence;
};

/* Tags */
struct Alphabetical {};
struct Popular {};
struct LastContacted {};
struct Status {};

typedef boost::multi_index::multi_index_container<
  Contact,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<Alphabetical>,
      BOOST_MULTI_INDEX_MEMBER(Contact, std::string, public_username)
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
    >
  >
> ContactSet;

class ContactsHandler {
 public:
  ContactsHandler() : contact_set_() { }
  int AddContact(const std::string &public_username,
                 const std::string &mpid_name,
                 const std::string &mmid_name,
                 const std::string &profile_picture_data_map,
                 const asymm::PublicKey &mpid_public_key,
                 const asymm::PublicKey &mmid_public_key,
                 ContactStatus status,
                 const uint32_t &rank,
                 const uint32_t &last_contact);
  int AddContact(const Contact &contact);
  int DeleteContact(const std::string &public_username);
  int UpdateContact(const Contact &contact);
  int UpdateMpidName(const std::string &public_username,
                     const std::string &new_mpid_name);
  int UpdateMmidName(const std::string &public_username,
                     const std::string &new_mmid_name);
  int UpdateProfilePictureDataMap(const std::string &public_username,
                                  const std::string &profile_picture_data_map);
  int UpdateMpidPublicKey(const std::string &public_username,
                          const asymm::PublicKey &new_mpid_public_key);
  int UpdateMmidPublicKey(const std::string &public_username,
                          const asymm::PublicKey &new_mmid_public_key);
  int UpdateStatus(const std::string &public_username,
                   const ContactStatus &status);
  int UpdatePresence(const std::string &public_username,
                     const ContactPresence &presence);
  int TouchContact(const std::string &public_username);
  int ContactInfo(const std::string &public_username, Contact *contact);
  void OrderedContacts(std::vector<Contact> *list,
                       ContactOrder type = kAlphabetical,
                       uint16_t bitwise_status = 0x00);

  void ClearContacts();

 private:
  template <typename T>
  void GetContactsByOrder(ContactSet *contacts, std::vector<Contact> *list);
  void GetContactsByStatus(ContactSet *contacts, ContactStatus status);

  ContactSet contact_set_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_CONTACTS_H_
