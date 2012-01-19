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
#include "boost/multi_index/composite_key.hpp"
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
//                            incorporated to the logic.

class PublicContact;

struct Contact {
  Contact();
  Contact(const std::string &public_username_in,
          const std::string &mpid_name_in,
          const std::string &mmid_name_in,
          const asymm::PublicKey &mpid_public_key_in,
          const asymm::PublicKey &mmid_public_key_in,
          ContactStatus status);
  Contact(const PublicContact &contact);

  std::string public_username, mpid_name, mmid_name;
  asymm::PublicKey mpid_public_key, mmid_public_key;
  ContactStatus status;
  uint32_t rank;
  uint32_t last_contact;
};

/* Tags */
struct Alphabetical {};
struct Popular {};
struct LastContacted {};
struct StatusAlphabetical {};
struct StatusPopular {};
struct StatusLastContacted {};

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
      boost::multi_index::tag<StatusAlphabetical>,
      boost::multi_index::composite_key<
        Contact,
        BOOST_MULTI_INDEX_MEMBER(Contact, ContactStatus, status),
        BOOST_MULTI_INDEX_MEMBER(Contact, std::string, public_username)
      >
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<StatusPopular>,
      boost::multi_index::composite_key<
        Contact,
        BOOST_MULTI_INDEX_MEMBER(Contact, ContactStatus, status),
        BOOST_MULTI_INDEX_MEMBER(Contact, uint32_t, rank)
      >,
      boost::multi_index::composite_key_compare<
        std::less<ContactStatus>,
        std::greater<uint32_t>
      >
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<StatusLastContacted>,
      boost::multi_index::composite_key<
        Contact,
        BOOST_MULTI_INDEX_MEMBER(Contact, ContactStatus, status),
        BOOST_MULTI_INDEX_MEMBER(Contact, uint32_t, last_contact)
      >,
      boost::multi_index::composite_key_compare<
        std::less<ContactStatus>,
        std::greater<uint32_t>
      >
    >
  >
> ContactSet;

class ContactsHandler {
 public:
  ContactsHandler() : contact_set_() { }
  int AddContact(const std::string &public_username,
                 const std::string &mpid_name,
                 const std::string &mmid_name,
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
  int UpdateMpidPublicKey(const std::string &public_username,
                          const asymm::PublicKey &new_mpid_public_key);
  int UpdateMmidPublicKey(const std::string &public_username,
                          const asymm::PublicKey &new_mmid_public_key);
  int UpdateStatus(const std::string &public_username,
                   const ContactStatus &status);
  int TouchContact(const std::string &public_username);
  int ContactInfo(const std::string &public_username, Contact *contact);
  int OrderedContacts(std::vector<Contact> *list,
                      ContactOrder type = kAlphabetical,
                      ContactStatus status = kConfirmed,
                      bool filter_by_status = false);

  void ClearContacts();

 private:
  template <typename T>
  void GetContactsBySingleKey(std::vector<Contact> *list);
  template <typename T>
  void GetContactsByCompositeKey(ContactStatus status,
                                 std::vector<Contact> *list);

  ContactSet contact_set_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_CONTACTS_H_
