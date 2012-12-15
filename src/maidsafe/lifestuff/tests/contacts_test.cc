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

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/utils/fob.h"

#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/contacts.h"

namespace maidsafe {

namespace lifestuff {

namespace test {

class ContactsTest : public testing::Test {
 protected:
  ContactsHandler sch_;
  Fob fob_;
  Fob fob1_;
  Contact contact_;

  ContactsTest()
      : sch_(),
        fob_(priv::utils::GenerateFob(nullptr)),
        fob1_(priv::utils::GenerateFob(nullptr)),
        contact_(NonEmptyString("dan.schmidt"),
                 Identity(RandomString(64)),
                 Identity(RandomString(64)),
                 NonEmptyString("Picky"),
                 Identity(RandomString(64)),
                 asymm::PublicKey(),
                 asymm::PublicKey(),
                 kUninitialised) {}

  ContactsTest(const ContactsTest&);
  ContactsTest& operator=(const ContactsTest&);

  virtual void SetUp() {}

  virtual void TearDown() {}
};

TEST_F(ContactsTest, BEH_Create_ListContacts) {
  std::vector<Contact> mi_list;
  sch_.OrderedContacts(&mi_list);
  ASSERT_EQ(size_t(0), mi_list.size());
  sch_.OrderedContacts(&mi_list, kPopular);
  ASSERT_EQ(size_t(0), mi_list.size());
  sch_.OrderedContacts(&mi_list, kLastContacted);
  ASSERT_EQ(size_t(0), mi_list.size());
}

TEST_F(ContactsTest, BEH_AddContacts) {
  std::vector<Contact> mi_list;
  sch_.OrderedContacts(&mi_list);
  ASSERT_EQ(size_t(0), mi_list.size());

  Contact msc(contact_);
  ASSERT_EQ(0, sch_.AddContact(msc));
  sch_.OrderedContacts(&mi_list);
  ASSERT_EQ(size_t(1), mi_list.size());

  Contact mic;
  ASSERT_EQ(0, sch_.ContactInfo(msc.public_id, &mic));
  ASSERT_EQ(msc.public_id, mic.public_id);

  ASSERT_EQ(kContactInsertionFailure, sch_.AddContact(msc.public_id,
                                                      msc.mpid_name,
                                                      msc.inbox_name,
                                                      msc.profile_picture_data_map,
                                                      msc.pointer_to_info,
                                                      msc.mpid_public_key,
                                                      msc.inbox_public_key,
                                                      msc.status,
                                                      msc.rank,
                                                      msc.last_contact));
  ASSERT_EQ(kContactInsertionFailure, sch_.AddContact(msc));
  sch_.OrderedContacts(&mi_list);
  ASSERT_EQ(size_t(1), mi_list.size());

  msc.public_id = NonEmptyString("palo.feo.smer");
  ASSERT_EQ(0, sch_.AddContact(msc.public_id,
                               msc.mpid_name,
                               msc.inbox_name,
                               msc.profile_picture_data_map,
                               msc.pointer_to_info,
                               msc.mpid_public_key,
                               msc.inbox_public_key,
                               msc.status,
                               msc.rank,
                               msc.last_contact));
  sch_.OrderedContacts(&mi_list);
  ASSERT_EQ(size_t(2), mi_list.size());
}

TEST_F(ContactsTest, BEH_DeleteContacts) {
  std::vector<Contact> mi_list;
  sch_.OrderedContacts(&mi_list);
  ASSERT_EQ(size_t(0), mi_list.size());

  Contact msc(contact_);
  ASSERT_EQ(0, sch_.AddContact(msc));
  sch_.OrderedContacts(&mi_list);
  ASSERT_EQ(size_t(1), mi_list.size());

  Contact mic;
  ASSERT_EQ(0, sch_.ContactInfo(msc.public_id, &mic));
  ASSERT_EQ(msc.public_id, mic.public_id);

  ASSERT_EQ(0, sch_.DeleteContact(msc.public_id));
  ASSERT_EQ(kContactNotPresentFailure, sch_.ContactInfo(msc.public_id, &mic));
  sch_.OrderedContacts(&mi_list);
  ASSERT_EQ(size_t(0), mi_list.size());
  ASSERT_EQ(kContactErasureFailure, sch_.DeleteContact(msc.public_id));
}

TEST_F(ContactsTest, BEH_Update_Select_PubName_Contacts) {
  std::vector<Contact> mi_list;
  sch_.OrderedContacts(&mi_list);
  ASSERT_EQ(size_t(0), mi_list.size());

  Contact msc(contact_);
  ASSERT_EQ(0, sch_.AddContact(msc));
  sch_.OrderedContacts(&mi_list);
  ASSERT_EQ(size_t(1), mi_list.size());

  Contact mic;
  ASSERT_EQ(0, sch_.ContactInfo(msc.public_id, &mic));
  ASSERT_EQ(msc.public_id, mic.public_id);

  Contact msc1(contact_);
  msc1.mpid_name = crypto::Hash<crypto::SHA512>("new mpid name");
  msc1.inbox_name = crypto::Hash<crypto::SHA512>("new mmid name");
  msc1.mpid_public_key = fob_.keys.public_key;
  msc1.inbox_public_key = fob_.keys.public_key;
  msc1.status = kConfirmed;

  // Status
  ASSERT_EQ(0, sch_.UpdateStatus(msc1.public_id, msc1.status));
  ASSERT_EQ(0, sch_.ContactInfo(msc1.public_id, &mic));
  ASSERT_EQ(msc1.status, mic.status);

  // All together
  msc1.mpid_name = crypto::Hash<crypto::SHA512>("latest mpid name");
  msc1.inbox_name = crypto::Hash<crypto::SHA512>("latest mmid name");
  msc1.mpid_public_key = fob1_.keys.public_key;
  msc1.inbox_public_key = fob1_.keys.public_key;
  msc1.status = kPendingResponse;
  ASSERT_EQ(0, sch_.UpdateContact(msc1));
  ASSERT_EQ(0, sch_.ContactInfo(msc1.public_id, &mic));
  ASSERT_TRUE(asymm::MatchingKeys(msc1.mpid_public_key, mic.mpid_public_key));
  ASSERT_TRUE(asymm::MatchingKeys(msc1.inbox_public_key, mic.inbox_public_key));
  ASSERT_EQ(msc1.mpid_name, mic.mpid_name);
  ASSERT_EQ(msc1.inbox_name, mic.inbox_name);
  ASSERT_EQ(msc1.status, mic.status);
}

TEST_F(ContactsTest, BEH_ListContacts_Rank_LastContact) {
  std::vector<Contact> mi_list;
  sch_.OrderedContacts(&mi_list);
  ASSERT_EQ(size_t(0), mi_list.size());

  Contact msc(contact_);
  for (int n = 1; n < 21; n++) {
    msc.rank = RandomUint32() % 10;
    msc.last_contact = RandomUint32() % 10;
    msc.public_id = NonEmptyString("pub_name_" + std::to_string(n));
    ASSERT_EQ(0, sch_.AddContact(msc));
  }

  sch_.OrderedContacts(&mi_list);
  ASSERT_EQ(size_t(20), mi_list.size());

  sch_.OrderedContacts(&mi_list, kPopular);
  ASSERT_EQ(size_t(20), mi_list.size());

  for (unsigned int n = 0; n < mi_list.size()-1; n++) {
    Contact mic = mi_list[n];
    Contact mic1 = mi_list[n+1];
    ASSERT_GE(mic.rank, mic1.rank);
  }

  sch_.OrderedContacts(&mi_list, kLastContacted);
  ASSERT_EQ(size_t(20), mi_list.size());

  for (unsigned int n = 0; n < mi_list.size()-1; n++) {
    Contact mic = mi_list[n];
    Contact mic1 = mi_list[n+1];
    ASSERT_GE(mic.last_contact, mic1.last_contact);
  }
}

TEST_F(ContactsTest, BEH_ListContacts_Status) {
  Contact msc(contact_);
  uint16_t indexing(0);
  uint16_t status_index(0);
  std::vector<ContactStatus> types;
  types.push_back(kUninitialised);
  types.push_back(kRequestSent);
  types.push_back(kPendingResponse);
  types.push_back(kConfirmed);
  types.push_back(kBlocked);

  do {
    for (int n(1); n < 21; ++n) {
      msc.rank = RandomUint32() % 10;
      msc.last_contact = RandomUint32() % 10;
      msc.status = types[status_index];
      msc.public_id = NonEmptyString("pub_name_" + std::to_string(indexing));
      ASSERT_EQ(0, sch_.AddContact(msc));
      ++indexing;
    }
    ++status_index;
  } while (status_index < 5);

  std::vector<Contact> mi_list;
  sch_.OrderedContacts(&mi_list);
  ASSERT_EQ(size_t(100), mi_list.size());

  status_index = 0;
  do {
    sch_.OrderedContacts(&mi_list, kAlphabetical, static_cast<uint16_t>(types[status_index]));
    ASSERT_EQ(size_t(20), mi_list.size());

    sch_.OrderedContacts(&mi_list, kPopular, static_cast<uint16_t>(types[status_index]));
    ASSERT_EQ(size_t(20), mi_list.size());

    for (unsigned int n = 0; n < mi_list.size()-1; n++) {
      Contact mic = mi_list[n];
      Contact mic1 = mi_list[n+1];
      ASSERT_GE(mic.rank, mic1.rank);
    }

    sch_.OrderedContacts(&mi_list, kLastContacted, static_cast<uint16_t>(types[status_index]));
    ASSERT_EQ(size_t(20), mi_list.size());

    for (unsigned int n = 0; n < mi_list.size()-1; n++) {
      Contact mic = mi_list[n];
      Contact mic1 = mi_list[n+1];
      ASSERT_GE(mic.last_contact, mic1.last_contact);
    }
    ++status_index;
  } while (status_index < 5);

  // Enquire multiple status at once
  sch_.OrderedContacts(&mi_list, kPopular, kUninitialised | kPendingResponse);
  ASSERT_EQ(size_t(40), mi_list.size());
  for (unsigned int n = 0; n < mi_list.size()-1; n++) {
    Contact mic = mi_list[n];
    Contact mic1 = mi_list[n+1];
    ASSERT_GE(mic.rank, mic1.rank);
    ASSERT_NE(0, mic.status & (kUninitialised | kPendingResponse));
    ASSERT_NE(0, mic1.status & (kUninitialised | kPendingResponse));
  }
  sch_.OrderedContacts(&mi_list, kLastContacted,
                        kRequestSent | kConfirmed | kBlocked);
  ASSERT_EQ(size_t(60), mi_list.size());
  for (unsigned int n = 0; n < mi_list.size()-1; n++) {
    Contact mic = mi_list[n];
    Contact mic1 = mi_list[n+1];
    ASSERT_GE(mic.last_contact, mic1.last_contact);
    ASSERT_NE(0, mic.status & (kRequestSent | kConfirmed | kBlocked));
    ASSERT_NE(0, mic1.status & (kRequestSent | kConfirmed | kBlocked));
  }
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
