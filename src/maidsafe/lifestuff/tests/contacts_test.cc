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

#include "boost/filesystem.hpp"
#include "boost/thread.hpp"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/lifestuff/contacts.h"

namespace maidsafe {

namespace lifestuff {

namespace test {

 class ContactsTest : public testing::Test {
  protected:
   ContactsHandler *sch_;
   std::string name_;
   int test;
   asymm::Keys keys_;
   asymm::Keys keys1_;
   Contact contact_;

   ContactsTest() : sch_(NULL), name_(""), test(0), keys_(), keys1_(),
                    contact_("dan.schmidt", "abcdefghijk", "Dan Schmidt Valle",
                             asymm::PublicKey(), asymm::PublicKey(),
                             Contact::kUnitialised) {
     GenerateKeyPair(&keys_);
     GenerateKeyPair(&keys1_);
   }
   ContactsTest(const ContactsTest&);
   ContactsTest& operator=(const ContactsTest&);

   virtual void SetUp() {
     name_ = "Contacts.db";
     sch_ = new ContactsHandler();
     sch_->ClearContacts();
   }

   virtual void TearDown() {
     delete sch_;
   }
 };

 TEST_F(ContactsTest, BEH_Create_ListContacts) {
   std::vector<Contact> mi_list;
   ASSERT_EQ(0, sch_->OrderedContacts(&mi_list)) <<
             "MI - Problem getting contact list";
   ASSERT_EQ((unsigned)0, mi_list.size()) <<
             "List came back not empty after DB creation.";
   ASSERT_EQ(0, sch_->OrderedContacts(&mi_list, ContactsHandler::kPopular)) <<
             "MI - Problem getting contact list";
   ASSERT_EQ((unsigned)0, mi_list.size()) <<
             "List came back not empty after DB creation.";
   ASSERT_EQ(0, sch_->OrderedContacts(&mi_list,
                                      ContactsHandler::kLastContacted)) <<
             "MI - Problem getting contact list";
   ASSERT_EQ((unsigned)0, mi_list.size()) <<
             "List came back not empty after DB creation.";
   test++;
 }

 TEST_F(ContactsTest, BEH_AddContacts) {
   std::vector<Contact> mi_list;
   ASSERT_EQ(0, sch_->OrderedContacts(&mi_list)) <<
             "MI - Problem getting contact list";
   ASSERT_EQ((unsigned)0, mi_list.size()) <<
             "List came back not empty after DB creation.";

   Contact msc(contact_);
   ASSERT_EQ(0, sch_->AddContact(msc)) << "MI - Problem adding a contact";
   ASSERT_EQ(0, sch_->OrderedContacts(&mi_list)) <<
             "MI - Problem getting contact list";
   ASSERT_EQ((unsigned)1, mi_list.size()) <<
             "List came back empty after addition.";

   Contact mic;
   ASSERT_EQ(0, sch_->ContactInfo(msc.public_username, &mic)) <<
             "MI - Problem getting the contact";
   ASSERT_EQ(msc.public_username, mic.public_username) <<
             "MI - Public name not the same";

   ASSERT_EQ(-77, sch_->AddContact(msc.public_username, msc.mpid_name,
                                   msc.mmid_name, msc.mpid_public_key,
                                   msc.mmid_public_key, msc.status,
                                   msc.rank, msc.last_contact)) <<
             "MI - Duplicated Contact shall not be allowed to add";
   ASSERT_EQ(-77, sch_->AddContact(msc)) <<
             "MI - Duplicated Contact shall not be allowed to add";
   ASSERT_EQ(0, sch_->OrderedContacts(&mi_list)) <<
             "MI - Problem getting contact list";
   ASSERT_EQ((unsigned)1, mi_list.size()) <<
             "MI - List came back with wrong number of elements after addition.";

   msc.public_username = "palo.feo.smer";
   ASSERT_EQ(0, sch_->AddContact(msc.public_username, msc.mpid_name,
                                 msc.mmid_name, msc.mpid_public_key,
                                 msc.mmid_public_key, msc.status,
                                 msc.rank, msc.last_contact))
             << "MI - Problem adding a contact";
   ASSERT_EQ(0, sch_->OrderedContacts(&mi_list)) <<
             "MI - Problem getting contact list";
   ASSERT_EQ((unsigned)2, mi_list.size()) <<
             "MI - List came back with wrong number of elements after addition.";
 }

 TEST_F(ContactsTest, BEH_DeleteContacts) {
   std::vector<Contact> mi_list;
   ASSERT_EQ(0, sch_->OrderedContacts(&mi_list)) <<
             "MI - Problem getting contact list";
   ASSERT_EQ((unsigned)0, mi_list.size()) <<
             "List came back not empty after DB creation.";

   Contact msc(contact_);
   ASSERT_EQ(0, sch_->AddContact(msc)) << "MI - Problem adding a contact";
   ASSERT_EQ(0, sch_->OrderedContacts(&mi_list)) <<
             "MI - Problem getting contact list";
   ASSERT_EQ((unsigned)1, mi_list.size()) <<
             "MI - List came back empty after addition.";

   Contact mic;
   ASSERT_EQ(0, sch_->ContactInfo(msc.public_username, &mic)) <<
             "MI - Problem getting the contact";
   ASSERT_EQ(msc.public_username, mic.public_username) <<
             "MI - Public name not the same";

   ASSERT_EQ(0, sch_->DeleteContact(msc.public_username)) <<
             "MI - Problem deleting contact.";
   ASSERT_EQ(-80, sch_->ContactInfo(msc.public_username, &mic)) <<
             "MI - Contact exists after deletion";
   ASSERT_EQ(0, sch_->OrderedContacts(&mi_list)) <<
             "MI - Problem getting contact list";
   ASSERT_EQ((unsigned)0, mi_list.size()) <<
             "MI - List came back empty after addition.";
   ASSERT_EQ(-78, sch_->DeleteContact(msc.public_username)) <<
             "MI - Problem deleting contact.";
 }

 TEST_F(ContactsTest, BEH_Update_Select_PubName_Contacts) {
   std::vector<Contact> mi_list;
   ASSERT_EQ(0, sch_->OrderedContacts(&mi_list)) <<
             "MI - Problem getting contact list";
   ASSERT_EQ((unsigned)0, mi_list.size()) <<
             "List came back not empty after DB creation.";

   Contact msc(contact_);
   ASSERT_EQ(0, sch_->AddContact(msc))
             << "MI - Problem adding a contact";
   ASSERT_EQ(0, sch_->OrderedContacts(&mi_list)) <<
             "MI - Problem getting contact list";
   ASSERT_EQ((unsigned)1, mi_list.size()) <<
             "MI - List came back empty after addition.";

   Contact mic;
   ASSERT_EQ(0, sch_->ContactInfo(msc.public_username, &mic)) <<
             "MI - Problem getting the contact";
   ASSERT_EQ(msc.public_username, mic.public_username) <<
             "MI - Public name not the same";

   Contact msc1(contact_);
   msc1.mpid_name = "new mpid name";
   msc1.mmid_name = "new mmid name";
   msc1.mpid_public_key = keys_.public_key;
   msc1.mmid_public_key = keys_.public_key;
   msc1.status = Contact::kConfirmed;


   // Public key
   ASSERT_EQ(0, sch_->UpdateMpidPublicKey(msc1.public_username,
                                          msc1.mpid_public_key))
             << "MI - Pub key update failed";
   ASSERT_EQ(0, sch_->ContactInfo(msc1.public_username, &mic)) <<
             "MI - Problem getting the contact";
   ASSERT_TRUE(asymm::MatchingPublicKeys(msc1.mpid_public_key,
                                         mic.mpid_public_key)) <<
               "MI - MPID Public key not the same";
   ASSERT_FALSE(asymm::MatchingPublicKeys(msc1.mmid_public_key,
                                          mic.mmid_public_key)) <<
               "MI - MMID Public key become the same before update";
   ASSERT_EQ(0, sch_->UpdateMmidPublicKey(msc1.public_username,
                                          msc1.mmid_public_key)) <<
             "MI - Pub key update failed";
   ASSERT_EQ(0, sch_->ContactInfo(msc1.public_username, &mic)) <<
             "MI - Problem getting the contact";
   ASSERT_TRUE(asymm::MatchingPublicKeys(msc1.mpid_public_key,
                                         mic.mpid_public_key)) <<
             "MI - MPID Public key not the same";
   ASSERT_TRUE(asymm::MatchingPublicKeys(msc1.mmid_public_key,
                                         mic.mmid_public_key)) <<
             "MI - MMID Public key not the same";

   // Name
   ASSERT_EQ(0, sch_->UpdateMpidName(msc1.public_username, msc1.mpid_name))
             << "MI - MOID name update failed";
   ASSERT_EQ(0, sch_->ContactInfo(msc1.public_username, &mic)) <<
             "MI - Problem getting the contact";
   ASSERT_EQ(msc1.mpid_name, mic.mpid_name) <<
             "MI - MPID name not the same";
   ASSERT_NE(msc1.mmid_name, mic.mmid_name) <<
             "MI - MMID name become the same before update";
   ASSERT_EQ(0, sch_->UpdateMmidName(msc1.public_username, msc1.mmid_name)) <<
             "MI - MMID name update failed";
   ASSERT_EQ(0, sch_->ContactInfo(msc1.public_username, &mic)) <<
             "MI - Problem getting the contact";
   ASSERT_EQ(msc1.mpid_name, mic.mpid_name) <<
             "MI - MPID name not the same";
   ASSERT_EQ(msc1.mmid_name, mic.mmid_name) <<
             "MI - MMID name not the same";

   // Status
   ASSERT_EQ(0, sch_->UpdateStatus(msc1.public_username, msc1.status)) <<
             "MI - Status update failed";
   ASSERT_EQ(0, sch_->ContactInfo(msc1.public_username, &mic)) <<
             "MI - Problem getting the contact";
   ASSERT_EQ(msc1.status, mic.status) <<
             "MI - Status not the same";

   // All together
   msc1.mpid_name = "latest mpid name";
   msc1.mmid_name = "latest mmid name";
   msc1.mpid_public_key = keys1_.public_key;
   msc1.mmid_public_key = keys1_.public_key;
   msc1.status = Contact::kPendingResponse;
   ASSERT_EQ(0, sch_->UpdateContact(msc1)) << "MI - Status update failed";
   ASSERT_EQ(0, sch_->ContactInfo(msc1.public_username, &mic)) <<
             "MI - Problem getting the contact";
   ASSERT_TRUE(asymm::MatchingPublicKeys(msc1.mpid_public_key,
                                         mic.mpid_public_key)) <<
             "MI - MPID Public key not the same";
   ASSERT_TRUE(asymm::MatchingPublicKeys(msc1.mmid_public_key,
                                         mic.mmid_public_key)) <<
             "MI - MMID Public key not the same";
   ASSERT_EQ(msc1.mpid_name, mic.mpid_name) <<
             "MI - MPID name not the same";
   ASSERT_EQ(msc1.mmid_name, mic.mmid_name) <<
             "MI - MMID name not the same";
   ASSERT_EQ(msc1.status, mic.status) <<
             "MI - Status not the same";
 }

//  TEST_F(ContactsTest, BEH_LastContact_Rank_Contacts) {
//    std::string pub_name("");
//    std::vector<Contact> mi_list;
//    ASSERT_EQ(0, sch_->OrderedContacts(&mi_list)) <<
//              "MI - Problem getting contact list";
//    ASSERT_EQ((unsigned)0, mi_list.size()) <<
//              "List came back not empty after DB creation.";
// 
//    Contact msc(contact_);
//    ASSERT_EQ(0, sch_->AddContact(msc.public_username, msc.PublicKey(),
//                 msc.FullName(), msc.OfficePhone(), msc.Birthday(),
//                 msc.Gender(), msc.Language(), msc.Country(), msc.City(),
//                 msc.Confirmed(), 0, 0))
//              << "MI - Problem adding a contact";
//    ASSERT_EQ(0, sch_->OrderedContacts(&mi_list)) <<
//              "MI - Problem getting contact list";
//    ASSERT_EQ((unsigned)1, mi_list.size()) <<
//              "MI - List came back empty after addition.";
// 
//    pub_name = msc.public_username;
//    Contact mic;
//    ASSERT_EQ(0, sch_->SetLastContactRank(msc.public_username)) <<
//              "Problem modifying contact";
//    ASSERT_EQ(0, sch_->ContactInfo(msc.public_username, &mic)) <<
//              "MI - Problem getting the contact";
//    ASSERT_EQ(msc.public_username, mic.public_username) <<
//              "MI - Public name not the same";
//    ASSERT_LT(0, mic.last_contact_) <<
//              "Last contact did not update";
//    boost::uint32_t time = mic.last_contact_;
//    ASSERT_EQ(1, mic.rank_) << "Rank did not update";
// 
//    Sleep(boost::posix_time::seconds(1));
//    ASSERT_EQ(0, sch_->SetLastContactRank(msc.public_username)) <<
//              "Problem modifying contact";
//    ASSERT_EQ(0, sch_->ContactInfo(msc.public_username, &mic)) <<
//              "MI - Problem getting the contact";
//    ASSERT_EQ(msc.public_username, mic.public_username) <<
//              "MI - Public name not the same";
//    ASSERT_LT(time, static_cast<boost::uint32_t>(mic.last_contact_)) <<
//              "Last contact did not update";
//    ASSERT_EQ(2, mic.rank_) << "Rank did not update";
//  }

 TEST_F(ContactsTest, BEH_ListContacts_Rank_LastContact) {
   std::vector<Contact> mi_list;
   ASSERT_EQ(0, sch_->OrderedContacts(&mi_list)) <<
             "MI - Problem getting contact list";
   ASSERT_EQ((unsigned)0, mi_list.size()) <<
             "List came back not empty after DB creation.";

   Contact msc(contact_);
   for (int n = 1; n < 21; n++) {
     msc.rank = RandomUint32() % 10;
     msc.last_contact = RandomUint32() % 10;
     msc.public_username = "pub_name_" + IntToString(n);
     ASSERT_EQ(0, sch_->AddContact(msc));
   }

   ASSERT_EQ(0, sch_->OrderedContacts(&mi_list)) <<
             "MI - Problem getting contact list";
   ASSERT_EQ((unsigned)20, mi_list.size()) <<
             "List with wrong number of items after DB creation.";

   ASSERT_EQ(0, sch_->OrderedContacts(&mi_list, ContactsHandler::kPopular)) <<
             "MI - Problem getting contact list";
   ASSERT_EQ((unsigned)20, mi_list.size()) <<
             "List came back not empty after DB creation.";

   for (unsigned int n = 0; n < mi_list.size()-1; n++) {
     Contact mic = mi_list[n];
     Contact mic1 = mi_list[n+1];
     ASSERT_GE(mic.rank, mic1.rank) << "Rank order higher-to-lower broken.";
   }

   ASSERT_EQ(0, sch_->OrderedContacts(&mi_list,
                                      ContactsHandler::kLastContacted)) <<
             "MI - Problem getting contact list";
   ASSERT_EQ((unsigned)20, mi_list.size()) <<
             "List came back not empty after DB creation.";

   for (unsigned int n = 0; n < mi_list.size()-1; n++) {
     Contact mic = mi_list[n];
     Contact mic1 = mi_list[n+1];
     ASSERT_GE(mic.last_contact, mic1.last_contact) <<
               "Last contact order higher-to-lower broken.";
   }
 }

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
