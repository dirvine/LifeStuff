/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
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

#include "maidsafe/lifestuff/public_id.h"

#include "boost/thread/thread.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/pd/client/client_container.h"
#endif

#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/data_atlas_pb.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/utils.h"

namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace args = std::placeholders;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

namespace test {

typedef std::map<std::string, ContactStatus> ContactMap;

class PublicIdTest : public testing::TestWithParam<std::string> {
 public:
  PublicIdTest()
      : test_dir_(maidsafe::test::CreateTestPath()),
        session1_(new Session),
        session2_(new Session),
        remote_chunk_store1_(),
        remote_chunk_store2_(),
        public_id1_(),
        public_id2_(),
        asio_service1_(),
        asio_service2_(),
        public_username1_("User 1 " + RandomAlphaNumericString(8)),
        public_username2_("User 2 " + RandomAlphaNumericString(8)),
        received_public_username_(),
#ifndef LOCAL_TARGETS_ONLY
        client_container1_(),
        client_container2_(),
#endif
        interval_(3) {}

  void ManyContactsSlot(const std::string&,
                        const std::string&,
                        volatile bool *done,
                        int *count) {
    ++(*count);
    if (*count == 5)
      *done = true;
  }

  void NewContactSlot(const std::string&,
                      const std::string &other_public_username) {
    received_public_username_ = other_public_username;
  }

  void NewContactCounterSlot(const std::string&,
                             const std::string &other_public_username,
                             const int &times,
                             int *counter,
                             volatile bool *done) {
    received_public_username_ = other_public_username;
    ++(*counter);
    if (*counter == times)
      *done = true;
  }

  void ContactRequestSlot(const std::string&,
                          const std::string &other_public_username,
                          volatile bool *invoked) {
    received_public_username_ = other_public_username;
    *invoked = true;
  }

  void ContactConfirmedSlot(const std::string&,
                            const std::string &signal_public_username,
                            std::string *slot_public_username,
                            volatile bool *invoked) {
    *slot_public_username  = signal_public_username;
    *invoked = true;
  }

 protected:
  void SetUp() {
    session1_->Reset();
    session2_->Reset();
    asio_service1_.Start(10);
    asio_service2_.Start(10);

#ifdef LOCAL_TARGETS_ONLY
    remote_chunk_store1_ = BuildChunkStore(*test_dir_ /
                                               RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service1_.service());
    remote_chunk_store2_ = BuildChunkStore(*test_dir_ /
                                               RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service2_.service());
#else
    remote_chunk_store1_ = BuildChunkStore(*test_dir_, client_container1_);
    remote_chunk_store2_ = BuildChunkStore(*test_dir_, client_container2_);
#endif

    public_id1_.reset(new PublicId(remote_chunk_store1_,
                                   session1_,
                                   asio_service1_.service()));

    public_id2_.reset(new PublicId(remote_chunk_store2_,
                                   session2_,
                                   asio_service2_.service()));
  }

  void TearDown() {
    public_id1_->StopCheckingForNewContacts();
    public_id2_->StopCheckingForNewContacts();
    asio_service1_.Stop();
    asio_service2_.Stop();
  }

  void CreateTestSignaturePackets(std::shared_ptr<Session> session) {
    ASSERT_EQ(kSuccess, session->passport_->CreateSigningPackets());
    ASSERT_EQ(kSuccess, session->passport_->ConfirmSigningPackets());
  }

  void DumpSession(std::shared_ptr<Session> session,
                   std::string *ser_keys,
                   std::string *ser_sels,
                   std::string *ser_conts) {
    ser_keys->clear();
    ser_sels->clear();
    ser_conts->clear();
    session->SerialiseKeyChain(ser_keys, ser_sels);
    std::vector<Contact> contacts;
    DataAtlas data_atlas;
    for (auto it(session->contact_handler_map().begin());
         it != session->contact_handler_map().end();
         ++it) {
      contacts.clear();
      PublicUsername *pub_name = data_atlas.add_public_usernames();
      pub_name->set_own_public_username((*it).first);
      (*it).second->OrderedContacts(&contacts, kAlphabetical, kRequestSent |
                                                              kPendingResponse |
                                                              kConfirmed |
                                                              kBlocked);
      for (size_t n = 0; n < contacts.size(); ++n) {
        PublicContact *pc = pub_name->add_contacts();
        pc->set_public_username(contacts[n].public_username);
        pc->set_mpid_name(contacts[n].mpid_name);
        pc->set_mmid_name(contacts[n].mmid_name);
        pc->set_status(contacts[n].status);
        pc->set_rank(contacts[n].rank);
        pc->set_last_contact(contacts[n].last_contact);
        DLOG(ERROR) << "Added contact " << contacts[n].public_username
                    << " of own pubname " << (*it).first;
      }
    }
    data_atlas.SerializeToString(ser_conts);
  }

  void LoadSession(std::shared_ptr<Session> session,
                   const std::string &ser_keys,
                   const std::string &ser_sels,
                   const std::string &ser_conts) {
    ASSERT_EQ(kSuccess, session->ParseKeyChain(ser_keys, ser_sels));
    DataAtlas data_atlas;
    data_atlas.ParseFromString(ser_conts);
    std::string pub_name;
    for (int n = 0; n < data_atlas.public_usernames_size(); ++n) {
      pub_name = data_atlas.public_usernames(n).own_public_username();
      session->contact_handler_map().insert(
          std::make_pair(pub_name,
                         std::make_shared<ContactsHandler>()));
      for (int a(0); a < data_atlas.public_usernames(n).contacts_size(); ++a) {
        Contact c(data_atlas.public_usernames(n).contacts(a));
        session->contact_handler_map()[pub_name]->AddContact(c);
      }
    }
  }

  std::shared_ptr<fs::path> test_dir_;
  std::shared_ptr<Session> session1_, session2_;
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store1_,
                                         remote_chunk_store2_;
  std::shared_ptr<PublicId> public_id1_, public_id2_;

  AsioService asio_service1_, asio_service2_;

  std::string public_username1_, public_username2_, received_public_username_;
#ifndef LOCAL_TARGETS_ONLY
  ClientContainerPtr client_container1_, client_container2_;
#endif
  bptime::seconds interval_;

 private:
  explicit PublicIdTest(const PublicIdTest&);
  PublicIdTest &operator=(const PublicIdTest&);
};

TEST_F(PublicIdTest, FUNC_CreateInvalidId) {
  ASSERT_EQ(kPublicIdEmpty, public_id1_->CreatePublicId("", false));
  ASSERT_EQ(kPublicIdEmpty, public_id1_->CreatePublicId("", true));

  ASSERT_EQ(kNoPublicIds, public_id1_->StartCheckingForNewContacts(interval_));

  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, false));

  ASSERT_EQ(kStorePublicIdFailure,
            public_id1_->CreatePublicId(public_username1_, false));

  ASSERT_EQ(kStorePublicIdFailure,
            public_id1_->CreatePublicId(public_username1_, true));
  ASSERT_EQ(kStorePublicIdFailure,
            public_id2_->CreatePublicId(public_username1_, false));
  ASSERT_EQ(kStorePublicIdFailure,
            public_id2_->CreatePublicId(public_username1_, true));
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdAntiSocial) {
  // Create user1 who doesn't accept new contacts, and user2 who does
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, false));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_username2_, true));

  public_id1_->ConnectToNewContactSignal(
      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, args::_2));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));

  ASSERT_EQ(kSendContactInfoFailure,
            public_id2_->SendContactInfo(public_username2_, public_username1_));

  Sleep(interval_ * 2);
  ASSERT_TRUE(received_public_username_.empty());
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdSociable) {
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_username2_, true));

  // Connect a slot which will reject the new contact
  bs2::connection connection(public_id1_->ConnectToNewContactSignal(
      std::bind(&PublicIdTest::NewContactSlot,
                this, args::_1, args::_2)));
  ASSERT_EQ(kSuccess,
            public_id2_->SendContactInfo(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));

  Sleep(interval_ * 2);

  ASSERT_EQ(public_username2_, received_public_username_);
  Contact received_contact;
  ASSERT_EQ(kSuccess,
            session1_->contact_handler_map()[public_username1_]->ContactInfo(
                received_public_username_,
                &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);

  received_contact = Contact();
  std::string public_username3(public_username2_ + "1");
  ASSERT_EQ(kSuccess,
            public_id2_->CreatePublicId(public_username3, true));
  ASSERT_EQ(kSuccess,
            public_id2_->SendContactInfo(public_username3, public_username1_));
  Sleep(interval_ * 2);
  ASSERT_EQ(public_username3, received_public_username_);
  ASSERT_EQ(kSuccess,
            session1_->contact_handler_map()[public_username1_]->ContactInfo(
                received_public_username_,
                &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdWithReply) {
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_username2_, true));

  // Connect a slot which will reject the new contact
  volatile bool invoked1(false), invoked2(false);
  bs2::connection connection(public_id1_->ConnectToNewContactSignal(
      std::bind(&PublicIdTest::ContactRequestSlot,
                this, args::_1, args::_2, &invoked1)));

  std::string confirmed_contact;
  bs2::connection connection2(public_id2_->ConnectToContactConfirmedSignal(
      std::bind(&PublicIdTest::ContactConfirmedSlot,
                this, args::_1, args::_2, &confirmed_contact, &invoked2)));

  // Send the message and start checking for messages
  ASSERT_EQ(kSuccess,
            public_id2_->SendContactInfo(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  Contact received_contact;
  ASSERT_EQ(kSuccess,
            session2_->contact_handler_map()[public_username2_]->ContactInfo(
                public_username1_,
                &received_contact));
  ASSERT_EQ(kRequestSent, received_contact.status);

  while (!invoked1)
    Sleep(bptime::milliseconds(100));

  // Other side got message. Check status of contact and reply affirmatively.
  ASSERT_EQ(public_username2_, received_public_username_);
  received_contact = Contact();
  ASSERT_EQ(kSuccess,
            session1_->contact_handler_map()[public_username1_]->ContactInfo(
                public_username2_,
                &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);
  ASSERT_EQ(kSuccess,
            public_id1_->ConfirmContact(public_username1_, public_username2_));
  ASSERT_EQ(kSuccess, public_id2_->StartCheckingForNewContacts(interval_));

  // Contact should now be confirmed after reply
  received_contact = Contact();
  ASSERT_EQ(kSuccess,
            session1_->contact_handler_map()[public_username1_]->ContactInfo(
                public_username2_,
                &received_contact));
  ASSERT_EQ(kConfirmed, received_contact.status);

  while (!invoked2)
    Sleep(bptime::milliseconds(100));


  // Confirmation received, status should be updated
  ASSERT_EQ(public_username1_, confirmed_contact);
  received_contact = Contact();
  ASSERT_EQ(kSuccess,
            session2_->contact_handler_map()[public_username2_]->ContactInfo(
                public_username1_,
                &received_contact));
  ASSERT_EQ(kConfirmed, received_contact.status);
  ASSERT_FALSE(received_contact.mmid_name.empty());
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdWithRefusal) {
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_username2_, true));

  // Connect a slot which will reject the new contact
  volatile bool invoked1(false), invoked2(false);
  bs2::connection connection(public_id1_->ConnectToNewContactSignal(
      std::bind(&PublicIdTest::ContactRequestSlot,
                this, args::_1, args::_2, &invoked1)));

  std::string confirmed_contact;
  bs2::connection connection2(public_id2_->ConnectToContactConfirmedSignal(
      std::bind(&PublicIdTest::ContactConfirmedSlot,
                this, args::_1, args::_2, &confirmed_contact, &invoked2)));

  // Send the message and start checking for messages
  ASSERT_EQ(kSuccess,
            public_id2_->SendContactInfo(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  Contact received_contact;
  ASSERT_EQ(kSuccess,
            session2_->contact_handler_map()[public_username2_]->ContactInfo(
                public_username1_,
                &received_contact));
  ASSERT_EQ(kRequestSent, received_contact.status);

  while (!invoked1)
    Sleep(bptime::milliseconds(100));

  // Other side got message. Check status of contact and reply affirmatively.
  ASSERT_EQ(public_username2_, received_public_username_);
  received_contact = Contact();
  ASSERT_EQ(kSuccess,
            session1_->contact_handler_map()[public_username1_]->ContactInfo(
                public_username2_,
                &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);
  ASSERT_EQ(kSuccess,
            public_id1_->ConfirmContact(public_username1_,
                                       public_username2_,
                                       false));
  received_contact = Contact();
  ASSERT_NE(kSuccess,
            session1_->contact_handler_map()[public_username1_]->ContactInfo(
                public_username2_,
                &received_contact));
}

TEST_F(PublicIdTest, FUNC_DisablePublicId) {
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, true));

  ASSERT_EQ(kPublicIdEmpty, public_id1_->DisablePublicId(""));
  ASSERT_EQ(kGetPublicIdError, public_id1_->DisablePublicId("Rubbish"));

  ASSERT_EQ(kSuccess, public_id1_->DisablePublicId(public_username1_));

  // Check a new user can't take this public username
  ASSERT_EQ(kStorePublicIdFailure,
            public_id2_->CreatePublicId(public_username1_, false));
  ASSERT_EQ(kStorePublicIdFailure,
            public_id2_->CreatePublicId(public_username1_, true));

  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_username2_, true));

  // Check user2 can't add itself to user1's MCID
  public_id1_->ConnectToNewContactSignal(
      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, args::_2));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSendContactInfoFailure,
            public_id2_->SendContactInfo(public_username2_, public_username1_));
  Sleep(interval_ * 2);
  ASSERT_TRUE(received_public_username_.empty());

  // TODO(Qi,Ma): 2012-01-12 -Check if user2 alread in the MCID,
  //                  then it shall not be allowed to send msg to MMID anymore
}

TEST_F(PublicIdTest, FUNC_EnablePublicId) {
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_username2_, true));

  ASSERT_EQ(kPublicIdEmpty, public_id1_->EnablePublicId(""));
  ASSERT_EQ(kGetPublicIdError, public_id1_->EnablePublicId("Rubbish"));

  ASSERT_EQ(kSuccess, public_id1_->DisablePublicId(public_username1_));

  // Check user2 can't add itself to user1's MCID
  public_id1_->ConnectToNewContactSignal(
      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, args::_2));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSendContactInfoFailure,
            public_id2_->SendContactInfo(public_username2_, public_username1_));
  Sleep(interval_ * 2);
  ASSERT_TRUE(received_public_username_.empty());

  ASSERT_EQ(kSuccess, public_id1_->EnablePublicId(public_username1_));

  // Check user2 can now add itself to user1's MCID
  public_id1_->ConnectToNewContactSignal(
      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, args::_2));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSuccess,
            public_id2_->SendContactInfo(public_username2_, public_username1_));
  Sleep(interval_ * 2);
  ASSERT_FALSE(received_public_username_.empty());
}

TEST_F(PublicIdTest, FUNC_RemoveContact) {
  // Detailed msg exchanging behaviour tests are undertaken as part of
  // message_handler_test. Here only basic functionality is tested
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_username2_, true));

  ASSERT_EQ(kPublicIdEmpty, public_id1_->RemoveContact(public_username1_, ""));
  ASSERT_EQ(kPublicIdEmpty, public_id1_->RemoveContact("", public_username2_));

  ASSERT_EQ(kLiveContactNotFound,
            public_id1_->RemoveContact(public_username1_, public_username2_));

  public_id1_->ConnectToNewContactSignal(
      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, args::_2));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSuccess,
            public_id2_->SendContactInfo(public_username2_, public_username1_));
  Sleep(interval_ * 2);
  ASSERT_FALSE(received_public_username_.empty());

  ASSERT_EQ(kSuccess,
            public_id1_->RemoveContact(public_username1_, public_username2_));

  // Although sending msg is disallowed, sending contact_info shall be allowed
  received_public_username_.clear();
  ASSERT_EQ(-77,
            public_id2_->SendContactInfo(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess,
            public_id2_->RemoveContact(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess,
            public_id2_->SendContactInfo(public_username2_, public_username1_));
  Sleep(interval_ * 2);
  ASSERT_FALSE(received_public_username_.empty());
}

TEST_F(PublicIdTest, FUNC_ContactList) {
  int n(5), counter(0);
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, true));
  std::vector<std::string> usernames;
  for (int a(0); a < n; ++a) {
    usernames.push_back(public_username2_ +
                        boost::lexical_cast<std::string>(a));
    ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(usernames.at(a), true));
  }

  for (int y(0); y < n; ++y) {
    ASSERT_EQ(kSuccess,
              public_id2_->SendContactInfo(
                  public_username2_ + boost::lexical_cast<std::string>(y),
                  public_username1_)) << y;
  }

  volatile bool done(false);
  public_id1_->ConnectToNewContactSignal(
      std::bind(&PublicIdTest::NewContactCounterSlot,
                this, args::_1, args::_2, n, &counter, &done));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSuccess, public_id2_->StartCheckingForNewContacts(interval_));

  while (!done)
    Sleep(bptime::milliseconds(100));

  ContactMap contacts(public_id1_->ContactList(public_username1_,
                                               kAlphabetical,
                                               kAll));
  ASSERT_EQ(size_t(n), contacts.size());
  for (auto it(usernames.begin()); it != usernames.end(); ++it)
    ASSERT_FALSE(contacts.find(*it) == contacts.end());
}

// Tiberius(PublicIdTest, FUNC_PublicIdList) {
//   int n(10);
//   for (int a(0); a < n; ++a) {
//     std::string pub_name(public_username1_ +
//                          boost::lexical_cast<std::string>(a));
//     ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(pub_name, (a % 2) == 0));
//     DLOG(INFO) << "Created #" << a;
//   }
//
//   std::vector<std::string> public_ids(public_id1_->PublicIdsList());
//   ASSERT_EQ(size_t(n), public_ids.size());
//   for (int y(0); y < n; ++y)
//     ASSERT_EQ(public_username1_ + boost::lexical_cast<std::string>(y),
//               public_ids.at(y));
// }

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
