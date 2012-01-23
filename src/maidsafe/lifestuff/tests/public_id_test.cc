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

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/tests/test_callback.h"
#if defined AMAZON_WEB_SERVICE_STORE
#  include "maidsafe/lifestuff/store_components/aws_store_manager.h"
#else
#  include "maidsafe/lifestuff/store_components/local_store_manager.h"
#endif

namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace args = std::placeholders;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

namespace test {

typedef std::map<std::string, ContactStatus> ContactMap;

class PublicIdTest : public testing::Test {
 public:
  PublicIdTest()
      : test_dir_(maidsafe::test::CreateTestPath()),
        session1_(new Session),
        session2_(new Session),
#if defined AMAZON_WEB_SERVICE_STORE
        packet_manager1_(new AWSStoreManager(session1_, *test_dir_)),
        packet_manager2_(new AWSStoreManager(session2_, *test_dir_)),
#else
        packet_manager1_(new LocalStoreManager(session1_, test_dir_->string())),
        packet_manager2_(new LocalStoreManager(session2_, test_dir_->string())),
#endif
        asio_service_(),
        work_(new ba::io_service::work(asio_service_)),
        threads_(),
        public_id1_(packet_manager1_, session1_, asio_service_),
        public_id2_(packet_manager2_, session2_, asio_service_),
        public_username1_("User 1 " + RandomAlphaNumericString(8)),
        public_username2_("User 2 " + RandomAlphaNumericString(8)),
        received_public_username_(),
        interval_(3) {}

  void NewContactSlot(const std::string &/*own_public_username*/,
                      const std::string &other_public_username) {
    received_public_username_ = other_public_username;
  }

  void ContactRequestSlot(const std::string &/*own_public_username*/,
                          const std::string &other_public_username,
                          volatile bool *invoked) {
    received_public_username_ = other_public_username;
    *invoked = true;
  }

  void ContactConfirmedSlot(const std::string &signal_public_username,
                            std::string *slot_public_username,
                            volatile bool *invoked) {
    *slot_public_username  = signal_public_username;
    *invoked = true;
  }

 protected:
  void SetUp() {
    session1_->ResetSession();
    session2_->ResetSession();
    packet_manager1_->Init([](int /*result*/) {});
    packet_manager2_->Init([](int /*result*/) {});
    for (int i(0); i != 10; ++i)
      threads_.create_thread(std::bind(
          static_cast<std::size_t(boost::asio::io_service::*)()>
              (&boost::asio::io_service::run), &asio_service_));
  }

  void TearDown() {
    work_.reset();
    asio_service_.stop();
    threads_.join_all();
    packet_manager1_->Close(true);
    packet_manager2_->Close(true);
  }

  std::shared_ptr<fs::path> test_dir_;
  std::shared_ptr<Session> session1_, session2_;
  std::shared_ptr<PacketManager> packet_manager1_, packet_manager2_;
  ba::io_service asio_service_;
  std::shared_ptr<ba::io_service::work> work_;
  boost::thread_group threads_;
  PublicId public_id1_, public_id2_;
  std::string public_username1_,
              public_username2_,
              received_public_username_/*, received_public_username2_*/;
  bptime::seconds interval_;

 private:
  explicit PublicIdTest(const PublicIdTest&);
  PublicIdTest &operator=(const PublicIdTest&);
};

TEST_F(PublicIdTest, FUNC_CreateInvalidId) {
  ASSERT_EQ(kPublicIdEmpty, public_id1_.CreatePublicId("", false));
  ASSERT_EQ(kPublicIdEmpty, public_id1_.CreatePublicId("", true));

  ASSERT_EQ(kNoPublicIds, public_id1_.StartCheckingForNewContacts(interval_));

  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, false));

  // The remote chunkstore doesn't check on AWS during the Has operation, so
  // this results in an attampt to store the ID packets again, hence the
  // different failures below.
#if defined AMAZON_WEB_SERVICE_STORE
  EXPECT_EQ(kStorePublicIdFailure,
            public_id1_.CreatePublicId(public_username1_, false));
#else
  EXPECT_EQ(kPublicIdExists,
            public_id1_.CreatePublicId(public_username1_, false));
#endif
  EXPECT_EQ(kPublicIdExists,
            public_id1_.CreatePublicId(public_username1_, true));
  ASSERT_EQ(kPublicIdExists,
            public_id2_.CreatePublicId(public_username1_, false));
  ASSERT_EQ(kPublicIdExists,
            public_id2_.CreatePublicId(public_username1_, true));
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdAntiSocial) {
  // Create user1 who doesn't accept new contacts, and user2 who does
  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, false));
  ASSERT_EQ(kSuccess, public_id2_.CreatePublicId(public_username2_, true));

  public_id1_.new_contact_signal()->connect(
      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, args::_2));
  ASSERT_EQ(kSuccess, public_id1_.StartCheckingForNewContacts(interval_));

  ASSERT_EQ(kSendContactInfoFailure,
            public_id2_.SendContactInfo(public_username2_, public_username1_));

  Sleep(interval_ * 2);
  ASSERT_TRUE(received_public_username_.empty());
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdSociable) {
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_.CreatePublicId(public_username2_, true));

  // Connect a slot which will reject the new contact
  bs2::connection connection(public_id1_.new_contact_signal()->connect(
      std::bind(&PublicIdTest::NewContactSlot,
                this, args::_1, args::_2)));
  ASSERT_EQ(kSuccess,
            public_id2_.SendContactInfo(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess, public_id1_.StartCheckingForNewContacts(interval_));

  Sleep(interval_ * 2);

  ASSERT_EQ(public_username2_, received_public_username_);
  Contact received_contact;
  ASSERT_EQ(kSuccess,
            session1_->contact_handler_map()[public_username1_]->ContactInfo(
                received_public_username_,
                &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);
// TODO(Fraser#5#): 2011-12-01 - Check contents of contact struct are correct

  received_contact = Contact();
  std::string public_username3(public_username2_ + "1");
  ASSERT_EQ(kSuccess,
            public_id2_.CreatePublicId(public_username3, true));
  ASSERT_EQ(kSuccess,
            public_id2_.SendContactInfo(public_username3, public_username1_));
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
  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_.CreatePublicId(public_username2_, true));

  // Connect a slot which will reject the new contact
  volatile bool invoked1(false), invoked2(false);
  bs2::connection connection(public_id1_.new_contact_signal()->connect(
      std::bind(&PublicIdTest::ContactRequestSlot,
                this, args::_1, args::_2, &invoked1)));

  std::string confirmed_contact;
  bs2::connection connection2(public_id2_.contact_confirmed_signal()->connect(
      std::bind(&PublicIdTest::ContactConfirmedSlot,
                this, args::_1, &confirmed_contact, &invoked2)));

  // Send the message and start checking for messages
  ASSERT_EQ(kSuccess,
            public_id2_.SendContactInfo(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess, public_id1_.StartCheckingForNewContacts(interval_));
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
            public_id1_.ConfirmContact(public_username1_, public_username2_));
  ASSERT_EQ(kSuccess, public_id2_.StartCheckingForNewContacts(interval_));

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
  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_.CreatePublicId(public_username2_, true));

  // Connect a slot which will reject the new contact
  volatile bool invoked1(false), invoked2(false);
  bs2::connection connection(public_id1_.new_contact_signal()->connect(
      std::bind(&PublicIdTest::ContactRequestSlot,
                this, args::_1, args::_2, &invoked1)));

  std::string confirmed_contact;
  bs2::connection connection2(public_id2_.contact_confirmed_signal()->connect(
      std::bind(&PublicIdTest::ContactConfirmedSlot,
                this, args::_1, &confirmed_contact, &invoked2)));

  // Send the message and start checking for messages
  ASSERT_EQ(kSuccess,
            public_id2_.SendContactInfo(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess, public_id1_.StartCheckingForNewContacts(interval_));
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
            public_id1_.ConfirmContact(public_username1_,
                                       public_username2_,
                                       false));
  received_contact = Contact();
  ASSERT_NE(kSuccess,
            session1_->contact_handler_map()[public_username1_]->ContactInfo(
                public_username2_,
                &received_contact));
}

TEST_F(PublicIdTest, FUNC_DisablePublicId) {
  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, true));

  ASSERT_EQ(kPublicIdEmpty, public_id1_.DisablePublicId(""));
  ASSERT_EQ(kGetPublicIdError, public_id1_.DisablePublicId("Rubbish"));

  ASSERT_EQ(kSuccess, public_id1_.DisablePublicId(public_username1_));

  // Check a new user can't take this public username
  ASSERT_EQ(kPublicIdExists,
            public_id2_.CreatePublicId(public_username1_, false));
  ASSERT_EQ(kPublicIdExists,
            public_id2_.CreatePublicId(public_username1_, true));

  ASSERT_EQ(kSuccess, public_id2_.CreatePublicId(public_username2_, true));

  // Check user2 can't add itself to user1's MCID
  public_id1_.new_contact_signal()->connect(
      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, args::_2));
  ASSERT_EQ(kSuccess, public_id1_.StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSendContactInfoFailure,
            public_id2_.SendContactInfo(public_username2_, public_username1_));
  Sleep(interval_ * 2);
  ASSERT_TRUE(received_public_username_.empty());

  // TODO(Qi,Ma): 2012-01-12 -Check if user2 alread in the MCID,
  //                  then it shall not be allowed to send msg to MMID anymore
}

TEST_F(PublicIdTest, FUNC_EnablePublicId) {
  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_.CreatePublicId(public_username2_, true));

  ASSERT_EQ(kPublicIdEmpty, public_id1_.EnablePublicId(""));
  ASSERT_EQ(kGetPublicIdError, public_id1_.EnablePublicId("Rubbish"));

  ASSERT_EQ(kSuccess, public_id1_.DisablePublicId(public_username1_));

  // Check user2 can't add itself to user1's MCID
  public_id1_.new_contact_signal()->connect(
      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, args::_2));
  ASSERT_EQ(kSuccess, public_id1_.StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSendContactInfoFailure,
            public_id2_.SendContactInfo(public_username2_, public_username1_));
  Sleep(interval_ * 2);
  ASSERT_TRUE(received_public_username_.empty());

  ASSERT_EQ(kSuccess, public_id1_.EnablePublicId(public_username1_));

  // Check user2 can now add itself to user1's MCID
  public_id1_.new_contact_signal()->connect(
      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, args::_2));
  ASSERT_EQ(kSuccess, public_id1_.StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSuccess,
            public_id2_.SendContactInfo(public_username2_, public_username1_));
  Sleep(interval_ * 2);
  ASSERT_FALSE(received_public_username_.empty());
}

TEST_F(PublicIdTest, FUNC_RemoveContact) {
  // Detailed msg exchanging behaviour tests are undertaken as part of
  // message_handler_test. Here only basic functionality is tested
  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_.CreatePublicId(public_username2_, true));

  ASSERT_EQ(kPublicIdEmpty, public_id1_.RemoveContact(public_username1_, ""));
  ASSERT_EQ(kPublicIdEmpty, public_id1_.RemoveContact("", public_username2_));

  ASSERT_EQ(kLiveContactNotFound,
            public_id1_.RemoveContact(public_username1_, public_username2_));

  public_id1_.new_contact_signal()->connect(
      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, args::_2));
  ASSERT_EQ(kSuccess, public_id1_.StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSuccess,
            public_id2_.SendContactInfo(public_username2_, public_username1_));
  Sleep(interval_ * 2);
  ASSERT_FALSE(received_public_username_.empty());

  ASSERT_EQ(kSuccess,
            public_id1_.RemoveContact(public_username1_, public_username2_));

  // Although sending msg is disallowed, sending contact_info shall be allowed
  received_public_username_.clear();
  ASSERT_EQ(-77,
            public_id2_.SendContactInfo(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess,
            public_id2_.RemoveContact(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess,
            public_id2_.SendContactInfo(public_username2_, public_username1_));
  Sleep(interval_ * 2);
  ASSERT_FALSE(received_public_username_.empty());
}

// TODO(Fraser#5#): 2011-12-01 - Test for multiple public usernames per user
// TODO(Fraser#5#): 2011-12-01 - Test for moving MMID

TEST_F(PublicIdTest, FUNC_ContactList) {
  int n(5);
  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, true));
  std::vector<std::string> usernames;
  for (int a(0); a < n; ++a) {
    usernames.push_back(public_username2_ +
                        boost::lexical_cast<std::string>(a));
    ASSERT_EQ(kSuccess, public_id2_.CreatePublicId(usernames.at(a), true));
  }

  for (int y(0); y < n; ++y) {
    ASSERT_EQ(kSuccess,
              public_id2_.SendContactInfo(
                  public_username2_ + boost::lexical_cast<std::string>(y),
                  public_username1_)) << y;
  }

  public_id1_.new_contact_signal()->connect(
      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, args::_2));
  ASSERT_EQ(kSuccess, public_id1_.StartCheckingForNewContacts(interval_));
  Sleep(interval_ * 3);

  ContactMap contacts(public_id1_.ContactList(public_username1_,
                                              kAlphabetical,
                                              kAll));
  ASSERT_EQ(size_t(n), contacts.size());
  for (auto it(usernames.begin()); it != usernames.end(); ++it)
    ASSERT_FALSE(contacts.find(*it) == contacts.end());
}

TEST_F(PublicIdTest, FUNC_PublicIdList) {
  int n(10);
  for (int a(0); a < n; ++a) {
    std::string pub_name(public_username1_ +
                         boost::lexical_cast<std::string>(a));
    ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(pub_name, (a % 2) == 0));
    DLOG(INFO) << "Created #" << a;
  }

  std::vector<std::string> public_ids(public_id1_.PublicIdsList());
  ASSERT_EQ(size_t(n), public_ids.size());
  for (int y(0); y < n; ++y)
    ASSERT_EQ(public_username1_ + boost::lexical_cast<std::string>(y),
              public_ids.at(y));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
