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

//#include "maidsafe/lifestuff/public_id.h"
//
//#include "maidsafe/common/test.h"
//#include "maidsafe/common/utils.h"
//
//#include "maidsafe/lifestuff/contacts.h"
//#include "maidsafe/lifestuff/session.h"
//#include "maidsafe/lifestuff/tests/test_callback.h"
//#if defined AMAZON_WEB_SERVICE_STORE
//#  include "maidsafe/lifestuff/store_components/aws_store_manager.h"
//#else
//#  include "maidsafe/lifestuff/store_components/local_store_manager.h"
//#endif
//
//namespace ba = boost::asio;
//namespace bptime = boost::posix_time;
//namespace bs2 = boost::signals2;
//namespace args = std::placeholders;
//namespace fs = boost::filesystem;
//
//namespace maidsafe {
//
//namespace lifestuff {
//
//namespace test {
//
//class PublicIdTest : public testing::Test {
// public:
//  PublicIdTest()
//      : test_dir_(maidsafe::test::CreateTestPath()),
//        session1_(new Session),
//        session2_(new Session),
//#if defined AMAZON_WEB_SERVICE_STORE
//        packet_manager1_(new AWSStoreManager(session1_, *test_dir_)),
//        packet_manager2_(new AWSStoreManager(session2_, *test_dir_)),
//#else
//        packet_manager1_(new LocalStoreManager(session1_, test_dir_->string())),
//        packet_manager2_(new LocalStoreManager(session2_, test_dir_->string())),
//#endif
//        asio_service_(),
//        work_(new ba::io_service::work(asio_service_)),
//        threads_(),
//        public_id1_(packet_manager1_, session1_, asio_service_),
//        public_id2_(packet_manager2_, session2_, asio_service_),
//        public_username1_("User 1 " + RandomAlphaNumericString(8)),
//        public_username2_("User 2 " + RandomAlphaNumericString(8)),
//        received_public_username_(),
//        interval_(3) {}
//
//  bool NewContactSlot(const std::string &/*own_public_username*/,
//                      const std::string &other_public_username,
//                      bool accept_new_contact) {
//    received_public_username_ = other_public_username;
//    return accept_new_contact;
//  }
//
//  void ContactConfirmedSlot(const std::string &signal_public_username,
//                            std::string *slot_public_username,
//                            volatile bool *invoked) {
//    *slot_public_username  = signal_public_username;
//    *invoked = true;
//  }
//
// protected:
//  void SetUp() {
//    session1_->ResetSession();
//    session2_->ResetSession();
//    packet_manager1_->Init([](int /*result*/) {});
//    packet_manager2_->Init([](int /*result*/) {});
//    for (int i(0); i != 10; ++i)
//      threads_.create_thread(std::bind(
//          static_cast<std::size_t(boost::asio::io_service::*)()>
//              (&boost::asio::io_service::run), &asio_service_));
//  }
//
//  void TearDown() {
//    work_.reset();
//    asio_service_.stop();
//    threads_.join_all();
//    packet_manager1_->Close(true);
//    packet_manager2_->Close(true);
//  }
//
//  std::shared_ptr<fs::path> test_dir_;
//  std::shared_ptr<Session> session1_, session2_;
//  std::shared_ptr<PacketManager> packet_manager1_, packet_manager2_;
//  ba::io_service asio_service_;
//  std::shared_ptr<ba::io_service::work> work_;
//  boost::thread_group threads_;
//  PublicId public_id1_, public_id2_;
//  std::string public_username1_,
//              public_username2_,
//              received_public_username_/*, received_public_username2_*/;
//  bptime::seconds interval_;
//
// private:
//  explicit PublicIdTest(const PublicIdTest&);
//  PublicIdTest &operator=(const PublicIdTest&);
//};
//
//TEST_F(PublicIdTest, FUNC_CreateInvalidId) {
//  ASSERT_EQ(kPublicIdEmpty, public_id1_.CreatePublicId("", false));
//  ASSERT_EQ(kPublicIdEmpty, public_id1_.CreatePublicId("", true));
//
//  ASSERT_EQ(kNoPublicIds, public_id1_.StartCheckingForNewContacts(interval_));
//
//  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, false));
//
//  // The remote chunkstore doesn't check on AWS during the Has operation, so
//  // this results in an attampt to store the ID packets again, hence the
//  // different failures below.
//#if defined AMAZON_WEB_SERVICE_STORE
//  EXPECT_EQ(kStorePublicIdFailure,
//            public_id1_.CreatePublicId(public_username1_, false));
//#else
//  EXPECT_EQ(kPublicIdExists,
//            public_id1_.CreatePublicId(public_username1_, false));
//#endif
//  EXPECT_EQ(kPublicIdExists,
//            public_id1_.CreatePublicId(public_username1_, true));
//  ASSERT_EQ(kPublicIdExists,
//            public_id2_.CreatePublicId(public_username1_, false));
//  ASSERT_EQ(kPublicIdExists,
//            public_id2_.CreatePublicId(public_username1_, true));
//}
//
//TEST_F(PublicIdTest, FUNC_CreatePublicIdAntiSocial) {
//  // Create user1 who doesn't accept new contacts, and user2 who does
//  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, false));
//  ASSERT_EQ(kSuccess, public_id2_.CreatePublicId(public_username2_, true));
//
//  public_id1_.new_contact_signal()->connect(
//      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, args::_2, true));
//  ASSERT_EQ(kSuccess, public_id1_.StartCheckingForNewContacts(interval_));
//
//  ASSERT_EQ(kSendContactInfoFailure,
//            public_id2_.SendContactInfo(public_username2_, public_username1_));
//
//  Sleep(interval_ * 2);
//  ASSERT_TRUE(received_public_username_.empty());
//}
//
//TEST_F(PublicIdTest, FUNC_CreatePublicIdSociable) {
//  // Create users who both accept new contacts
//  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, true));
//  ASSERT_EQ(kSuccess, public_id2_.CreatePublicId(public_username2_, true));
//
//  // Connect a slot which will reject the new contact
//  bs2::connection connection(public_id1_.new_contact_signal()->connect(
//      std::bind(&PublicIdTest::NewContactSlot,
//                this, args::_1, args::_2, false)));
//  ASSERT_EQ(kSuccess,
//            public_id2_.SendContactInfo(public_username2_, public_username1_));
//
//  ASSERT_EQ(kSuccess, public_id1_.StartCheckingForNewContacts(interval_));
//  Sleep(interval_ * 2);
//  ASSERT_EQ(public_username2_, received_public_username_);
//  mi_contact received_contact;
//  ASSERT_EQ(-1913, session1_->contacts_handler()->GetContactInfo(
//                       received_public_username_, &received_contact));
//
//  // Connect a slot which will accept the new contact
//  connection.disconnect();
//  received_public_username_.clear();
//  received_contact = mi_contact();
//  public_id1_.new_contact_signal()->connect(
//      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, args::_2, true));
//  ASSERT_EQ(kSuccess,
//            public_id2_.SendContactInfo(public_username2_, public_username1_));
//
//  Sleep(interval_ * 2);
//
//  ASSERT_EQ(public_username2_, received_public_username_);
//  ASSERT_EQ(kSuccess,
//            session1_->contacts_handler()->GetContactInfo(
//                received_public_username_, &received_contact));
//// TODO(Fraser#5#): 2011-12-01 - Check contents of contact struct are correct
//
//  std::string public_username3(public_username2_ + "1");
//  ASSERT_EQ(kSuccess,
//            public_id2_.CreatePublicId(public_username3, true));
//  ASSERT_EQ(kSuccess,
//            public_id2_.SendContactInfo(public_username3, public_username1_));
//  Sleep(interval_ * 2);
//  ASSERT_EQ(public_username3, received_public_username_);
//}
//
//TEST_F(PublicIdTest, FUNC_CreatePublicIdWithReply) {
//  // Create users who both accept new contacts
//  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, true));
//  ASSERT_EQ(kSuccess, public_id2_.CreatePublicId(public_username2_, true));
//
//  // Connect a slot which will reject the new contact
//  bs2::connection connection(public_id1_.new_contact_signal()->connect(
//      std::bind(&PublicIdTest::NewContactSlot,
//                this, args::_1, args::_2, true)));
//  volatile bool invoked(false);
//  std::string confirmed_contact;
//  bs2::connection connection2(public_id2_.contact_confirmed_signal()->connect(
//      std::bind(&PublicIdTest::ContactConfirmedSlot,
//                this, args::_1, &confirmed_contact, &invoked)));
//  ASSERT_EQ(kSuccess,
//            public_id2_.SendContactInfo(public_username2_, public_username1_));
//
//  ASSERT_EQ(kSuccess, public_id1_.StartCheckingForNewContacts(interval_));
//  ASSERT_EQ(kSuccess, public_id2_.StartCheckingForNewContacts(interval_));
//
//  while (!invoked)
//    Sleep(bptime::milliseconds(100));
//
//  ASSERT_EQ(public_username2_, received_public_username_);
//  ASSERT_EQ(public_username1_, confirmed_contact);
//  mi_contact received_contact;
//  ASSERT_EQ(kSuccess,
//            session1_->contacts_handler()->GetContactInfo(
//                public_username2_,
//                &received_contact));
//  received_contact = mi_contact();
//  ASSERT_EQ(kSuccess,
//            session2_->contacts_handler()->GetContactInfo(
//                public_username1_,
//                &received_contact));
//}
//
//TEST_F(PublicIdTest, FUNC_DeletePublicId) {
//  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, true));
//  ASSERT_EQ(kSuccess, public_id2_.CreatePublicId(public_username2_, true));
//
//  // TODO(Fraser#5#): 2011-12-01 - Change kPendingResult for correct value
//  ASSERT_EQ(kPendingResult, public_id1_.DeletePublicId(""));
//  ASSERT_EQ(kPendingResult, public_id1_.DeletePublicId("Rubbish"));
//
//  ASSERT_EQ(kSuccess, public_id1_.DeletePublicId(public_username1_));
//  // TODO(Fraser#5#): 2011-12-01 - Check user2 can't "send" message to user1's
//  //                               MMID
//
//  // Check a new user can't take this public username
//  ASSERT_EQ(kPublicIdExists,
//            public_id2_.CreatePublicId(public_username1_, false));
//  ASSERT_EQ(kPublicIdExists,
//            public_id2_.CreatePublicId(public_username1_, true));
//
//  // Check the original user can re-take the public username
//  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, true));
//}
//
//// TODO(Fraser#5#): 2011-12-01 - Test for multiple public usernames per user
//// TODO(Fraser#5#): 2011-12-01 - Test for moving MMID
//
//TEST_F(PublicIdTest, FUNC_ContactList) {
//  int n(5);
//  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, true));
//  std::vector<std::string> usernames;
//  for (int a(0); a < n; ++a) {
//    usernames.push_back(public_username2_ +
//                        boost::lexical_cast<std::string>(a));
//    ASSERT_EQ(kSuccess, public_id2_.CreatePublicId(usernames.at(a), true));
//  }
//
//  for (int y(0); y < n; ++y) {
//    ASSERT_EQ(kSuccess,
//              public_id2_.SendContactInfo(
//                  public_username2_ + boost::lexical_cast<std::string>(y),
//                  public_username1_));
//  }
//
//  public_id1_.new_contact_signal()->connect(
//      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, args::_2, true));
//  ASSERT_EQ(kSuccess, public_id1_.StartCheckingForNewContacts(interval_));
//  Sleep(interval_ * 3);
//
//  std::vector<std::string> contacts(public_id1_.ContactList());
//  ASSERT_EQ(size_t(n), contacts.size());
//  ASSERT_EQ(std::set<std::string>(usernames.begin(), usernames.end()),
//            std::set<std::string>(contacts.begin(), contacts.end()));
//}
//
//TEST_F(PublicIdTest, FUNC_PublicIdList) {
//  int n(10);
//  for (int a(0); a < n; ++a) {
//    std::string pub_name(public_username1_ +
//                         boost::lexical_cast<std::string>(a));
//    ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(pub_name, (a % 2) == 0));
//    DLOG(INFO) << "Created #" << a;
//  }
//
//  std::vector<std::string> public_ids(public_id1_.PublicIdsList());
//  ASSERT_EQ(size_t(n), public_ids.size());
//  for (int y(0); y < n; ++y)
//    ASSERT_EQ(public_username1_ + boost::lexical_cast<std::string>(y),
//              public_ids.at(y));
//}
//
//}  // namespace test
//
//}  // namespace lifestuff
//
//}  // namespace maidsafe
