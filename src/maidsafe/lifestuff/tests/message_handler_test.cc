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

#include "maidsafe/lifestuff/message_handler.h"

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/public_id.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/tests/test_callback.h"
#if defined AMAZON_WEB_SERVICE_STORE
#  include "maidsafe/lifestuff/store_components/aws_store_manager.h"
#else
#  include "maidsafe/lifestuff/store_components/local_store_manager.h"
#endif

namespace args = std::placeholders;
namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

namespace test {

class MessageHandlerTest : public testing::Test {
 public:
  MessageHandlerTest()
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
        message_handler1_(packet_manager1_, session1_, asio_service_),
        message_handler2_(packet_manager2_, session2_, asio_service_),
        public_username1_("User 1 " + RandomAlphaNumericString(8)),
        public_username2_("User 2 " + RandomAlphaNumericString(8)),
        received_public_username_(),
        interval_(3) {}

  bool NewContactSlot(const std::string &/*own_public_username*/,
                      const std::string &other_public_username,
                      bool accept_new_contact) {
    received_public_username_ = other_public_username;
    return accept_new_contact;
  }

  void NewMessagetSlot(const pca::Message &signal_message,
                       pca::Message *slot_message,
                       volatile bool *invoked) {
    *slot_message = signal_message;
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

  bool MessagesEqual(const pca::Message &left,
                     const pca::Message &right) const {
    return left.type() == right.type() &&
           left.id() == right.id() &&
           left.parent_id() == right.parent_id() &&
           left.has_subject() == right.has_subject() &&
           left.subject() == right.subject() &&
           left.content_size() == right.content_size();
  }

  std::shared_ptr<fs::path> test_dir_;
  std::shared_ptr<Session> session1_, session2_;
  std::shared_ptr<PacketManager> packet_manager1_, packet_manager2_;
  ba::io_service asio_service_;
  std::shared_ptr<ba::io_service::work> work_;
  boost::thread_group threads_;
  PublicId public_id1_, public_id2_;
  MessageHandler message_handler1_, message_handler2_;
  std::string public_username1_, public_username2_, received_public_username_;
  bptime::seconds interval_;

 private:
  explicit MessageHandlerTest(const MessageHandlerTest&);
  MessageHandlerTest &operator=(const MessageHandlerTest&);
};

TEST_F(MessageHandlerTest, FUNC_ReceiveOneMessage) {
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_.CreatePublicId(public_username2_, true));

  // Connect a slot which will reject the new contact
  public_id1_.new_contact_signal()->connect(
      std::bind(&MessageHandlerTest::NewContactSlot,
                this, args::_1, args::_2, true));
  ASSERT_EQ(kSuccess, public_id1_.StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSuccess,
            public_id2_.SendContactInfo(public_username2_, public_username1_));

  Sleep(interval_ * 2);
  ASSERT_EQ(public_username2_, received_public_username_);
  mi_contact received_contact;
  ASSERT_EQ(kSuccess,
            session1_->contacts_handler()->GetContactInfo(
                received_public_username_,
                &received_contact));
  public_id1_.StopCheckingForNewContacts();
  Sleep(interval_ * 2);

  pca::Message received;
  volatile bool invoked(false);
  message_handler2_.new_message_signal()->connect(
      std::bind(&MessageHandlerTest::NewMessagetSlot,
                this, args::_1, &received, &invoked));
  ASSERT_EQ(kSuccess,
            message_handler2_.StartCheckingForNewMessages(interval_));

  pca::Message sent;
  sent.set_type(pca::Message::kNormal);
  sent.set_id("id");
  sent.set_parent_id("parent_id");
  sent.set_sender_public_username(public_username1_);
  sent.set_subject("subject");
  sent.add_content(std::string("content"));

  ASSERT_EQ(kSuccess,
            message_handler1_.Send(public_username1_, public_username2_, sent));

  while (!invoked)
    Sleep(bptime::milliseconds(100));

  ASSERT_TRUE(MessagesEqual(sent, received));
}

//  TEST_F(PublicIdTest, FUNC_CreatePublicIdAntiSocial) {
//  // Create user1 who doesn't accept new contacts, and user2 who does
//  EXPECT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, false));
//  EXPECT_EQ(kSuccess, public_id2_.CreatePublicId(public_username2_, true));
//
//  public_id1_.new_contact_signal()->connect(
//      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, true));
//  EXPECT_EQ(kSuccess, public_id1_.StartCheckingForNewContacts(interval_));
//
//  EXPECT_EQ(kSendContactInfoFailure,
//           public_id2_.SendContactInfo(public_username2_, public_username1_));
//
//  Sleep(interval_ * 2);
//  EXPECT_TRUE(received_public_username_.empty());
//  }
//
// TEST_F(PublicIdTest, FUNC_CreatePublicIdSociable) {
//  // Create users who both accept new contacts
//  EXPECT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, true));
//  EXPECT_EQ(kSuccess, public_id2_.CreatePublicId(public_username2_, true));
//
//  // Connect a slot which will reject the new contact
//  bs2::connection connection(public_id1_.new_contact_signal()->connect(
//      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, false)));
//  EXPECT_EQ(kSuccess,
//           public_id2_.SendContactInfo(public_username2_, public_username1_));
//
//  EXPECT_EQ(kSuccess, public_id1_.StartCheckingForNewContacts(interval_));
//  Sleep(interval_ * 2);
//  EXPECT_EQ(public_username2_, received_public_username_);
//  mi_contact received_contact;
//  EXPECT_EQ(-1913, session1_->contacts_handler()->GetContactInfo(
//                       received_public_username_, &received_contact));
//
//  // Connect a slot which will accept the new contact
//  connection.disconnect();
//  received_public_username_.clear();
//  received_contact = mi_contact();
//  public_id1_.new_contact_signal()->connect(
//      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, true));
//  EXPECT_EQ(kSuccess,
//           public_id2_.SendContactInfo(public_username2_, public_username1_));
//  Sleep(interval_ * 2);
//  EXPECT_EQ(public_username2_, received_public_username_);
//  EXPECT_EQ(kSuccess,
//            session1_->contacts_handler()->GetContactInfo(
//                received_public_username_, &received_contact));
// // TODO(Fraser#5#): 2011-12-01 - Check contents of contact struct are correct
// }
//
// TEST_F(PublicIdTest, FUNC_DeletePublicId) {
//  EXPECT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, true));
//  EXPECT_EQ(kSuccess, public_id2_.CreatePublicId(public_username2_, true));
//
//  // TODO(Fraser#5#): 2011-12-01 - Change kPendingResult for correct value
//  EXPECT_EQ(kPendingResult, public_id1_.DeletePublicId(""));
//  EXPECT_EQ(kPendingResult, public_id1_.DeletePublicId("Rubbish"));
//
//  EXPECT_EQ(kSuccess, public_id1_.DeletePublicId(public_username1_));
//  // TODO(Fraser#5#): 2011-12-01 - Check user2 can't "send" message to user1's
//  //                               MMID
//
//  // Check a new user can't take this public username
//  EXPECT_EQ(kPublicIdExists,
//            public_id2_.CreatePublicId(public_username1_, false));
//  EXPECT_EQ(kPublicIdExists,
//            public_id2_.CreatePublicId(public_username1_, true));
//
//  // Check the original user can re-take the public username
//  EXPECT_EQ(kSuccess, public_id1_.CreatePublicId(public_username1_, true));
// }
//
// TODO(Fraser#5#): 2011-12-01 - Test for multiple public usernames per user
// TODO(Fraser#5#): 2011-12-01 - Test for moving MMID

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
