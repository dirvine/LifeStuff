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
#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#include "maidsafe/pd/client/client_container.h"
#include "maidsafe/pd/client/remote_chunk_store.h"

#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/local_chunk_manager.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/public_id.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/ye_olde_signal_to_callback_converter.h"

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
        session3_(new Session),
        converter1_(new YeOldeSignalToCallbackConverter),
        converter2_(new YeOldeSignalToCallbackConverter),
        converter3_(new YeOldeSignalToCallbackConverter),
        remote_chunk_store1_(),
        remote_chunk_store2_(),
        remote_chunk_store3_(),
        public_id1_(),
        public_id2_(),
        public_id3_(),
        message_handler1_(),
        message_handler2_(),
        message_handler3_(),
        asio_service1_(),
        asio_service2_(),
        asio_service3_(),
        work1_(new ba::io_service::work(asio_service1_)),
        work2_(new ba::io_service::work(asio_service2_)),
        work3_(new ba::io_service::work(asio_service3_)),
        threads1_(),
        threads2_(),
        threads3_(),
        public_username1_("User 1 " + RandomAlphaNumericString(8)),
        public_username2_("User 2 " + RandomAlphaNumericString(8)),
        public_username3_("User 3 " + RandomAlphaNumericString(8)),
        received_public_username_(),
        interval_(3),
        multiple_messages_(5) {}

  bool NewContactSlot(const std::string &/*own_public_username*/,
                      const std::string &other_public_username,
                      bool accept_new_contact) {
    received_public_username_ = other_public_username;
    return accept_new_contact;
  }

  void NewMessageSlot(const pca::Message &signal_message,
                      pca::Message *slot_message,
                      volatile bool *invoked) {
    *slot_message = signal_message;
    *invoked = true;
  }

  void SeveralMessagesSlot(const pca::Message &signal_message,
                           std::vector<pca::Message> *messages,
                           volatile bool *invoked,
                           size_t *count) {
    messages->push_back(signal_message);
    if (messages->size() == *count)
      *invoked = true;
  }

 protected:
  void SetUp() {
    session1_->ResetSession();
    session2_->ResetSession();
    session3_->ResetSession();
    for (int i1(0); i1 != 10; ++i1)
      threads1_.create_thread(std::bind(
          static_cast<std::size_t(boost::asio::io_service::*)()>
              (&boost::asio::io_service::run), &asio_service1_));
    for (int i2(0); i2 != 10; ++i2)
      threads2_.create_thread(std::bind(
          static_cast<std::size_t(boost::asio::io_service::*)()>
              (&boost::asio::io_service::run), &asio_service2_));
    for (int i3(0); i3 != 10; ++i3)
      threads3_.create_thread(std::bind(
          static_cast<std::size_t(boost::asio::io_service::*)()>
              (&boost::asio::io_service::run), &asio_service3_));

    std::shared_ptr<BufferedChunkStore> bcs1(
        new BufferedChunkStore(asio_service1_));
    bcs1->Init(*test_dir_ / "buffered_chunk_store1");
    std::shared_ptr<priv::ChunkActionAuthority> caa1(
        new priv::ChunkActionAuthority(bcs1));
    std::shared_ptr<LocalChunkManager> local_chunk_manager1(
        new LocalChunkManager(bcs1, *test_dir_ / "local_chunk_manager"));
    remote_chunk_store1_.reset(new pd::RemoteChunkStore(bcs1,
                                                        local_chunk_manager1,
                                                        caa1));
    remote_chunk_store1_->sig_chunk_stored()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Stored, converter1_.get(),
                  args::_1, args::_2));
    remote_chunk_store1_->sig_chunk_deleted()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Deleted, converter1_.get(),
                  args::_1, args::_2));
    remote_chunk_store1_->sig_chunk_modified()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Modified, converter1_.get(),
                  args::_1, args::_2));
    public_id1_.reset(new PublicId(remote_chunk_store1_,
                                   converter1_,
                                   session1_,
                                   asio_service1_));
    message_handler1_.reset(new MessageHandler(remote_chunk_store1_,
                                               converter1_,
                                               session1_,
                                               asio_service1_));

    std::shared_ptr<BufferedChunkStore> bcs2(
        new BufferedChunkStore(asio_service2_));
    bcs2->Init(*test_dir_ / "buffered_chunk_store2");
    std::shared_ptr<priv::ChunkActionAuthority> caa2(
        new priv::ChunkActionAuthority(bcs2));
    std::shared_ptr<LocalChunkManager> local_chunk_manager2(
        new LocalChunkManager(bcs2, *test_dir_ / "local_chunk_manager"));
    remote_chunk_store2_.reset(new pd::RemoteChunkStore(bcs2,
                                                        local_chunk_manager2,
                                                        caa2));
    remote_chunk_store2_->sig_chunk_stored()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Stored, converter2_.get(),
                  args::_1, args::_2));
    remote_chunk_store2_->sig_chunk_deleted()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Deleted, converter2_.get(),
                  args::_1, args::_2));
    remote_chunk_store2_->sig_chunk_modified()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Modified, converter2_.get(),
                  args::_1, args::_2));
    public_id2_.reset(new PublicId(remote_chunk_store2_,
                                   converter2_,
                                   session2_,
                                   asio_service2_));
    message_handler2_.reset(new MessageHandler(remote_chunk_store2_,
                                               converter2_,
                                               session2_,
                                               asio_service2_));

    std::shared_ptr<BufferedChunkStore> bcs3(
        new BufferedChunkStore(asio_service3_));
    bcs3->Init(*test_dir_ / "buffered_chunk_store3");
    std::shared_ptr<priv::ChunkActionAuthority> caa3(
        new priv::ChunkActionAuthority(bcs3));
    std::shared_ptr<LocalChunkManager> local_chunk_manager3(
        new LocalChunkManager(bcs3, *test_dir_ / "local_chunk_manager"));
    remote_chunk_store3_.reset(new pd::RemoteChunkStore(bcs3,
                                                        local_chunk_manager3,
                                                        caa3));
    remote_chunk_store3_->sig_chunk_stored()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Stored, converter3_.get(),
                  args::_1, args::_2));
    remote_chunk_store3_->sig_chunk_deleted()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Deleted, converter3_.get(),
                  args::_1, args::_2));
    remote_chunk_store3_->sig_chunk_modified()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Modified, converter3_.get(),
                  args::_1, args::_2));
    public_id3_.reset(new PublicId(remote_chunk_store3_,
                                   converter3_,
                                   session3_,
                                   asio_service3_));
    message_handler3_.reset(new MessageHandler(remote_chunk_store3_,
                                               converter3_,
                                               session3_,
                                               asio_service3_));
  }

  void TearDown() {
    work1_.reset();
    work2_.reset();
    work3_.reset();
    asio_service1_.stop();
    asio_service2_.stop();
    asio_service3_.stop();
    threads1_.join_all();
    threads2_.join_all();
    threads3_.join_all();
  }

  bool MessagesEqual(const pca::Message &left,
                     const pca::Message &right) const {
    bool b(left.type() == right.type() &&
           left.id() == right.id() &&
           left.parent_id() == right.parent_id() &&
           left.has_subject() == right.has_subject() &&
           left.subject() == right.subject() &&
           left.content_size() == right.content_size());
    if (left.has_timestamp() && right.has_timestamp())
      b = b && (left.timestamp() == right.timestamp());
    return b;
  }

  std::shared_ptr<fs::path> test_dir_;
  std::shared_ptr<Session> session1_, session2_, session3_;
  std::shared_ptr<YeOldeSignalToCallbackConverter> converter1_,
                                                   converter2_,
                                                   converter3_;
  std::shared_ptr<pd::RemoteChunkStore> remote_chunk_store1_,
                                        remote_chunk_store2_,
                                        remote_chunk_store3_;
  std::shared_ptr<PublicId> public_id1_, public_id2_, public_id3_;
  std::shared_ptr<MessageHandler> message_handler1_,
                                  message_handler2_,
                                  message_handler3_;

  ba::io_service asio_service1_, asio_service2_, asio_service3_;
  std::shared_ptr<ba::io_service::work> work1_, work2_, work3_;
  boost::thread_group threads1_, threads2_, threads3_;

  std::string public_username1_, public_username2_, public_username3_,
              received_public_username_;
  bptime::seconds interval_;
  size_t multiple_messages_;

 private:
  explicit MessageHandlerTest(const MessageHandlerTest&);
  MessageHandlerTest &operator=(const MessageHandlerTest&);
};

TEST_F(MessageHandlerTest, FUNC_SignalConnections) {
  pca::Message received;
  volatile bool invoked(false);
  bs2::connection connection(message_handler1_->ConnectToSignal(
                                 static_cast<pca::Message::ContentType>(
                                     pca::Message::ContentType_MIN - 1),
                                 std::bind(&MessageHandlerTest::NewMessageSlot,
                                           this, args::_1, &received,
                                           &invoked)));
  ASSERT_FALSE(connection.connected());
  connection = message_handler1_->ConnectToSignal(
                   static_cast<pca::Message::ContentType>(
                       pca::Message::ContentType_MAX + 1),
                   std::bind(&MessageHandlerTest::NewMessageSlot,
                             this, args::_1, &received, &invoked));
  ASSERT_FALSE(connection.connected());

  for (int n(pca::Message::ContentType_MIN);
       n <= pca::Message::ContentType_MAX;
       ++n) {
    connection.disconnect();
    connection = message_handler1_->ConnectToSignal(
                     static_cast<pca::Message::ContentType>(n),
                     std::bind(&MessageHandlerTest::NewMessageSlot,
                               this, args::_1, &received, &invoked));
    ASSERT_TRUE(connection.connected());
  }
}

TEST_F(MessageHandlerTest, FUNC_ReceiveOneMessage) {
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_username2_, true));

  // Connect a slot which will reject the new contact
  public_id1_->new_contact_signal()->connect(
      std::bind(&MessageHandlerTest::NewContactSlot,
                this, args::_1, args::_2, true));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSuccess,
            public_id2_->SendContactInfo(public_username2_, public_username1_));

  Sleep(interval_ * 2);
  ASSERT_EQ(public_username2_, received_public_username_);
  Contact received_contact;
  ASSERT_EQ(kSuccess,
            session1_->contact_handler_map()[public_username1_]->ContactInfo(
                received_public_username_,
                &received_contact));
  public_id1_->StopCheckingForNewContacts();
  Sleep(interval_ * 2);

  pca::Message received;
  volatile bool invoked(false);
  message_handler2_->ConnectToSignal(
      pca::Message::kNormal,
      std::bind(&MessageHandlerTest::NewMessageSlot,
                this, args::_1, &received, &invoked));
  ASSERT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));

  pca::Message sent;
  sent.set_type(pca::Message::kNormal);
  sent.set_id("id");
  sent.set_parent_id("parent_id");
  sent.set_sender_public_username(public_username1_);
  sent.set_subject("subject");
  sent.add_content(std::string("content"));

  ASSERT_EQ(kSuccess,
            message_handler1_->Send(public_username1_,
                                    public_username2_,
                                    sent));

  while (!invoked)
    Sleep(bptime::milliseconds(100));

  ASSERT_TRUE(MessagesEqual(sent, received));
}

TEST_F(MessageHandlerTest, FUNC_ReceiveMultipleMessages) {
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_username2_, true));

  // Connect a slot which will reject the new contact
  public_id1_->new_contact_signal()->connect(
      std::bind(&MessageHandlerTest::NewContactSlot,
                this, args::_1, args::_2, true));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSuccess,
            public_id2_->SendContactInfo(public_username2_, public_username1_));

  Sleep(interval_ * 2);
  ASSERT_EQ(public_username2_, received_public_username_);
  Contact received_contact;
  ASSERT_EQ(kSuccess,
            session1_->contact_handler_map()[public_username1_]->ContactInfo(
                received_public_username_,
                &received_contact));
  public_id1_->StopCheckingForNewContacts();
  Sleep(interval_ * 2);

  pca::Message sent;
  sent.set_type(pca::Message::kNormal);
  sent.set_id("id");
  sent.set_parent_id("parent_id");
  sent.set_sender_public_username(public_username1_);
  sent.set_subject("subject");
  sent.add_content(std::string("content"));

  for (size_t n(0); n < multiple_messages_; ++n) {
    sent.set_timestamp(crypto::Hash<crypto::SHA512>(
                           boost::lexical_cast<std::string>(n)));
    ASSERT_EQ(kSuccess,
              message_handler1_->Send(public_username1_,
                                     public_username2_,
                                     sent));
  }

  std::vector<pca::Message> received_messages;
  volatile bool done(false);
  bs2::connection connection(message_handler2_->ConnectToSignal(
                                 pca::Message::kNormal,
                                 std::bind(
                                     &MessageHandlerTest::SeveralMessagesSlot,
                                     this,
                                     args::_1,
                                     &received_messages,
                                     &done,
                                     &multiple_messages_)));
  ASSERT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  while (!done)
    Sleep(bptime::milliseconds(100));

  connection.disconnect();
  message_handler2_->StopCheckingForNewMessages();
  ASSERT_EQ(multiple_messages_, received_messages.size());
  for (size_t a(0); a < multiple_messages_; ++a) {
    sent.set_timestamp(crypto::Hash<crypto::SHA512>(
                           boost::lexical_cast<std::string>(a)));
    ASSERT_TRUE(MessagesEqual(sent, received_messages[a]));
  }

  done = false;
  multiple_messages_ = 1;
  for (size_t a(0); a < multiple_messages_ * 5; ++a) {
    sent.set_timestamp(crypto::Hash<crypto::SHA512>(
                           boost::lexical_cast<std::string>("n")));
    ASSERT_EQ(kSuccess,
              message_handler1_->Send(public_username1_,
                                     public_username2_,
                                     sent));
    DLOG(ERROR) << "Sent " << a;
  }

  // If same message is sent, it should be reported only once
  received_messages.clear();
  connection = message_handler2_->ConnectToSignal(
                   pca::Message::kNormal,
                   std::bind(&MessageHandlerTest::SeveralMessagesSlot,
                             this,
                             args::_1,
                             &received_messages,
                             &done,
                             &multiple_messages_));
  ASSERT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  while (!done)
    Sleep(bptime::milliseconds(100));

  message_handler2_->StopCheckingForNewMessages();
  ASSERT_EQ(multiple_messages_, received_messages.size());
}

TEST_F(MessageHandlerTest, BEH_RemoveContact) {
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_username2_, true));
  ASSERT_EQ(kSuccess, public_id3_->CreatePublicId(public_username3_, true));

  public_id1_->new_contact_signal()->connect(
      std::bind(&MessageHandlerTest::NewContactSlot,
                this, args::_1, args::_2, true));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  public_id2_->new_contact_signal()->connect(
      std::bind(&MessageHandlerTest::NewContactSlot,
                this, args::_1, args::_2, true));
  ASSERT_EQ(kSuccess, public_id2_->StartCheckingForNewContacts(interval_));
  public_id3_->new_contact_signal()->connect(
      std::bind(&MessageHandlerTest::NewContactSlot,
                this, args::_1, args::_2, true));
  ASSERT_EQ(kSuccess, public_id3_->StartCheckingForNewContacts(interval_));

  ASSERT_EQ(kSuccess,
            public_id1_->SendContactInfo(public_username1_, public_username2_));
  ASSERT_EQ(kSuccess,
            public_id1_->SendContactInfo(public_username1_, public_username3_));
  Sleep(interval_ * 2);
  ASSERT_EQ(kSuccess,
            public_id2_->ConfirmContact(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess,
            public_id3_->ConfirmContact(public_username3_, public_username1_));
  Sleep(interval_ * 2);

  pca::Message received;
  volatile bool invoked(false);
  message_handler1_->ConnectToSignal(
      pca::Message::kNormal,
      std::bind(&MessageHandlerTest::NewMessageSlot,
                this, args::_1, &received, &invoked));
  ASSERT_EQ(kSuccess,
            message_handler1_->StartCheckingForNewMessages(interval_));

  pca::Message sent;
  sent.set_type(pca::Message::kNormal);
  sent.set_id("id");
  sent.set_parent_id("parent_id");
  sent.set_sender_public_username(public_username2_);
  sent.set_subject("subject");
  sent.add_content(std::string("content"));

  ASSERT_EQ(kSuccess,
            message_handler2_->Send(public_username2_,
                                    public_username1_,
                                    sent));
  while (!invoked)
    Sleep(bptime::milliseconds(100));
  ASSERT_TRUE(MessagesEqual(sent, received));

  public_id1_->RemoveContact(public_username1_, public_username2_);
  Sleep(interval_ * 2);

  received.Clear();
  ASSERT_EQ(kUpdatePacketFailure,
            message_handler2_->Send(public_username2_,
                                    public_username1_,
                                    sent));
  Sleep(interval_ * 2);
  ASSERT_FALSE(MessagesEqual(sent, received));

  invoked = false;
  sent.set_sender_public_username(public_username3_);
  ASSERT_EQ(kSuccess,
            message_handler3_->Send(public_username3_,
                                    public_username1_,
                                    sent));
  while (!invoked)
    Sleep(bptime::milliseconds(100));
  ASSERT_TRUE(MessagesEqual(sent, received));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
