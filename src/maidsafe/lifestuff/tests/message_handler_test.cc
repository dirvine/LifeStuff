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

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/pd/client/client_container.h"
#endif

#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/public_id.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/utils.h"
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
        public_username1_("User 1 " + RandomAlphaNumericString(8)),
        public_username2_("User 2 " + RandomAlphaNumericString(8)),
        public_username3_("User 3 " + RandomAlphaNumericString(8)),
        received_public_username_(),
#ifndef LOCAL_TARGETS_ONLY
        client_container1_(),
        client_container2_(),
        client_container3_(),
#endif
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
    session1_->Reset();
    session2_->Reset();
    session3_->Reset();
    asio_service1_.Start(10);
    asio_service2_.Start(10);
    asio_service3_.Start(10);

#ifdef LOCAL_TARGETS_ONLY
    remote_chunk_store1_ = pcs::CreateLocalChunkStore(*test_dir_,
                                                      asio_service1_.service());
    remote_chunk_store2_ = pcs::CreateLocalChunkStore(*test_dir_,
                                                      asio_service2_.service());
    remote_chunk_store3_ = pcs::CreateLocalChunkStore(*test_dir_,
                                                      asio_service3_.service());
#else
    client_container1_ = SetUpClientContainer(*test_dir_);
    ASSERT_TRUE(client_container1_.get() != nullptr);
    remote_chunk_store1_.reset(new pcs::RemoteChunkStore(
        client_container1_->chunk_store(),
        client_container1_->chunk_manager(),
        client_container1_->chunk_action_authority()));
    client_container2_ = SetUpClientContainer(*test_dir_);
    ASSERT_TRUE(client_container2_.get() != nullptr);
    remote_chunk_store2_.reset(new pcs::RemoteChunkStore(
        client_container2_->chunk_store(),
        client_container2_->chunk_manager(),
        client_container2_->chunk_action_authority()));
    client_container3_ = SetUpClientContainer(*test_dir_);
    ASSERT_TRUE(client_container3_.get() != nullptr);
    remote_chunk_store3_.reset(new pcs::RemoteChunkStore(
        client_container3_->chunk_store(),
        client_container3_->chunk_manager(),
        client_container3_->chunk_action_authority()));
#endif

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
                                   asio_service1_.service()));
    message_handler1_.reset(new MessageHandler(remote_chunk_store1_,
                                               converter1_,
                                               session1_,
                                               asio_service1_.service()));

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
                                   asio_service2_.service()));
    message_handler2_.reset(new MessageHandler(remote_chunk_store2_,
                                               converter2_,
                                               session2_,
                                               asio_service2_.service()));

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
                                   asio_service3_.service()));
    message_handler3_.reset(new MessageHandler(remote_chunk_store3_,
                                               converter3_,
                                               session3_,
                                               asio_service3_.service()));
  }

  void TearDown() {
    asio_service1_.Stop();
    asio_service2_.Stop();
    asio_service3_.Stop();
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
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store1_,
                                         remote_chunk_store2_,
                                         remote_chunk_store3_;
  std::shared_ptr<PublicId> public_id1_, public_id2_, public_id3_;
  std::shared_ptr<MessageHandler> message_handler1_,
                                  message_handler2_,
                                  message_handler3_;

  AsioService asio_service1_, asio_service2_, asio_service3_;

  std::string public_username1_, public_username2_, public_username3_,
              received_public_username_;
#ifndef LOCAL_TARGETS_ONLY
  ClientContainerPtr client_container1_, client_container2_, client_container3_;
#endif
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
  ASSERT_EQ(priv::kModifyFailure,
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
