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
#include "maidsafe/lifestuff/data_atlas_pb.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/public_id.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/utils.h"

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
        multiple_messages_(5),
        invitations_(0) {}

  void NewContactSlot(const std::string &/*own_public_username*/,
                      const std::string &other_public_username,
                      volatile bool *done) {
    received_public_username_ = other_public_username;
    *done = true;
  }

  void NewContactCountSlot(const std::string &/*own_public_username*/,
                           const std::string &other_public_username,
                           volatile bool *done) {
    received_public_username_ = other_public_username;
    ++invitations_;
    if (invitations_ == 2U)
      *done = true;
  }

  void NewMessageSlot(const std::string &own_public_username,
                      const std::string &other_public_username,
                      const std::string &message,
                      InboxItem *slot_message,
                      volatile bool *invoked) {
    slot_message->receiver_public_id = own_public_username;
    slot_message->sender_public_id = other_public_username;
    slot_message->content.push_back(message);
    slot_message->item_type = kChat;
    *invoked = true;
  }

  void SeveralMessagesSlot(const std::string &own_public_username,
                           const std::string &other_public_username,
                           const std::string &message,
                           std::vector<InboxItem> *messages,
                           volatile bool *invoked,
                           size_t *count) {
    InboxItem slot_message;
    slot_message.receiver_public_id = own_public_username;
    slot_message.sender_public_id = other_public_username;
    slot_message.content.push_back(message);
    slot_message.item_type = kChat;
    messages->push_back(slot_message);
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
    remote_chunk_store1_ = BuildChunkStore(*test_dir_ /
                                               RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service1_.service());
    remote_chunk_store2_ = BuildChunkStore(*test_dir_ /
                                               RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service2_.service());
    remote_chunk_store3_ = BuildChunkStore(*test_dir_ /
                                               RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service3_.service());
#else
    remote_chunk_store1_ = BuildChunkStore(*test_dir_, &client_container1_);
    remote_chunk_store2_ = BuildChunkStore(*test_dir_, &client_container2_);
    remote_chunk_store3_ = BuildChunkStore(*test_dir_, &client_container3_);
#endif

    public_id1_.reset(new PublicId(remote_chunk_store1_,
                                   session1_,
                                   asio_service1_.service()));
    message_handler1_.reset(new MessageHandler(remote_chunk_store1_,
                                               session1_,
                                               asio_service1_.service()));

    public_id2_.reset(new PublicId(remote_chunk_store2_,
                                   session2_,
                                   asio_service2_.service()));
    message_handler2_.reset(new MessageHandler(remote_chunk_store2_,
                                               session2_,
                                               asio_service2_.service()));

    public_id3_.reset(new PublicId(remote_chunk_store3_,
                                   session3_,
                                   asio_service3_.service()));
    message_handler3_.reset(new MessageHandler(remote_chunk_store3_,
                                               session3_,
                                               asio_service3_.service()));
  }

  void TearDown() {
    asio_service1_.Stop();
    asio_service2_.Stop();
    asio_service3_.Stop();
  }

  bool MessagesEqual(const InboxItem &left,
                     const InboxItem &right) const {
    if (left.item_type == right.item_type &&
        left.content.size() == right.content.size() &&
        left.receiver_public_id == right.receiver_public_id &&
        left.sender_public_id == right.sender_public_id)
      return true;

    return false;
  }

  InboxItem CreateMessage(const std::string &sender,
                          const std::string receiver) {
    InboxItem sent;
    sent.sender_public_id = sender;
    sent.receiver_public_id = receiver;
    sent.content.push_back("content");
    return sent;
  }

  std::shared_ptr<fs::path> test_dir_;
  std::shared_ptr<Session> session1_, session2_, session3_;
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
  size_t multiple_messages_, invitations_;

 private:
  explicit MessageHandlerTest(const MessageHandlerTest&);
  MessageHandlerTest &operator=(const MessageHandlerTest&);
};

TEST_F(MessageHandlerTest, FUNC_ReceiveOneMessage) {
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_username2_, true));

  // Connect a slot which will reject the new contact
  volatile bool done(false);
  public_id1_->ConnectToNewContactSignal(
      std::bind(&MessageHandlerTest::NewContactSlot,
                this, args::_1, args::_2, &done));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSuccess,
            public_id2_->SendContactInfo(public_username2_, public_username1_));

  while (!done)
    Sleep(bptime::milliseconds(100));
  ASSERT_EQ(public_username2_, received_public_username_);
  Contact received_contact;
  ASSERT_EQ(kSuccess,
            session1_->contact_handler_map()[public_username1_]->ContactInfo(
                received_public_username_,
                &received_contact));

  InboxItem received;
  volatile bool invoked(false);
  message_handler2_->ConnectToChatSignal(
      std::bind(&MessageHandlerTest::NewMessageSlot,
                this, args::_1, args::_2, args::_3, &received, &invoked));
  ASSERT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));

  InboxItem sent(CreateMessage(public_username1_, public_username2_));
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
  volatile bool done(false);
  public_id1_->ConnectToNewContactSignal(
      std::bind(&MessageHandlerTest::NewContactSlot,
                this, args::_1, args::_2, &done));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSuccess,
            public_id2_->SendContactInfo(public_username2_, public_username1_));
  while (!done)
    Sleep(bptime::milliseconds(100));
  ASSERT_EQ(public_username2_, received_public_username_);
  Contact received_contact;
  ASSERT_EQ(kSuccess,
            session1_->contact_handler_map()[public_username1_]->ContactInfo(
                received_public_username_,
                &received_contact));

  InboxItem sent(CreateMessage(public_username1_, public_username2_));
  for (size_t n(0); n < multiple_messages_; ++n) {
    sent.timestamp = crypto::Hash<crypto::SHA512>(
                         boost::lexical_cast<std::string>(n));
    ASSERT_EQ(kSuccess, message_handler1_->Send(public_username1_,
                                                public_username2_,
                                                sent));
  }

  std::vector<InboxItem> received_messages;
  volatile bool finished(false);
  bs2::connection connection(message_handler2_->ConnectToChatSignal(
                                 std::bind(
                                     &MessageHandlerTest::SeveralMessagesSlot,
                                     this,
                                     args::_1,
                                     args::_2,
                                     args::_3,
                                     &received_messages,
                                     &finished,
                                     &multiple_messages_)));
  ASSERT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  while (!finished)
    Sleep(bptime::milliseconds(100));

  connection.disconnect();
  message_handler2_->StopCheckingForNewMessages();
  ASSERT_EQ(multiple_messages_, received_messages.size());
  for (size_t a(0); a < multiple_messages_; ++a) {
    sent.timestamp = crypto::Hash<crypto::SHA512>(
                         boost::lexical_cast<std::string>(a));
    ASSERT_TRUE(MessagesEqual(sent, received_messages[a]));
  }

  done = false;
  multiple_messages_ = 1;
  for (size_t a(0); a < multiple_messages_ * 5; ++a) {
    sent.timestamp = crypto::Hash<crypto::SHA512>(
                          boost::lexical_cast<std::string>("n"));
    ASSERT_EQ(kSuccess, message_handler1_->Send(public_username1_,
                                                public_username2_,
                                                sent));
    DLOG(ERROR) << "Sent " << a;
  }

  // If same message is sent, it should be reported only once
  received_messages.clear();
  connection = message_handler2_->ConnectToChatSignal(
                   std::bind(&MessageHandlerTest::SeveralMessagesSlot,
                             this,
                             args::_1,
                             args::_2,
                             args::_3,
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

  volatile bool done1(false), done2(false), done3(false);
  public_id1_->ConnectToContactConfirmedSignal(
      std::bind(&MessageHandlerTest::NewContactCountSlot,
                this, args::_1, args::_2, &done1));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  public_id2_->ConnectToNewContactSignal(
      std::bind(&MessageHandlerTest::NewContactSlot,
                this, args::_1, args::_2, &done2));
  ASSERT_EQ(kSuccess, public_id2_->StartCheckingForNewContacts(interval_));
  public_id3_->ConnectToNewContactSignal(
      std::bind(&MessageHandlerTest::NewContactSlot,
                this, args::_1, args::_2, &done3));
  ASSERT_EQ(kSuccess, public_id3_->StartCheckingForNewContacts(interval_));

  ASSERT_EQ(kSuccess,
            public_id1_->SendContactInfo(public_username1_, public_username2_));
  ASSERT_EQ(kSuccess,
            public_id1_->SendContactInfo(public_username1_, public_username3_));
  while (!(done2 && done3))
    Sleep(bptime::milliseconds(100));

  ASSERT_EQ(kSuccess,
            public_id2_->ConfirmContact(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess,
            public_id3_->ConfirmContact(public_username3_, public_username1_));
  while (!done1)
    Sleep(bptime::milliseconds(100));

  InboxItem received;
  volatile bool invoked(false);
  message_handler1_->ConnectToChatSignal(
      std::bind(&MessageHandlerTest::NewMessageSlot,
                this, args::_1, args::_2, args::_3, &received, &invoked));
  ASSERT_EQ(kSuccess,
            message_handler1_->StartCheckingForNewMessages(interval_));

  InboxItem sent(CreateMessage(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess,
            message_handler2_->Send(public_username2_,
                                    public_username1_,
                                    sent));
  while (!invoked)
    Sleep(bptime::milliseconds(100));
  ASSERT_TRUE(MessagesEqual(sent, received));

  public_id1_->RemoveContact(public_username1_, public_username2_);
  Sleep(interval_ * 2);

  received = InboxItem();
  ASSERT_NE(kSuccess, message_handler2_->Send(public_username2_,
                                              public_username1_,
                                              sent));
  ASSERT_FALSE(MessagesEqual(sent, received));

  invoked = false;
  sent.sender_public_id = public_username3_;
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
