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

#include "maidsafe/lifestuff/detail/message_handler.h"

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

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/rcs_helper.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/public_id.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

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
        session1_(),
        session2_(),
        session3_(),
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

  void NewContactSlot(const std::string&,
                      const std::string &other_public_username,
                      boost::mutex *mutex,
                      boost::condition_variable *cond_var) {
    boost::mutex::scoped_lock lock(*mutex);
    received_public_username_ = other_public_username;
    cond_var->notify_one();
  }

  void NewContactCountSlot(const std::string &/*own_public_username*/,
                           const std::string &other_public_username,
                           boost::mutex *mutex,
                           boost::condition_variable *cond_var) {
    boost::mutex::scoped_lock lock(*mutex);
    received_public_username_ = other_public_username;
    ++invitations_;
    if (invitations_ == 2U)
      cond_var->notify_one();
  }

  void NewMessageSlot(const std::string &own_public_username,
                      const std::string &other_public_username,
                      const std::string &message,
                      const std::string &timestamp,
                      InboxItem *slot_message,
                      boost::mutex *mutex,
                      boost::condition_variable *cond_var) {
    boost::mutex::scoped_lock lock(*mutex);
    slot_message->receiver_public_id = own_public_username;
    slot_message->sender_public_id = other_public_username;
    slot_message->content.push_back(message);
    slot_message->item_type = kChat;
    slot_message->timestamp = timestamp;
    cond_var->notify_one();
  }

  void SeveralMessagesSlot(const std::string &own_public_username,
                           const std::string &other_public_username,
                           const std::string &message,
                           const std::string &timestamp,
                           std::vector<InboxItem> *messages,
                           boost::mutex *mutex,
                           boost::condition_variable *cond_var,
                           size_t *count) {
    boost::mutex::scoped_lock lock(*mutex);
    InboxItem slot_message;
    slot_message.receiver_public_id = own_public_username;
    slot_message.sender_public_id = other_public_username;
    slot_message.content.push_back(message);
    slot_message.item_type = kChat;
    slot_message.timestamp = timestamp;
    messages->push_back(slot_message);
    if (messages->size() == *count)
      cond_var->notify_all();
  }

 protected:
  void SetUp() {
    asio_service1_.Start(10);
    asio_service2_.Start(10);
    asio_service3_.Start(10);

#ifdef LOCAL_TARGETS_ONLY
    remote_chunk_store1_ = BuildChunkStore(*test_dir_ / RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service1_.service());
    remote_chunk_store2_ = BuildChunkStore(*test_dir_ / RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service2_.service());
    remote_chunk_store3_ = BuildChunkStore(*test_dir_ / RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service3_.service());
#else
    remote_chunk_store1_ = BuildChunkStore(*test_dir_, &client_container1_);
    remote_chunk_store2_ = BuildChunkStore(*test_dir_, &client_container2_);
    remote_chunk_store3_ = BuildChunkStore(*test_dir_, &client_container3_);
#endif

    public_id1_.reset(new PublicId(remote_chunk_store1_, session1_, asio_service1_.service()));
    message_handler1_.reset(new MessageHandler(remote_chunk_store1_,
                                               session1_,
                                               asio_service1_.service()));

    public_id2_.reset(new PublicId(remote_chunk_store2_, session2_, asio_service2_.service()));
    message_handler2_.reset(new MessageHandler(remote_chunk_store2_,
                                               session2_,
                                               asio_service2_.service()));

    public_id3_.reset(new PublicId(remote_chunk_store3_, session3_, asio_service3_.service()));
    message_handler3_.reset(new MessageHandler(remote_chunk_store3_,
                                               session3_,
                                               asio_service3_.service()));
  }

  void TearDown() {
    asio_service1_.Stop();
    asio_service2_.Stop();
    asio_service3_.Stop();
#ifndef LOCAL_TARGETS_ONLY
    client_container1_->Stop(nullptr);
    client_container2_->Stop(nullptr);
    client_container3_->Stop(nullptr);
#endif
    remote_chunk_store1_->WaitForCompletion();
    remote_chunk_store2_->WaitForCompletion();
    remote_chunk_store3_->WaitForCompletion();
  }

  bool MessagesEqual(const InboxItem &left, const InboxItem &right) const {
    if (left.item_type != right.item_type) {
      DLOG(ERROR) << "Different type.";
      return false;
    }
    if (left.content.size() != right.content.size()) {
      DLOG(ERROR) << "Different content size.";
      return false;
    }
    if (left.receiver_public_id != right.receiver_public_id) {
      DLOG(ERROR) << "Different receiver.";
      return false;
    }
    if (left.sender_public_id != right.sender_public_id) {
      DLOG(ERROR) << "Different sender.";
      return false;
    }
    if (left.timestamp != right.timestamp) {
      DLOG(ERROR) << "Different timestamp -left: " << left.timestamp
                  << ", right: " << right.timestamp;
      return false;
    }

    return true;
  }

  InboxItem CreateMessage(const std::string &sender, const std::string &receiver) {
    InboxItem sent;
    sent.sender_public_id = sender;
    sent.receiver_public_id = receiver;
    sent.content.push_back("content");
    sent.timestamp = IsoTimeWithMicroSeconds();
    return sent;
  }

  std::shared_ptr<fs::path> test_dir_;
  Session session1_, session2_, session3_;
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store1_,
                                         remote_chunk_store2_,
                                         remote_chunk_store3_;
  std::shared_ptr<PublicId> public_id1_, public_id2_, public_id3_;
  std::shared_ptr<MessageHandler> message_handler1_, message_handler2_, message_handler3_;

  AsioService asio_service1_, asio_service2_, asio_service3_;

  std::string public_username1_, public_username2_, public_username3_, received_public_username_;
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
  EXPECT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, true));
  EXPECT_EQ(kSuccess, public_id2_->CreatePublicId(public_username2_, true));

  // Connect a slot which will reject the new contact
  boost::mutex mutex;
  boost::condition_variable cond_var;
  public_id1_->ConnectToNewContactSignal(std::bind(&MessageHandlerTest::NewContactSlot,
                                                   this, args::_1, args::_2, &mutex, &cond_var));
  EXPECT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  EXPECT_EQ(kSuccess, public_id2_->SendContactInfo(public_username2_, public_username1_));

  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }

  EXPECT_EQ(public_username2_, received_public_username_);
  Contact received_contact;
  EXPECT_EQ(kSuccess,
            session1_.contact_handler_map()[public_username1_]->ContactInfo(
                received_public_username_,
                &received_contact));

  InboxItem received;
  message_handler2_->ConnectToChatSignal(std::bind(&MessageHandlerTest::NewMessageSlot, this,
                                                   args::_1, args::_2, args::_3, args::_4,
                                                   &received, &mutex, &cond_var));
  EXPECT_EQ(kSuccess, message_handler2_->StartCheckingForNewMessages(interval_));

  InboxItem sent(CreateMessage(public_username1_, public_username2_));
  EXPECT_EQ(kSuccess, message_handler1_->Send(sent));


  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }

  EXPECT_TRUE(MessagesEqual(sent, received));

  bptime::ptime sent_time(bptime::from_iso_string(sent.timestamp)),
                received_time(bptime::from_iso_string(sent.timestamp));
  EXPECT_FALSE(sent_time.is_not_a_date_time() || sent_time.is_special());
  EXPECT_FALSE(received_time.is_not_a_date_time() || received_time.is_special());
  EXPECT_EQ(sent_time.time_of_day(), received_time.time_of_day());
  EXPECT_EQ(sent_time.date(), received_time.date());
  EXPECT_EQ(sent_time.zone_abbrev(), received_time.zone_abbrev());
  EXPECT_EQ(sent_time.zone_as_posix_string(), received_time.zone_as_posix_string());
  EXPECT_EQ(sent_time.zone_name(), received_time.zone_name());
}

TEST_F(MessageHandlerTest, FUNC_ReceiveMultipleMessages) {
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_username2_, true));

  // Connect a slot which will reject the new contact
//  volatile bool done(false);
  boost::mutex mutex;
  boost::condition_variable cond_var;
  public_id1_->ConnectToNewContactSignal(std::bind(&MessageHandlerTest::NewContactSlot,
                                                   this, args::_1, args::_2, &mutex, &cond_var));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSuccess, public_id2_->SendContactInfo(public_username2_, public_username1_));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }

  ASSERT_EQ(public_username2_, received_public_username_);
  Contact received_contact;
  ASSERT_EQ(kSuccess,
            session1_.contact_handler_map()[public_username1_]->ContactInfo(
                received_public_username_,
                &received_contact));

  InboxItem sent(CreateMessage(public_username1_, public_username2_));
  for (size_t n(0); n < multiple_messages_; ++n) {
    sent.timestamp = crypto::Hash<crypto::SHA512>(boost::lexical_cast<std::string>(n));
    ASSERT_EQ(kSuccess, message_handler1_->Send(sent));
  }

  std::vector<InboxItem> received_messages;
//  volatile bool finished(false);
  bs2::connection connection(message_handler2_->ConnectToChatSignal(
                                 std::bind(&MessageHandlerTest::SeveralMessagesSlot, this, args::_1,
                                           args::_2, args::_3, args::_4, &received_messages, &mutex,
                                           &cond_var, &multiple_messages_)));
  ASSERT_EQ(kSuccess, message_handler2_->StartCheckingForNewMessages(interval_));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }

  connection.disconnect();
  message_handler2_->StopCheckingForNewMessages();
  ASSERT_EQ(multiple_messages_, received_messages.size());
  for (size_t a(0); a < multiple_messages_; ++a) {
    sent.timestamp = crypto::Hash<crypto::SHA512>(boost::lexical_cast<std::string>(a));
    ASSERT_TRUE(MessagesEqual(sent, received_messages[a]));
  }

  multiple_messages_ = 1;
  for (size_t a(0); a < multiple_messages_ * 5; ++a) {
    sent.timestamp = crypto::Hash<crypto::SHA512>(boost::lexical_cast<std::string>("n"));
    ASSERT_EQ(kSuccess, message_handler1_->Send(sent));
    DLOG(ERROR) << "Sent " << a;
  }

  // If same message is sent, it should be reported only once
  received_messages.clear();
  connection = message_handler2_->ConnectToChatSignal(
                   std::bind(&MessageHandlerTest::SeveralMessagesSlot, this, args::_1, args::_2,
                             args::_3, args::_4, &received_messages, &mutex, &cond_var,
                             &multiple_messages_));
  ASSERT_EQ(kSuccess, message_handler2_->StartCheckingForNewMessages(interval_));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }

  message_handler2_->StopCheckingForNewMessages();
  ASSERT_EQ(multiple_messages_, received_messages.size());
}

TEST_F(MessageHandlerTest, BEH_RemoveContact) {
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_username2_, true));
  ASSERT_EQ(kSuccess, public_id3_->CreatePublicId(public_username3_, true));

  boost::mutex mutex;
  boost::condition_variable cond_var;
  public_id1_->ConnectToContactConfirmedSignal(std::bind(&MessageHandlerTest::NewContactCountSlot,
                                                         this, args::_1, args::_2, &mutex,
                                                         &cond_var));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  public_id2_->ConnectToNewContactSignal(std::bind(&MessageHandlerTest::NewContactSlot, this,
                                                   args::_1, args::_2, &mutex, &cond_var));
  ASSERT_EQ(kSuccess, public_id2_->StartCheckingForNewContacts(interval_));
  public_id3_->ConnectToNewContactSignal(std::bind(&MessageHandlerTest::NewContactSlot, this,
                                                   args::_1, args::_2, &mutex, &cond_var));
  ASSERT_EQ(kSuccess, public_id3_->StartCheckingForNewContacts(interval_));

  ASSERT_EQ(kSuccess, public_id1_->SendContactInfo(public_username1_, public_username2_));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }
  ASSERT_EQ(kSuccess, public_id1_->SendContactInfo(public_username1_, public_username3_));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }

  ASSERT_EQ(kSuccess, public_id2_->ConfirmContact(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess, public_id3_->ConfirmContact(public_username3_, public_username1_));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }

  InboxItem received;
  message_handler1_->ConnectToChatSignal(std::bind(&MessageHandlerTest::NewMessageSlot, this,
                                                   args::_1, args::_2, args::_3, args::_4,
                                                   &received, &mutex, &cond_var));
  ASSERT_EQ(kSuccess, message_handler1_->StartCheckingForNewMessages(interval_));

  InboxItem sent(CreateMessage(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess, message_handler2_->Send(sent));

  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }
  ASSERT_TRUE(MessagesEqual(sent, received));

  public_id1_->RemoveContact(public_username1_, public_username2_);
  Sleep(interval_ * 2);

  received = InboxItem();
  ASSERT_NE(kSuccess, message_handler2_->Send(sent));
  ASSERT_FALSE(MessagesEqual(sent, received));

  sent.sender_public_id = public_username3_;
  ASSERT_EQ(kSuccess, message_handler3_->Send(sent));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }
  ASSERT_TRUE(MessagesEqual(sent, received));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
