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
#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#include "maidsafe/pd/client/node.h"

#include "maidsafe/lifestuff/lifestuff.h"
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
        asio_service1_(10),
        asio_service2_(10),
        asio_service3_(10),
        remote_chunk_store1_(),
        remote_chunk_store2_(),
        remote_chunk_store3_(),
        public_id1_(),
        public_id2_(),
        public_id3_(),
        message_handler1_(),
        message_handler2_(),
        message_handler3_(),
        public_username1_("User 1 " + RandomAlphaNumericString(8)),
        public_username2_("User 2 " + RandomAlphaNumericString(8)),
        public_username3_("User 3 " + RandomAlphaNumericString(8)),
        received_public_username_(),
        received_message_(),
        node1_(),
        node2_(),
        node3_(),
        interval_(3),
        multiple_messages_(5),
        invitations_(0) {}

  void NewContactSlot(const std::string&,
                      const std::string& other_public_username,
                      const std::string& message,
                      boost::mutex* mutex,
                      boost::condition_variable* cond_var,
                      bool* done) {
    boost::mutex::scoped_lock lock(*mutex);
    received_public_username_ = other_public_username;
    received_message_ = message;
    *done = true;
    cond_var->notify_one();
  }

  void NewContactCountSlot(const std::string& /*own_public_username*/,
                           const std::string& other_public_username,
                           boost::mutex* mutex,
                           boost::condition_variable* cond_var,
                           bool* done) {
    boost::mutex::scoped_lock lock(*mutex);
    received_public_username_ = other_public_username;
    ++invitations_;
    if (invitations_ == 2U) {
      *done = true;
      cond_var->notify_one();
    }
  }

  void NewMessageSlot(const std::string& own_public_username,
                      const std::string& other_public_username,
                      const std::string& message,
                      const std::string& timestamp,
                      InboxItem* slot_message,
                      boost::mutex* mutex,
                      boost::condition_variable* cond_var,
                      bool* done) {
    boost::mutex::scoped_lock lock(*mutex);
    slot_message->receiver_public_id = own_public_username;
    slot_message->sender_public_id = other_public_username;
    slot_message->content.push_back(message);
    slot_message->item_type = kChat;
    slot_message->timestamp = timestamp;
    *done = true;
    cond_var->notify_one();
  }

  void SeveralMessagesSlot(const std::string& own_public_username,
                           const std::string& other_public_username,
                           const std::string& message,
                           const std::string& timestamp,
                           std::vector<InboxItem>* messages,
                           boost::mutex* mutex,
                           boost::condition_variable* cond_var,
                           size_t* count,
                           bool* done) {
    boost::mutex::scoped_lock lock(*mutex);
    InboxItem slot_message;
    slot_message.receiver_public_id = own_public_username;
    slot_message.sender_public_id = other_public_username;
    slot_message.content.push_back(message);
    slot_message.item_type = kChat;
    slot_message.timestamp = timestamp;
    messages->push_back(slot_message);
    if (messages->size() == *count) {
      *done = true;
      cond_var->notify_all();
    }
  }

 protected:
  void SetUp() {
    asio_service1_.Start();
    asio_service2_.Start();
    asio_service3_.Start();

    std::vector<std::pair<std::string, uint16_t>> bootstrap_endpoints;
    remote_chunk_store1_ = BuildChunkStore(*test_dir_,
                                           bootstrap_endpoints,
                                           node1_,
                                           NetworkHealthFunction());
    remote_chunk_store2_ = BuildChunkStore(*test_dir_,
                                           bootstrap_endpoints,
                                           node2_,
                                           NetworkHealthFunction());
    remote_chunk_store3_ = BuildChunkStore(*test_dir_,
                                           bootstrap_endpoints,
                                           node3_,
                                           NetworkHealthFunction());

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
    node1_->Stop();
    node2_->Stop();
    node3_->Stop();
    remote_chunk_store1_->WaitForCompletion();
    remote_chunk_store2_->WaitForCompletion();
    remote_chunk_store3_->WaitForCompletion();
  }

  bool MessagesEqual(const InboxItem& left, const InboxItem& right) const {
    if (left.item_type != right.item_type) {
      LOG(kError) << "Different type.";
      return false;
    }
    if (left.content.size() != right.content.size()) {
      LOG(kError) << "Different content size.";
      return false;
    }
    if (left.receiver_public_id != right.receiver_public_id) {
      LOG(kError) << "Different receiver.";
      return false;
    }
    if (left.sender_public_id != right.sender_public_id) {
      LOG(kError) << "Different sender.";
      return false;
    }
    if (left.timestamp != right.timestamp) {
      LOG(kError) << "Different timestamp -left: " << left.timestamp
                  << ", right: " << right.timestamp;
      return false;
    }

    return true;
  }

  InboxItem CreateMessage(const std::string& sender, const std::string& receiver) {
    InboxItem sent;
    sent.sender_public_id = sender;
    sent.receiver_public_id = receiver;
    sent.content.push_back("content");
    sent.timestamp = IsoTimeWithMicroSeconds();
    return sent;
  }

  std::shared_ptr<fs::path> test_dir_;
  Session session1_, session2_, session3_;
  AsioService asio_service1_, asio_service2_, asio_service3_;
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store1_,
                                         remote_chunk_store2_,
                                         remote_chunk_store3_;
  std::shared_ptr<PublicId> public_id1_, public_id2_, public_id3_;
  std::shared_ptr<MessageHandler> message_handler1_, message_handler2_, message_handler3_;

  std::string public_username1_, public_username2_, public_username3_, received_public_username_,
              received_message_;
  std::shared_ptr<pd::Node> node1_, node2_, node3_;
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

  boost::mutex mutex;
  boost::condition_variable cond_var;
  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& message,
           const std::string& /*timestamp*/) {
        MessageHandlerTest::NewContactSlot(own_public_id,
                                           contact_public_id,
                                           message,
                                           &mutex,
                                           &cond_var,
                                           &done);
      });
  EXPECT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  EXPECT_EQ(kSuccess, public_id2_->AddContact(public_username2_, public_username1_, ""));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }

  EXPECT_EQ(public_username2_, received_public_username_);
  const ContactsHandlerPtr contacts_handler(session1_.contacts_handler(public_username1_));
  ASSERT_NE(nullptr, contacts_handler.get());
  Contact received_contact;
  EXPECT_EQ(kSuccess, contacts_handler->ContactInfo(received_public_username_, &received_contact));

  InboxItem received;
  done = false;
  message_handler2_->ConnectToChatSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& message,
           const std::string& timestamp) {
        MessageHandlerTest::NewMessageSlot(own_public_id,
                                           contact_public_id,
                                           message,
                                           timestamp,
                                           &received,
                                           &mutex,
                                           &cond_var,
                                           &done);
      });
  EXPECT_EQ(kSuccess, message_handler2_->StartCheckingForNewMessages(interval_));

  InboxItem sent(CreateMessage(public_username1_, public_username2_));
  EXPECT_EQ(kSuccess, message_handler1_->Send(sent));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
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

  public_id1_->StopCheckingForNewContacts();
  message_handler2_->StopCheckingForNewMessages();
}

TEST_F(MessageHandlerTest, FUNC_ReceiveMultipleMessages) {
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_username2_, true));

  // Connect a slot which will reject the new contact
  boost::mutex mutex;
  boost::condition_variable cond_var;
  bool done(false);
  public_id1_->ConnectToNewContactSignal(
        [&] (const std::string& own_public_id,
             const std::string& contact_public_id,
             const std::string& message,
             const std::string& /*timestamp*/) {
          MessageHandlerTest::NewContactSlot(own_public_id,
                                             contact_public_id,
                                             message,
                                             &mutex,
                                             &cond_var,
                                             &done);
        });
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_username2_, public_username1_, ""));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }

  ASSERT_EQ(public_username2_, received_public_username_);
  const ContactsHandlerPtr contacts_handler(session1_.contacts_handler(public_username1_));
  ASSERT_NE(nullptr, contacts_handler.get());
  Contact received_contact;
  ASSERT_EQ(kSuccess, contacts_handler->ContactInfo(received_public_username_, &received_contact));

  InboxItem sent(CreateMessage(public_username1_, public_username2_));
  for (size_t n(0); n < multiple_messages_; ++n) {
    sent.timestamp = crypto::Hash<crypto::SHA512>(boost::lexical_cast<std::string>(n));
    ASSERT_EQ(kSuccess, message_handler1_->Send(sent));
  }

  std::vector<InboxItem> received_messages;
  done = false;
  bs2::connection connection(
      message_handler2_->ConnectToChatSignal(
          [&] (const std::string& own_public_id,
               const std::string& contact_public_id,
               const std::string& message,
               const std::string& timestamp) {
            MessageHandlerTest::SeveralMessagesSlot(own_public_id,
                                                    contact_public_id,
                                                    message,
                                                    timestamp,
                                                    &received_messages,
                                                    &mutex,
                                                    &cond_var,
                                                    &multiple_messages_,
                                                    &done);
          }));
  ASSERT_EQ(kSuccess, message_handler2_->StartCheckingForNewMessages(interval_));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
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
    LOG(kError) << "Sent " << a;
  }

  // If same message is sent, it should be reported only once
  received_messages.clear();
  done = false;
  connection = message_handler2_->ConnectToChatSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& message,
           const std::string& timestamp) {
        MessageHandlerTest::SeveralMessagesSlot(own_public_id,
                                                contact_public_id,
                                                message,
                                                timestamp,
                                                &received_messages,
                                                &mutex,
                                                &cond_var,
                                                &multiple_messages_,
                                                &done);
      });
  ASSERT_EQ(kSuccess, message_handler2_->StartCheckingForNewMessages(interval_));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }

  connection.disconnect();
  message_handler2_->StopCheckingForNewMessages();
  ASSERT_EQ(multiple_messages_, received_messages.size());
  public_id1_->StopCheckingForNewContacts();
}

TEST_F(MessageHandlerTest, BEH_RemoveContact) {
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_username1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_username2_, true));
  ASSERT_EQ(kSuccess, public_id3_->CreatePublicId(public_username3_, true));

  boost::mutex mutex;
  boost::condition_variable cond_var;
  bool done(false), done2(false), done3(false);
  public_id1_->ConnectToContactConfirmedSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& /*timestamp*/) {
        MessageHandlerTest::NewContactCountSlot(own_public_id,
                                                contact_public_id,
                                                &mutex,
                                                &cond_var,
                                                &done);
      });
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  public_id2_->ConnectToNewContactSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& message,
           const std::string& /*timestamp*/) {
        MessageHandlerTest::NewContactSlot(own_public_id,
                                           contact_public_id,
                                           message,
                                           &mutex,
                                           &cond_var,
                                           &done2);
      });
  ASSERT_EQ(kSuccess, public_id2_->StartCheckingForNewContacts(interval_));
  public_id3_->ConnectToNewContactSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& message,
           const std::string& /*timestamp*/) {
        MessageHandlerTest::NewContactSlot(own_public_id,
                                           contact_public_id,
                                           message,
                                           &mutex,
                                           &cond_var,
                                           &done3);
      });
  ASSERT_EQ(kSuccess, public_id3_->StartCheckingForNewContacts(interval_));

  ASSERT_EQ(kSuccess, public_id1_->AddContact(public_username1_, public_username2_, ""));
  ASSERT_EQ(kSuccess, public_id1_->AddContact(public_username1_, public_username3_, ""));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done2 && done3; }));  // NOLINT (Dan)
  }

  ASSERT_EQ(kSuccess, public_id2_->ConfirmContact(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess, public_id3_->ConfirmContact(public_username3_, public_username1_));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }

  InboxItem received;
  done = false;
  message_handler1_->ConnectToChatSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& message,
           const std::string& timestamp) {
        MessageHandlerTest::NewMessageSlot(own_public_id,
                                           contact_public_id,
                                           message,
                                           timestamp,
                                           &received,
                                           &mutex,
                                           &cond_var,
                                           &done);
      });
  ASSERT_EQ(kSuccess, message_handler1_->StartCheckingForNewMessages(interval_));

  InboxItem sent(CreateMessage(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess, message_handler2_->Send(sent));

  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_TRUE(MessagesEqual(sent, received));

  public_id1_->RemoveContact(public_username1_, public_username2_, "", "", true);
  Sleep(interval_ * 2);

  received = InboxItem();
  ASSERT_NE(kSuccess, message_handler2_->Send(sent));
  ASSERT_FALSE(MessagesEqual(sent, received));

  done = false;
  sent.sender_public_id = public_username3_;
  ASSERT_EQ(kSuccess, message_handler3_->Send(sent));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_TRUE(MessagesEqual(sent, received));
  message_handler1_->StopCheckingForNewMessages();
  public_id3_->StopCheckingForNewContacts();
  public_id2_->StopCheckingForNewContacts();
  public_id1_->StopCheckingForNewContacts();
}

void NotificationFunction(const std::string&,
                          const std::string&,
                          boost::mutex& mutex,
                          boost::condition_variable& condition_variable,
                          bool& done) {
    boost::mutex::scoped_lock lock(mutex);
    done = true;
    condition_variable.notify_one();
}

int ConnectTwoPublicIds(PublicId& public_id1,
                        PublicId& public_id2,
                        const std::string& id1,
                        const std::string& id2,
                        const bptime::seconds interval) {
  int result(public_id1.CreatePublicId(id1, true));
  if (result != kSuccess)
    return -1;
  result = public_id2.CreatePublicId(id2, true);
  if (result != kSuccess)
    return -2;

  result = public_id2.AddContact(id2, id1, "");


  boost::mutex mutex;
  boost::condition_variable cond_var;
  bool done(false);
  public_id1.ConnectToNewContactSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& /*message*/,
           const std::string& /*timestamp*/) {
        NotificationFunction(own_public_id,
                             contact_public_id,
                             std::ref(mutex),
                             std::ref(cond_var),
                             std::ref(done));
      });
  result = public_id1.StartCheckingForNewContacts(interval);
  if (result != kSuccess)
    return -3;
  {
    boost::mutex::scoped_lock lock(mutex);
    if (!cond_var.timed_wait(lock, interval * 2, [&done] ()->bool { return done; }))  // NOLINT (Dan)
      return -41;
  }
  if (!done)
    return -42;
  public_id1.StopCheckingForNewContacts();
  if (result != kSuccess)
    return -5;

  result = public_id1.ConfirmContact(id1, id2);
  if (result != kSuccess)
    return -6;

  done = false;
  public_id2.ConnectToContactConfirmedSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& /*timestamp*/) {
        NotificationFunction(own_public_id,
                             contact_public_id,
                             std::ref(mutex),
                             std::ref(cond_var),
                             std::ref(done));
      });
  result = public_id2.StartCheckingForNewContacts(interval);
  if (result != kSuccess)
    return -7;
  {
    boost::mutex::scoped_lock lock(mutex);
    if (!cond_var.timed_wait(lock, interval * 2, [&done] ()->bool { return done; }))  // NOLINT (Dan)
      return -81;
  }
  if (!done)
    return -82;

  public_id2.StopCheckingForNewContacts();

  return kSuccess;
}

TEST_F(MessageHandlerTest, FUNC_DeletePublicIdUserPerception) {
  ASSERT_EQ(kSuccess, ConnectTwoPublicIds(*public_id1_,
                                          *public_id2_,
                                          public_username1_,
                                          public_username2_,
                                          interval_));

  InboxItem received;
  boost::mutex mutex;
  boost::condition_variable cond_var;
  bool done(false);
  message_handler1_->ConnectToChatSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& message,
           const std::string& timestamp) {
        MessageHandlerTest::NewMessageSlot(own_public_id,
                                           contact_public_id,
                                           message,
                                           timestamp,
                                           &received,
                                           &mutex,
                                           &cond_var,
                                           &done);
      });
  ASSERT_EQ(kSuccess, message_handler1_->StartCheckingForNewMessages(interval_));

  InboxItem sent(CreateMessage(public_username2_, public_username1_));
  ASSERT_EQ(kSuccess, message_handler2_->Send(sent));
  {
    boost::mutex::scoped_lock lock(mutex);
    ASSERT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }

  ASSERT_TRUE(MessagesEqual(sent, received));
  message_handler1_->StopCheckingForNewMessages();

  ASSERT_EQ(kSuccess, public_id1_->DeletePublicId(public_username1_));
  ASSERT_NE(kSuccess, message_handler2_->Send(sent));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
