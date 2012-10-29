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

#include "maidsafe/lifestuff/detail/public_id.h"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_id.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"
#include "maidsafe/private/utils/utilities.h"

#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

namespace test {

namespace {

const NonEmptyString kInvite("Be my friend?");

NonEmptyString GenerateNonemptyMessage() {
  return NonEmptyString(RandomAlphaNumericString(15));
}

void ExchangeSlot(std::mutex* mutex,
                  std::condition_variable* cond_var,
                  bool* done) {
  std::unique_lock<std::mutex> loch(*mutex);
  *done = true;
  cond_var->notify_one();
}

void LifestuffCardSlot(std::mutex* mutex,
                       std::condition_variable* cond_var,
                       bool* done) {
  std::unique_lock<std::mutex> loch(*mutex);
  *done = true;
  cond_var->notify_one();
}

int CreateAndConnectTwoIds(PublicId& public_id1,
                           const NonEmptyString& public_identity1,
                           Session& session1,
                           PublicId& public_id2,
                           const NonEmptyString& public_identity2,
                           Session& session2) {
  int result(public_id1.CreatePublicId(public_identity1, true));
  if (result != kSuccess)
    return result;
  result = public_id2.CreatePublicId(public_identity2, true);
  if (result != kSuccess)
    return result;

  std::mutex mutex, mutex2;
  std::condition_variable cond_var, cond_var2;
  bool done(false), done2(false);
  std::chrono::seconds interval(3);
  bptime::seconds timer_interval(3);
  public_id1.ConnectToNewContactSignal(
      [&] (const NonEmptyString& /*own_public_id*/,
           const NonEmptyString& /*contact_public_id*/,
           const NonEmptyString& /*message*/,
           const NonEmptyString& /*timestamp*/) {
        ExchangeSlot(&mutex, &cond_var, &done);
      });

  public_id2.ConnectToContactConfirmedSignal(
      [&] (const NonEmptyString& /*own_public_id*/,
           const NonEmptyString& /*contact_public_id*/,
           const NonEmptyString& /*timestamp*/) {
        ExchangeSlot(&mutex2, &cond_var2, &done2);
      });

  result = public_id2.AddContact(public_identity2, public_identity1, kInvite);
  if (result != kSuccess)
    return result;
  result = public_id1.StartCheckingForNewContacts(timer_interval);
  if (result != kSuccess)
    return result;

  {
    std::unique_lock<std::mutex> loch(mutex);
    if (!cond_var.wait_for(loch, interval * 2, [&] ()->bool { return done; }))  // NOLINT (Dan)
      return -1;
  }

  result = public_id1.ConfirmContact(public_identity1, public_identity2);
  if (result != kSuccess)
    return result;
  result = public_id2.StartCheckingForNewContacts(timer_interval);
  if (result != kSuccess)
    return result;

  {
    std::unique_lock<std::mutex> loch(mutex2);
    if (!cond_var2.wait_for(loch, interval * 2, [&] ()->bool { return done2; }))  // NOLINT (Dan)
      return -1;
  }

  session1.contacts_handler(public_identity1)->UpdatePresence(public_identity2, kOnline);
  session2.contacts_handler(public_identity2)->UpdatePresence(public_identity1, kOnline);

  return kSuccess;
}

SocialInfoMap CreateRandomSocialInfoMap(const size_t& size) {
  SocialInfoMap sim;
  while (sim.size() < size)
    sim[NonEmptyString(RandomAlphaNumericString(8))] = RandomAlphaNumericString(10);
  return sim;
}

void ChangeMapValues(SocialInfoMap& social_info_map) {
  std::for_each(social_info_map.begin(),
                social_info_map.end(),
                [&] (const SocialInfoMap::value_type& element) {
                  social_info_map[element.first] = RandomAlphaNumericString(20);
                });
}

bool EqualMaps(const SocialInfoMap& lhs, const SocialInfoMap& rhs) {
  return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

}  // namespace

class PublicIdTest : public testing::Test {
 public:
  PublicIdTest()
      : test_dir_(maidsafe::test::CreateTestPath()),
        session1_(),
        session2_(),
        asio_service1_(5),
        asio_service2_(5),
        remote_chunk_store1_(),
        remote_chunk_store2_(),
        public_id1_(),
        public_id2_(),
        public_identity1_("User 1 " + RandomAlphaNumericString(8)),
        public_identity2_("User 2 " + RandomAlphaNumericString(8)),
        received_public_identity_(),
        received_message_(),
        timer_interval_(3),
        interval_(3) {}

  void NewContactSlot(const NonEmptyString&,
                      const NonEmptyString& contact_public_id,
                      const NonEmptyString& message,
                      std::mutex* mutex,
                      std::condition_variable* cond_var,
                      bool* done) {
    std::unique_lock<std::mutex> lock(*mutex);
    received_public_identity_ = contact_public_id;
    received_message_ = message;
    *done = true;
    cond_var->notify_one();
  }

  void NewContactCounterSlot(const NonEmptyString&,
                             const NonEmptyString& contact_public_id,
                             const int& times,
                             int* counter,
                             std::mutex* mutex,
                             std::condition_variable* cond_var,
                             bool* done) {
    std::unique_lock<std::mutex> lock(*mutex);
    received_public_identity_ = contact_public_id;
    ++(*counter);
    if (*counter == times) {
      *done = true;
      cond_var->notify_one();
    }
  }

  void ContactRequestSlot(const NonEmptyString&,
                          const NonEmptyString& contact_public_id,
                          const NonEmptyString& message,
                          std::mutex* mutex,
                          std::condition_variable* cond_var,
                          bool* done) {
    std::unique_lock<std::mutex> lock(*mutex);
    received_public_identity_ = contact_public_id;
    received_message_ = message;
    *done = true;
    cond_var->notify_one();
  }

  void ContactConfirmedSlot(const NonEmptyString&,
                            const NonEmptyString& signal_public_id,
                            NonEmptyString* slot_public_id,
                            std::mutex* mutex,
                            std::condition_variable* cond_var,
                            bool* done) {
    std::unique_lock<std::mutex> lock(*mutex);
    *slot_public_id  = signal_public_id;
    *done = true;
    cond_var->notify_one();
  }


  void ContactDeletionReceivedSlot(const NonEmptyString&,
                                   const NonEmptyString& contact_public_id,
                                   const NonEmptyString& message,
                                   std::mutex* mutex,
                                   std::condition_variable* cond_var,
                                   bool* done) {
    std::unique_lock<std::mutex> lock(*mutex);
    received_public_identity_ = contact_public_id;
    received_message_ = message;
    *done = true;
    cond_var->notify_one();
  }

  void ContactDeletionProcessedSlot(const NonEmptyString&,
                                    const NonEmptyString& contact_public_id,
                                    const NonEmptyString& message,
                                    std::mutex* mutex,
                                    std::condition_variable* cond_var,
                                    bool* done) {
    std::unique_lock<std::mutex> lock(*mutex);
    received_public_identity_ = contact_public_id;
    received_message_ = message;
    *done = true;
    cond_var->notify_one();
  }

 protected:
  void SetUp() {
    asio_service1_.Start();
    asio_service2_.Start();

    std::string dir1(RandomAlphaNumericString(8));
    remote_chunk_store1_ = priv::chunk_store::CreateLocalChunkStore(*test_dir_ / dir1 / "buffer",
                                                                    *test_dir_ / "simulation",
                                                                    *test_dir_ / dir1 / "lock",
                                                                    asio_service1_.service());
    std::string dir2(RandomAlphaNumericString(8));
    remote_chunk_store2_ = priv::chunk_store::CreateLocalChunkStore(*test_dir_ / dir2 / "buffer",
                                                                    *test_dir_ / "simulation",
                                                                    *test_dir_ / dir2 / "lock",
                                                                    asio_service2_.service());

    public_id1_ = std::make_shared<PublicId>(*remote_chunk_store1_,
                                             session1_,
                                             asio_service1_.service());

    public_id2_ = std::make_shared<PublicId>(*remote_chunk_store2_,
                                             session2_,
                                             asio_service2_.service());
  }

  void TearDown() {
    public_id1_->StopCheckingForNewContacts();
    public_id2_->StopCheckingForNewContacts();
    asio_service1_.Stop();
    asio_service2_.Stop();
    remote_chunk_store1_->WaitForCompletion();
    remote_chunk_store2_->WaitForCompletion();
  }

  void CreateTestSignaturePackets(Session& session) {
    session.passport().CreateSigningPackets();
    ASSERT_EQ(kSuccess, session.passport().ConfirmSigningPackets());
  }

  int InformContactInfo(std::shared_ptr<PublicId> public_id,
                        const NonEmptyString& own_public_id,
                        const std::vector<Contact>& contacts,
                        const NonEmptyString& message,
                        const IntroductionType& type,
                        const std::string& inbox_name = "") {
    return public_id->InformContactInfo(own_public_id, contacts, message, type, inbox_name);
  }

  void StoreNewInbox(Identity& inbox_name) {
    std::mutex mutex;
    std::condition_variable cond_var;
    Fob new_inbox_keys(priv::utils::GenerateFob(nullptr));
    NonEmptyString new_inbox_value(AppendableIdValue(new_inbox_keys, true));
    priv::ChunkId new_inbox_name(AppendableByAllName(new_inbox_keys.identity));
    Fob shared_keys(new_inbox_keys);

    int result(priv::utils::kPendingResult);
    std::function<void(bool)> callback = [&] (const bool& response) {  // NOLINT (Dan)
                                           priv::utils::ChunkStoreOperationCallback(response,
                                                                                    &mutex,
                                                                                    &cond_var,
                                                                                    &result);
                                         };
    ASSERT_TRUE(remote_chunk_store2_->Store(new_inbox_name,
                                            new_inbox_value,
                                            callback,
                                            shared_keys));
    {
      std::unique_lock<std::mutex> lock(mutex);
      ASSERT_TRUE(cond_var.wait_for(lock,
                                    std::chrono::seconds(60),
                                    [&result] ()->bool {
                                      return result != priv::utils::kPendingResult;
                                    }));  // NOLINT (Dan)
    }
    ASSERT_EQ(kSuccess, result);
    inbox_name = new_inbox_keys.identity;
  }

  std::shared_ptr<fs::path> test_dir_;
  Session session1_, session2_;
  AsioService asio_service1_, asio_service2_;
  std::shared_ptr<priv::chunk_store::RemoteChunkStore> remote_chunk_store1_, remote_chunk_store2_;
  std::shared_ptr<PublicId> public_id1_, public_id2_;

  NonEmptyString public_identity1_, public_identity2_, received_public_identity_, received_message_;
  bptime::seconds timer_interval_;
  std::chrono::seconds interval_;

 private:
  explicit PublicIdTest(const PublicIdTest&);
  PublicIdTest &operator=(const PublicIdTest&);
};

TEST_F(PublicIdTest, FUNC_CreateInvalidId) {
  ASSERT_EQ(kStartContactsNoPublicIds, public_id1_->StartCheckingForNewContacts(timer_interval_));

  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, false));

  ASSERT_EQ(kStorePublicIdFailure, public_id1_->CreatePublicId(public_identity1_, false));

  ASSERT_EQ(kStorePublicIdFailure, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kStorePublicIdFailure, public_id2_->CreatePublicId(public_identity1_, false));
  ASSERT_EQ(kStorePublicIdFailure, public_id2_->CreatePublicId(public_identity1_, true));
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdAntiSocial) {
  // Create user1 who doesn't accept new contacts, and user2 who does
  std::mutex mutex;
  std::condition_variable cond_var;
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, false));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& message,
           const NonEmptyString& /*timestamp*/) {
        NewContactSlot(own_public_id, contact_public_id, message, &mutex, &cond_var, &done);
      });
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(timer_interval_));

  NonEmptyString message(GenerateNonemptyMessage());

  ASSERT_NE(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, message));

  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_FALSE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_THROW(received_public_identity_.string(), std::exception);
  ASSERT_THROW(received_message_.string(), std::exception);
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdSociable) {
  std::mutex mutex;
  std::condition_variable cond_var;
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& message,
           const NonEmptyString& /*timestamp*/) {
        NewContactSlot(own_public_id, contact_public_id, message, &mutex, &cond_var, &done);
      });

  NonEmptyString message(GenerateNonemptyMessage());
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, message));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(timer_interval_));

  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }

  ASSERT_EQ(public_identity2_, received_public_identity_);
  ASSERT_EQ(message, received_message_);

  const ContactsHandlerPtr contacts_handler1(session1_.contacts_handler(public_identity1_));
  ASSERT_NE(nullptr, contacts_handler1.get());
  Contact received_contact;
  ASSERT_EQ(kSuccess, contacts_handler1->ContactInfo(received_public_identity_, &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);

  received_contact = Contact();
  done = false;
  NonEmptyString public_id3(public_identity2_.string() + "1");
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_id3, true));
  message = GenerateNonemptyMessage();
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_id3, public_identity1_, message));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_EQ(public_id3, received_public_identity_);
  ASSERT_EQ(message, received_message_);
  ASSERT_EQ(kSuccess, contacts_handler1->ContactInfo(received_public_identity_, &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdWithReply) {
  std::mutex mutex, mutex2;
  std::condition_variable cond_var, cond_var2;
  bool done(false), done2(false);
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));
  Identity card1(session1_.social_info(public_identity1_).second->card_address),
           card2(session2_.social_info(public_identity2_).second->card_address);

  // Connect a slot which will reject the new contact
  public_id1_->ConnectToNewContactSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& message,
           const NonEmptyString& /*timestamp*/) {
        ContactRequestSlot(own_public_id, contact_public_id, message, &mutex, &cond_var, &done);
      });

  NonEmptyString confirmed_contact;
  public_id2_->ConnectToContactConfirmedSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& /*timestamp*/) {
        ContactConfirmedSlot(own_public_id, contact_public_id, &confirmed_contact, &mutex2,
                             &cond_var2, &done2);
      });

  // Send the message and start checking for messages
  NonEmptyString message(GenerateNonemptyMessage());
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, message));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(timer_interval_));

  const ContactsHandlerPtr contacts_handler2(session2_.contacts_handler(public_identity2_));
  ASSERT_NE(nullptr, contacts_handler2.get());
  Contact received_contact;
  ASSERT_EQ(kSuccess, contacts_handler2->ContactInfo(public_identity1_, &received_contact));
  ASSERT_EQ(kRequestSent, received_contact.status);

  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }

  // Other side got message. Check status of contact and reply affirmatively.
  ASSERT_EQ(public_identity2_, received_public_identity_);
  ASSERT_EQ(message, received_message_);
  received_contact = Contact();
  const ContactsHandlerPtr contacts_handler1(session1_.contacts_handler(public_identity1_));
  ASSERT_NE(nullptr, contacts_handler1.get());
  ASSERT_EQ(kSuccess, contacts_handler1->ContactInfo(public_identity2_, &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);
  ASSERT_EQ(kSuccess, public_id1_->ConfirmContact(public_identity1_, public_identity2_));
  ASSERT_EQ(kSuccess, public_id2_->StartCheckingForNewContacts(timer_interval_));

  // Contact should now be confirmed after reply
  received_contact = Contact();
  ASSERT_EQ(kSuccess, contacts_handler1->ContactInfo(public_identity2_, &received_contact));
  ASSERT_EQ(kConfirmed, received_contact.status);

  {
    std::unique_lock<std::mutex> lock(mutex2);
    ASSERT_TRUE(cond_var2.wait_for(lock, interval_ * 2, [&] ()->bool { return done2; }));  // NOLINT (Dan)
  }

  // Confirmation received, status should be updated
  ASSERT_EQ(public_identity1_, confirmed_contact);
  received_contact = Contact();
  ASSERT_EQ(kSuccess, contacts_handler2->ContactInfo(public_identity1_, &received_contact));
  ASSERT_EQ(kConfirmed, received_contact.status);
  ASSERT_NO_THROW(received_contact.inbox_name.string());

  // Check LS cards
  ASSERT_EQ(card1, received_contact.pointer_to_info);
  ASSERT_EQ(kSuccess, contacts_handler1->ContactInfo(public_identity2_, &received_contact));
  ASSERT_EQ(card2, received_contact.pointer_to_info);
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdWithRefusal) {
  std::mutex mutex;
  std::condition_variable cond_var;
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  // Connect a slot which will reject the new contact
  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& message,
           const NonEmptyString& /*timestamp*/) {
        ContactRequestSlot(own_public_id, contact_public_id, message, &mutex, &cond_var, &done);
       });

  // Send the message and start checking for messages
  NonEmptyString message(GenerateNonemptyMessage());
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, message));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(timer_interval_));
  const ContactsHandlerPtr contacts_handler2(session2_.contacts_handler(public_identity2_));
  ASSERT_NE(nullptr, contacts_handler2.get());
  Contact received_contact;
  ASSERT_EQ(kSuccess, contacts_handler2->ContactInfo(public_identity1_, &received_contact));
  ASSERT_EQ(kRequestSent, received_contact.status);

  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }

  // Other side got message. Check status of contact and reply affirmatively.
  ASSERT_EQ(public_identity2_, received_public_identity_);
  ASSERT_EQ(message, received_message_);
  received_contact = Contact();
  const ContactsHandlerPtr contacts_handler1(session1_.contacts_handler(public_identity1_));
  ASSERT_NE(nullptr, contacts_handler1.get());
  ASSERT_EQ(kSuccess, contacts_handler1->ContactInfo(public_identity2_, &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);

  ASSERT_EQ(kSuccess, public_id1_->RejectContact(public_identity1_, public_identity2_));
  received_contact = Contact();
  ASSERT_NE(kSuccess, contacts_handler1->ContactInfo(public_identity2_, &received_contact));
}

TEST_F(PublicIdTest, FUNC_AddContactsIncorrectly) {
  std::mutex mutex;
  std::condition_variable cond_var;

  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));
  NonEmptyString public_identity3("Name 3");
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity3, true));

  // incorrect additions
  NonEmptyString wrong_name("Name 42");
  ASSERT_NE(kSuccess, public_id1_->AddContact(wrong_name, wrong_name, kInvite));
  ASSERT_NE(kSuccess, public_id1_->AddContact(public_identity1_, wrong_name, kInvite));
  ASSERT_EQ(kCannotAddOwnPublicId,
            public_id1_->AddContact(public_identity1_, public_identity1_, kInvite));
  ASSERT_EQ(kCannotAddOwnPublicId,
            public_id1_->AddContact(public_identity1_, public_identity3, kInvite));


  // 2 adds 1 (correct)
  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& message,
           const NonEmptyString& /*timestamp*/) {
          NewContactSlot(own_public_id, contact_public_id, message, &mutex, &cond_var, &done);
      });
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(timer_interval_));
  ASSERT_EQ(kSuccess, public_id2_->StartCheckingForNewContacts(timer_interval_));
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, kInvite));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Alison)
  }
  ASSERT_NO_THROW(received_public_identity_.string());

  // 2 adds 1 again (incorrect)
  ASSERT_EQ(kContactInsertionFailure,
            public_id2_->AddContact(public_identity2_, public_identity1_, kInvite));

  // 2 confirms 1
  done = false;
  NonEmptyString confirmed_contact;
  public_id2_->ConnectToContactConfirmedSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& /*timestamp*/) {
        ContactConfirmedSlot(own_public_id, contact_public_id, &confirmed_contact, &mutex,
                             &cond_var, &done);
      });
  ASSERT_EQ(kSuccess, public_id1_->ConfirmContact(public_identity1_, public_identity2_));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Alison)
  }

  // 2 adds 1 again (incorrect)
  ASSERT_EQ(kContactInsertionFailure,
            public_id2_->AddContact(public_identity2_, public_identity1_, kInvite));
}

TEST_F(PublicIdTest, FUNC_ConfirmContactsIncorrectly) {
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));

  ASSERT_EQ(kPublicIdNotFoundFailure, public_id1_->ConfirmContact(public_identity2_,
                                                                  public_identity2_));
  ASSERT_EQ(kConfirmContactGetInfoFailure,
            public_id1_->ConfirmContact(public_identity1_, public_identity2_));
}

TEST_F(PublicIdTest, FUNC_RejectContactsIncorrectly) {
  std::mutex mutex;
  std::condition_variable cond_var;

  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  // Invalid rejections
  NonEmptyString wrong_name("Name 42");
  ASSERT_EQ(kPublicIdNotFoundFailure, public_id1_->RejectContact(wrong_name, wrong_name));
  ASSERT_NE(kSuccess, public_id1_->RejectContact(public_identity1_, wrong_name));
  ASSERT_NE(kSuccess, public_id1_->RejectContact(public_identity1_, public_identity2_));


  // 2 adds 1
  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& message,
           const NonEmptyString& /*timestamp*/) {
          NewContactSlot(own_public_id, contact_public_id, message, &mutex, &cond_var, &done);
      });
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(timer_interval_));
  ASSERT_EQ(kSuccess, public_id2_->StartCheckingForNewContacts(timer_interval_));
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, kInvite));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Alison)
  }
  ASSERT_NO_THROW(received_public_identity_.string());

  // Invalid rejection
  ASSERT_NE(kSuccess, public_id2_->RejectContact(public_identity2_, public_identity1_));

  // 2 confirms 1
  done = false;
  NonEmptyString confirmed_contact;
  public_id2_->ConnectToContactConfirmedSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& /*timestamp*/) {
        ContactConfirmedSlot(own_public_id, contact_public_id, &confirmed_contact, &mutex,
                             &cond_var, &done);
      });
  ASSERT_EQ(kSuccess, public_id1_->ConfirmContact(public_identity1_, public_identity2_));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Alison)
  }

  // Invalid rejection
  ASSERT_NE(kSuccess, public_id1_->RejectContact(public_identity1_, public_identity2_));
}

TEST_F(PublicIdTest, FUNC_RejectThenAddContact)  {
  std::mutex mutex;
  std::condition_variable cond_var;

  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  // Connect slot for 1 getting contact requests
  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& message,
           const NonEmptyString& /*timestamp*/) {
        ContactRequestSlot(own_public_id, contact_public_id, message, &mutex, &cond_var, &done);
       });

  // 2 adds 1 and checks own state
  NonEmptyString message(GenerateNonemptyMessage());
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, message));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(timer_interval_));
  const ContactsHandlerPtr contacts_handler2(session2_.contacts_handler(public_identity2_));
  ASSERT_NE(nullptr, contacts_handler2.get());
  Contact received_contact;
  ASSERT_EQ(kSuccess, contacts_handler2->ContactInfo(public_identity1_, &received_contact));
  ASSERT_EQ(kRequestSent, received_contact.status);

  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Alison)
  }

  // 1 gets request, checks state then rejects request
  ASSERT_EQ(public_identity2_, received_public_identity_);
  ASSERT_EQ(message, received_message_);
  received_contact = Contact();
  const ContactsHandlerPtr contacts_handler1(session1_.contacts_handler(public_identity1_));
  ASSERT_NE(nullptr, contacts_handler1.get());
  ASSERT_EQ(kSuccess, contacts_handler1->ContactInfo(public_identity2_, &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);

  ASSERT_EQ(kSuccess, public_id1_->RejectContact(public_identity1_, public_identity2_));
  received_contact = Contact();
  ASSERT_NE(kSuccess, contacts_handler1->ContactInfo(public_identity2_, &received_contact));

  done = false;
  NonEmptyString confirmed_contact;
  // Connect slot for 2 getting contact confirmations
  public_id2_->ConnectToContactConfirmedSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& /*timestamp*/) {
        ContactConfirmedSlot(own_public_id, contact_public_id, &confirmed_contact, &mutex,
                             &cond_var, &done);
      });
  // Connect slot for 1 getting contact confirmations
  public_id1_->ConnectToContactConfirmedSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& /*timestamp*/) {
        ContactConfirmedSlot(own_public_id, contact_public_id, &confirmed_contact, &mutex,
                             &cond_var, &done);
      });

  // 1 adds 2
  message = GenerateNonemptyMessage();
  ASSERT_EQ(kSuccess, public_id1_->AddContact(public_identity1_, public_identity2_, message));
  ASSERT_EQ(kSuccess, public_id2_->StartCheckingForNewContacts(timer_interval_));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Alison)
  }
  done = false;

  // 1 awaits an automatic friend confirmation from 2
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(timer_interval_));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Alison)
  }

  // Check states
  received_contact = Contact();
  ASSERT_EQ(kSuccess, contacts_handler1->ContactInfo(public_identity2_, &received_contact));
  ASSERT_EQ(kConfirmed, received_contact.status);

  received_contact = Contact();
  ASSERT_EQ(kSuccess, contacts_handler2->ContactInfo(public_identity1_, &received_contact));
  ASSERT_EQ(kConfirmed, received_contact.status);
}

TEST_F(PublicIdTest, FUNC_FixAsynchronousConfirmedContact) {
  std::mutex mutex;
  std::condition_variable cond_var;
  bool done(false);
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  const ContactsHandlerPtr contacts_handler(session2_.contacts_handler(public_identity2_));
  Contact contact;
  contact.status = kConfirmed;
  Fob keys_mmid(session1_.passport().SignaturePacketDetails(passport::kMmid,
                                                               true,
                                                               public_identity1_));
  Fob keys_mpid(session1_.passport().SignaturePacketDetails(passport::kMpid,
                                                               true,
                                                               public_identity1_));

  contact.public_id = public_identity1_;
  contact.mpid_public_key = keys_mpid.keys.public_key;
  contact.inbox_name = keys_mmid.identity;

  ASSERT_EQ(kSuccess, contacts_handler->AddContact(contact));

  NonEmptyString confirmed_contact;
  public_id1_->ConnectToContactConfirmedSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& /*timestamp*/) {
        ContactConfirmedSlot(own_public_id, contact_public_id, &confirmed_contact, &mutex,
                             &cond_var, &done);
      });

  ASSERT_EQ(kSuccess, public_id1_->AddContact(public_identity1_, public_identity2_, kInvite));
  ASSERT_EQ(kSuccess, public_id2_->StartCheckingForNewContacts(timer_interval_));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(timer_interval_));

  {
  std::unique_lock<std::mutex> lock(mutex);
  ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 3, [&] ()->bool { return done; }));  // NOLINT (Alison)
  }

  ASSERT_EQ(public_identity2_, confirmed_contact);
  Contact received_contact;
  ASSERT_EQ(kSuccess,
            session1_.contacts_handler(public_identity1_)->ContactInfo(public_identity2_,
                                                                       &received_contact));
  ASSERT_EQ(kConfirmed, received_contact.status);
  ASSERT_NO_THROW(received_contact.inbox_name.string());
}

TEST_F(PublicIdTest, FUNC_DisablePublicId) {
  std::mutex mutex;
  std::condition_variable cond_var;
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));

  ASSERT_THROW(public_id1_->DisablePublicId(NonEmptyString("Rubbish")), std::exception);

  ASSERT_EQ(kSuccess, public_id1_->DisablePublicId(public_identity1_));

  // Check a new user can't take this public username
  ASSERT_EQ(kStorePublicIdFailure, public_id2_->CreatePublicId(public_identity1_, false));
  ASSERT_EQ(kStorePublicIdFailure, public_id2_->CreatePublicId(public_identity1_, true));

  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  // Check user2 can't add itself to user1's MCID
  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& message,
           const NonEmptyString& /*timestamp*/) {
        NewContactSlot(own_public_id, contact_public_id, message, &mutex, &cond_var, &done);
      });
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(timer_interval_));
  NonEmptyString message(GenerateNonemptyMessage());
  ASSERT_EQ(kSendContactInfoFailure,
            public_id2_->AddContact(public_identity2_, public_identity1_, message));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_FALSE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_THROW(received_public_identity_.string(), std::exception);
  ASSERT_THROW(received_message_.string(), std::exception);
}

TEST_F(PublicIdTest, FUNC_EnablePublicId) {
  std::mutex mutex;
  std::condition_variable cond_var;
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  ASSERT_THROW(public_id1_->EnablePublicId(NonEmptyString("Rubbish")), std::exception);

  ASSERT_EQ(kSuccess, public_id1_->DisablePublicId(public_identity1_));

  // Check user2 can't add itself to user1's MCID
  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& message,
           const NonEmptyString& /*timestamp*/) {
        NewContactSlot(own_public_id, contact_public_id, message, &mutex, &cond_var, &done);
      });

  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(timer_interval_));
  NonEmptyString message(GenerateNonemptyMessage());
  ASSERT_EQ(kSendContactInfoFailure,
            public_id2_->AddContact(public_identity2_, public_identity1_, message));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_FALSE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_THROW(received_public_identity_.string(), std::exception);
  ASSERT_THROW(received_message_.string(), std::exception);

  ASSERT_EQ(kSuccess, public_id1_->EnablePublicId(public_identity1_));

  // Check user2 can now add itself to user1's MCID
  message = GenerateNonemptyMessage();
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, message));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_EQ(public_identity2_, received_public_identity_);
  ASSERT_EQ(message, received_message_);
}

TEST_F(PublicIdTest, FUNC_DeletePublicIdPacketVerification) {
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));

  Identity card_address(session1_.social_info(public_identity1_).second->card_address);
  passport::Passport& pass(session1_.passport());
  Fob mmid(pass.SignaturePacketDetails(passport::kMmid, true, public_identity1_)),
      mpid(pass.SignaturePacketDetails(passport::kMpid, true, public_identity1_)),
      anmpid(pass.SignaturePacketDetails(passport::kAnmpid, true, public_identity1_));
  Identity mcid_name(crypto::Hash<crypto::SHA512>(public_identity1_));

  ASSERT_NE("", remote_chunk_store1_->Get(AppendableByAllName(mmid.identity), Fob()));
  ASSERT_NE("", remote_chunk_store1_->Get(SignaturePacketName(mpid.identity), Fob()));
  ASSERT_NE("", remote_chunk_store1_->Get(SignaturePacketName(anmpid.identity), Fob()));
  ASSERT_NE("", remote_chunk_store1_->Get(AppendableByAllName(mcid_name), Fob()));
  ASSERT_NE("", remote_chunk_store1_->Get(AppendableByAllName(mmid.identity), mmid));
  ASSERT_NE("", remote_chunk_store1_->Get(AppendableByAllName(mcid_name), mpid));
  ASSERT_NE("", remote_chunk_store1_->Get(ModifiableName(card_address), Fob()));

  ASSERT_EQ(kSuccess, public_id1_->DeletePublicId(public_identity1_));
  ASSERT_EQ("", remote_chunk_store1_->Get(AppendableByAllName(mmid.identity), Fob()));
  ASSERT_EQ("", remote_chunk_store1_->Get(SignaturePacketName(mpid.identity), Fob()));
  ASSERT_EQ("", remote_chunk_store1_->Get(SignaturePacketName(anmpid.identity), Fob()));
  ASSERT_EQ("", remote_chunk_store1_->Get(AppendableByAllName(mcid_name), Fob()));
  ASSERT_EQ("", remote_chunk_store1_->Get(AppendableByAllName(mmid.identity), mmid));
  ASSERT_EQ("", remote_chunk_store1_->Get(AppendableByAllName(mcid_name), mpid));
  ASSERT_EQ("", remote_chunk_store1_->Get(ModifiableName(card_address), Fob()));

  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, false));
  card_address = session1_.social_info(public_identity1_).second->card_address;
  mmid = pass.SignaturePacketDetails(passport::kMmid, true, public_identity1_);
  mpid = pass.SignaturePacketDetails(passport::kMpid, true, public_identity1_);
  anmpid = pass.SignaturePacketDetails(passport::kAnmpid, true, public_identity1_);
  mcid_name = crypto::Hash<crypto::SHA512>(public_identity1_);

  ASSERT_NE("", remote_chunk_store1_->Get(AppendableByAllName(mmid.identity), Fob()));
  ASSERT_NE("", remote_chunk_store1_->Get(SignaturePacketName(mpid.identity), Fob()));
  ASSERT_NE("", remote_chunk_store1_->Get(SignaturePacketName(anmpid.identity), Fob()));
  ASSERT_NE("", remote_chunk_store1_->Get(AppendableByAllName(mcid_name), Fob()));
  ASSERT_NE("", remote_chunk_store1_->Get(AppendableByAllName(mmid.identity), mmid));
  ASSERT_NE("", remote_chunk_store1_->Get(AppendableByAllName(mcid_name), mpid));
  ASSERT_NE("", remote_chunk_store1_->Get(ModifiableName(card_address), Fob()));

  ASSERT_EQ(kSuccess, public_id1_->DeletePublicId(public_identity1_));
  ASSERT_EQ("", remote_chunk_store1_->Get(AppendableByAllName(mmid.identity), Fob()));
  ASSERT_EQ("", remote_chunk_store1_->Get(SignaturePacketName(mpid.identity), Fob()));
  ASSERT_EQ("", remote_chunk_store1_->Get(SignaturePacketName(anmpid.identity), Fob()));
  ASSERT_EQ("", remote_chunk_store1_->Get(AppendableByAllName(mcid_name), Fob()));
  ASSERT_EQ("", remote_chunk_store1_->Get(AppendableByAllName(mmid.identity), mmid));
  ASSERT_EQ("", remote_chunk_store1_->Get(AppendableByAllName(mcid_name), mpid));
  ASSERT_EQ("", remote_chunk_store1_->Get(ModifiableName(card_address), Fob()));
}

TEST_F(PublicIdTest, FUNC_RemoveContact) {
  // Detailed msg exchanging behaviour tests are undertaken as part of
  // message_handler_test. Here only basic functionality is tested
  std::mutex mutex;
  std::condition_variable cond_var;

  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));
  Identity card1(session1_.social_info(public_identity1_).second->card_address),
           card2(session2_.social_info(public_identity2_).second->card_address);

  // 2 adds 1
  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& message,
           const NonEmptyString& /*timestamp*/) {
          NewContactSlot(own_public_id, contact_public_id, message, &mutex, &cond_var, &done);
      });
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(timer_interval_));
  ASSERT_EQ(kSuccess, public_id2_->StartCheckingForNewContacts(timer_interval_));
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, kInvite));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_NO_THROW(received_public_identity_.string());

  // 1 confirms 2
  done = false;
  NonEmptyString confirmed_contact;
  public_id2_->ConnectToContactConfirmedSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& /*timestamp*/) {
        ContactConfirmedSlot(own_public_id, contact_public_id, &confirmed_contact, &mutex,
                             &cond_var, &done);
      });
  ASSERT_EQ(kSuccess, public_id1_->ConfirmContact(public_identity1_, public_identity2_));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Alison)
  }

  ASSERT_FALSE(session1_.contacts_handler(public_identity1_)->GetContacts(
                   kConfirmed | kRequestSent).empty());
  ASSERT_FALSE(session2_.contacts_handler(public_identity2_)->GetContacts(
                   kConfirmed | kRequestSent).empty());

  // 1 removes 2
  done = false;
  NonEmptyString message(GenerateNonemptyMessage());
  public_id2_->ConnectToContactDeletionReceivedSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& message,
           const NonEmptyString& /*timestamp*/) {
          ContactDeletionReceivedSlot(own_public_id, contact_public_id, message, &mutex, &cond_var,
                                      &done);
      });
  NonEmptyString timestamp("now");
  ASSERT_EQ(kSuccess, public_id1_->RemoveContact(public_identity1_,
                                                 public_identity2_,
                                                 message,
                                                 timestamp,
                                                 true));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Alison)
  }
  ASSERT_NO_THROW(received_public_identity_.string());
  ASSERT_EQ(received_message_, message);
  received_message_ = NonEmptyString();
  ASSERT_EQ("", remote_chunk_store2_->Get(ModifiableName(card1), Fob()));

  // 2 processes the deletion by 1
  done = false;
  public_id2_->ConnectToContactDeletionProcessedSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& message,
           const NonEmptyString& /*timestamp*/) {
          ContactDeletionProcessedSlot(own_public_id, contact_public_id, message, &mutex,
                                       &cond_var, &done);
      });
  ASSERT_EQ(kSuccess, public_id2_->RemoveContact(public_identity2_,
                                                 public_identity1_,
                                                 message,
                                                 timestamp,
                                                 false));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Alison)
  }
  ASSERT_EQ(received_message_, message);

  ASSERT_EQ("", remote_chunk_store1_->Get(ModifiableName(card2), Fob()));

  ASSERT_TRUE(session1_.changed());
  ASSERT_TRUE(session2_.changed());

  ASSERT_TRUE(session1_.contacts_handler(public_identity1_)->GetContacts(
                  kConfirmed | kRequestSent).empty());
  ASSERT_TRUE(session2_.contacts_handler(public_identity2_)->GetContacts(
                  kConfirmed | kRequestSent).empty());
}

TEST_F(PublicIdTest, FUNC_RemoveContactMoveInbox) {
  std::mutex mutex;
  std::condition_variable cond_var;
  const NonEmptyString public_identity3(RandomAlphaNumericString(10));
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity3, true));

  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& message,
           const NonEmptyString& /*timestamp*/) {
        NewContactSlot(own_public_id, contact_public_id, message, &mutex, &cond_var, &done);
      });
  // 2 adds 1 and 3
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(timer_interval_));
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, kInvite));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Alison)
  }
  ASSERT_NO_THROW(received_public_identity_.string());

  done = false;
  received_public_identity_ = NonEmptyString();
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity3, kInvite));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Alison)
  }
  ASSERT_NO_THROW(received_public_identity_.string());

  Identity old_inbox_name_2(session2_.passport().SignaturePacketDetails(
                                passport::kMmid, true, public_identity2_).identity);
  Identity old_card_address_2(session2_.social_info(public_identity2_).second->card_address);

  // 2 removes 1
  done = false;
  NonEmptyString reason(GenerateNonemptyMessage()), timestamp("now");
  ASSERT_EQ(kSuccess, public_id2_->RemoveContact(public_identity2_,
                                                 public_identity1_,
                                                 reason,
                                                 timestamp,
                                                 true));

  // Check that 3 has been given 2's new inbox name
  Contact contact;
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2,
                                    [&] ()->bool {
                                      session1_.contacts_handler(public_identity3)->ContactInfo(
                                          public_identity2_,
                                          &contact);
                                      return contact.inbox_name != old_inbox_name_2;
                                    }));
  }
  ASSERT_NE(contact.inbox_name, old_inbox_name_2);
  ASSERT_NE(contact.pointer_to_info, old_card_address_2);

  ASSERT_EQ(contact.inbox_name,
            session2_.passport().SignaturePacketDetails(passport::kMmid,
                                                        true,
                                                        public_identity2_).identity);
  ASSERT_EQ(contact.pointer_to_info,
            session2_.social_info(public_identity2_).second->card_address);
}

TEST_F(PublicIdTest, FUNC_MovedInbox) {
  std::mutex mutex, mutex2;
  std::condition_variable cond_var, cond_var2;
  bool done(false), done2(false);
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));
  NonEmptyString public_id3(RandomAlphaNumericString(6));
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_id3, true));

  // Connect a slot which will reject the new contact
  public_id1_->ConnectToNewContactSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& message,
           const NonEmptyString& /*timestamp*/) {
        ContactRequestSlot(own_public_id, contact_public_id, message, &mutex, &cond_var, &done);
      });

  NonEmptyString confirmed_contact;
  public_id2_->ConnectToContactConfirmedSignal(
      [&] (const NonEmptyString& own_public_id,
           const NonEmptyString& contact_public_id,
           const NonEmptyString& /*timestamp*/) {
        ContactConfirmedSlot(own_public_id, contact_public_id, &confirmed_contact, &mutex2,
                             &cond_var2, &done2);
      });

  // Send the message and start checking for contacts
  NonEmptyString message(GenerateNonemptyMessage());
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, message));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(timer_interval_));

  const ContactsHandlerPtr contacts_handler2(session2_.contacts_handler(public_identity2_));
  ASSERT_NE(nullptr, contacts_handler2.get());
  Contact received_contact;
  ASSERT_EQ(kSuccess, contacts_handler2->ContactInfo(public_identity1_, &received_contact));
  ASSERT_EQ(kRequestSent, received_contact.status);

  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }

  // Other side got message. Check status of contact and reply affirmatively.
  ASSERT_EQ(public_identity2_, received_public_identity_);
  ASSERT_EQ(message, received_message_);
  received_contact = Contact();
  const ContactsHandlerPtr contacts_handler1(session1_.contacts_handler(public_identity1_));
  ASSERT_NE(nullptr, contacts_handler1.get());
  ASSERT_EQ(kSuccess, contacts_handler1->ContactInfo(public_identity2_, &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);
  ASSERT_EQ(kSuccess, public_id1_->ConfirmContact(public_identity1_, public_identity2_));
  ASSERT_EQ(kSuccess, public_id2_->StartCheckingForNewContacts(timer_interval_));

  // Contact should now be confirmed after reply
  received_contact = Contact();
  ASSERT_EQ(kSuccess, contacts_handler1->ContactInfo(public_identity2_, &received_contact));
  ASSERT_EQ(kConfirmed, received_contact.status);

  {
    std::unique_lock<std::mutex> lock(mutex2);
    ASSERT_TRUE(cond_var2.wait_for(lock, interval_ * 2, [&] ()->bool { return done2; }));  // NOLINT (Dan)
  }

  // Confirmation received, status should be updated
  ASSERT_EQ(public_identity1_, confirmed_contact);
  received_contact = Contact();
  ASSERT_EQ(kSuccess, contacts_handler2->ContactInfo(public_identity1_, &received_contact));
  ASSERT_EQ(kConfirmed, received_contact.status);
  ASSERT_NO_THROW(received_contact.inbox_name.string());

  // Add the second one
  done = false;
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_id3, message));
  {
    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cond_var.wait_for(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }

  std::vector<Contact> contacts_id2(2);
  contacts_handler1->ContactInfo(public_identity2_, &contacts_id2[0]);
  Identity pre_inbox_name_in_id1(contacts_id2[0].inbox_name);
  session1_.contacts_handler(public_id3)->ContactInfo(public_identity2_, &contacts_id2[1]);
  Identity pre_inbox_name_in_id3(contacts_id2[1].inbox_name);
  ASSERT_EQ(pre_inbox_name_in_id1, pre_inbox_name_in_id3);

  Identity new_inbox_name;
  StoreNewInbox(new_inbox_name);
  ASSERT_NO_THROW(new_inbox_name.string());

  std::vector<Contact> contacts_ids_1_3(2);
  contacts_handler2->ContactInfo(public_identity1_, &contacts_ids_1_3[0]);
  contacts_handler2->ContactInfo(public_id3, &contacts_ids_1_3[1]);
  ASSERT_EQ(kSuccess, InformContactInfo(public_id2_,
                                        public_identity2_,
                                        contacts_ids_1_3,
                                        kInvite,
                                        kMovedInbox,
                                        new_inbox_name.string()));

  Sleep(bptime::seconds(kSecondsInterval));

  contacts_handler1->ContactInfo(public_identity2_, &contacts_id2[0]);
  Identity post_inbox_name_in_id1(contacts_id2[0].inbox_name);
  session1_.contacts_handler(public_id3)->ContactInfo(public_identity2_, &contacts_id2[1]);
  Identity post_inbox_name_in_id3(contacts_id2[1].inbox_name);
  ASSERT_EQ(new_inbox_name, post_inbox_name_in_id1);
  ASSERT_EQ(new_inbox_name, post_inbox_name_in_id3);
}

TEST_F(PublicIdTest, FUNC_LifestuffCardSetAndGet) {
  // Connect two public ids
  ASSERT_EQ(kSuccess, CreateAndConnectTwoIds(*public_id1_,
                                             public_identity1_,
                                             session1_,
                                             *public_id2_,
                                             public_identity2_,
                                             session2_));

  SocialInfoMap received_social_info_map, own_social_info_map;
  std::mutex mutex;
  std::condition_variable cond_var;
  bool done(false);
  public_id2_->ConnectToLifestuffCardUpdatedSignal(
        [&] (const NonEmptyString& /*own_public_id*/,
             const NonEmptyString& /*contact_public_id*/,
             const NonEmptyString& /*timestamp*/) {
          LifestuffCardSlot(&mutex, &cond_var, &done);
        });

  // Change one of the LS cards
  SocialInfoMap social_info_map(CreateRandomSocialInfoMap(10));
  ASSERT_EQ(kSuccess, public_id1_->SetLifestuffCard(public_identity1_, social_info_map));
  ASSERT_EQ(kSuccess, public_id1_->GetLifestuffCard(public_identity1_, "", own_social_info_map));
  ASSERT_TRUE(EqualMaps(social_info_map, own_social_info_map));
  {
    std::unique_lock<std::mutex> loch(mutex);
    ASSERT_TRUE(cond_var.wait_for(loch, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_TRUE(done);
  ASSERT_EQ(kSuccess, public_id2_->GetLifestuffCard(public_identity2_,
                                                    public_identity1_.string(),
                                                    received_social_info_map));
  ASSERT_TRUE(EqualMaps(social_info_map, received_social_info_map));

  // New map
  own_social_info_map.clear();
  received_social_info_map.clear();
  done = false;
  social_info_map = CreateRandomSocialInfoMap(10);
  ASSERT_EQ(kSuccess, public_id1_->SetLifestuffCard(public_identity1_, social_info_map));
  ASSERT_EQ(kSuccess, public_id1_->GetLifestuffCard(public_identity1_, "", own_social_info_map));
  ASSERT_TRUE(EqualMaps(social_info_map, own_social_info_map));
  {
    std::unique_lock<std::mutex> loch(mutex);
    ASSERT_TRUE(cond_var.wait_for(loch, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_TRUE(done);
  ASSERT_EQ(kSuccess, public_id2_->GetLifestuffCard(public_identity2_,
                                                    public_identity1_.string(),
                                                    received_social_info_map));
  ASSERT_TRUE(EqualMaps(social_info_map, received_social_info_map));

  // Modified values in map
  own_social_info_map.clear();
  received_social_info_map.clear();
  done = false;
  ChangeMapValues(social_info_map);
  ASSERT_EQ(kSuccess, public_id1_->SetLifestuffCard(public_identity1_, social_info_map));
  ASSERT_EQ(kSuccess, public_id1_->GetLifestuffCard(public_identity1_, "", own_social_info_map));
  ASSERT_TRUE(EqualMaps(social_info_map, own_social_info_map));
  {
    std::unique_lock<std::mutex> loch(mutex);
    ASSERT_TRUE(cond_var.wait_for(loch, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_TRUE(done);
  ASSERT_EQ(kSuccess, public_id2_->GetLifestuffCard(public_identity2_,
                                                    public_identity1_.string(),
                                                    received_social_info_map));
  ASSERT_TRUE(EqualMaps(social_info_map, received_social_info_map));

  // Change to smaller map
  own_social_info_map.clear();
  received_social_info_map.clear();
  done = false;
  social_info_map = CreateRandomSocialInfoMap(5);
  ASSERT_EQ(kSuccess, public_id1_->SetLifestuffCard(public_identity1_, social_info_map));
  ASSERT_EQ(kSuccess, public_id1_->GetLifestuffCard(public_identity1_, "", own_social_info_map));
  ASSERT_TRUE(EqualMaps(social_info_map, own_social_info_map));
  {
    std::unique_lock<std::mutex> loch(mutex);
    ASSERT_TRUE(cond_var.wait_for(loch, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_TRUE(done);
  ASSERT_EQ(kSuccess, public_id2_->GetLifestuffCard(public_identity2_,
                                                    public_identity1_.string(),
                                                    received_social_info_map));
  ASSERT_TRUE(EqualMaps(social_info_map, received_social_info_map));

  // Change to empty map
  social_info_map.clear();
  own_social_info_map.clear();
  received_social_info_map.clear();
  done = false;
  ASSERT_EQ(kSuccess, public_id1_->SetLifestuffCard(public_identity1_, social_info_map));
  ASSERT_EQ(kSuccess, public_id1_->GetLifestuffCard(public_identity1_, "", own_social_info_map));
  ASSERT_TRUE(EqualMaps(social_info_map, own_social_info_map));
  {
    std::unique_lock<std::mutex> loch(mutex);
    ASSERT_TRUE(cond_var.wait_for(loch, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_TRUE(done);
  ASSERT_EQ(kSuccess, public_id2_->GetLifestuffCard(public_identity2_,
                                                    public_identity1_.string(),
                                                    received_social_info_map));
  ASSERT_TRUE(EqualMaps(social_info_map, received_social_info_map));

  // Fill up map again
  received_social_info_map.clear();
  own_social_info_map.clear();
  done = false;
  social_info_map = CreateRandomSocialInfoMap(20);
  ASSERT_EQ(kSuccess, public_id1_->SetLifestuffCard(public_identity1_, social_info_map));
  ASSERT_EQ(kSuccess, public_id1_->GetLifestuffCard(public_identity1_, "", own_social_info_map));
  ASSERT_TRUE(EqualMaps(social_info_map, own_social_info_map));
  {
    std::unique_lock<std::mutex> loch(mutex);
    ASSERT_TRUE(cond_var.wait_for(loch, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_TRUE(done);
  ASSERT_EQ(kSuccess, public_id2_->GetLifestuffCard(public_identity2_,
                                                    public_identity1_.string(),
                                                    received_social_info_map));
  ASSERT_TRUE(EqualMaps(social_info_map, received_social_info_map));
}

int CreatePublicIdObject(std::shared_ptr<PublicId>& public_id,
                         AsioService& asio_service,
                         Session& session,
                         std::shared_ptr<priv::chunk_store::RemoteChunkStore>& remote_chunk_store,
                         maidsafe::test::TestPath& test_dir,
                         const NonEmptyString& public_identity) {
  session.Reset();
  asio_service.Start();

  std::string dir(RandomAlphaNumericString(8));
  remote_chunk_store = priv::chunk_store::CreateLocalChunkStore(*test_dir / dir / "buffer",
                                                                *test_dir / "simulation",
                                                                *test_dir / dir / "lock",
                                                                asio_service.service());

  public_id = std::make_shared<PublicId>(*remote_chunk_store, session, asio_service.service());

  return public_id->CreatePublicId(public_identity, true);
}

int ConnectTwoIds(PublicId& public_id1,
                  const NonEmptyString& public_identity1,
                  PublicId& public_id3,
                  const NonEmptyString& public_identity3) {
  std::mutex mutex, mutex3;
  std::condition_variable cond_var, cond_var3;
  bool done(false), done3(false);
  std::chrono::seconds interval(3);
  public_id3.ConnectToNewContactSignal(
      [&] (const NonEmptyString& /*own_public_id*/,
           const NonEmptyString& /*contact_public_id*/,
           const NonEmptyString& /*message*/,
           const NonEmptyString& /*timestamp*/) {
        ExchangeSlot(&mutex3, &cond_var3, &done3);
      });

  public_id1.ConnectToContactConfirmedSignal(
      [&] (const NonEmptyString& /*own_public_id*/,
           const NonEmptyString& /*contact_public_id*/,
           const NonEmptyString& /*timestamp*/) {
        ExchangeSlot(&mutex, &cond_var, &done);
      });

  int result(public_id1.AddContact(public_identity1, public_identity3, kInvite));
  if (result != kSuccess)
    return result;

  {
    std::unique_lock<std::mutex> loch(mutex3);
    if (!cond_var3.wait_for(loch, interval * 2, [&] ()->bool { return done3; }))  // NOLINT (Dan)
      return -1;
  }

  result = public_id3.ConfirmContact(public_identity3, public_identity1);
  if (result != kSuccess)
    return result;

  {
    std::unique_lock<std::mutex> loch(mutex);
    if (!cond_var.wait_for(loch, interval * 2, [&] ()->bool { return done; }))  // NOLINT (Dan)
      return -1;
  }

  return kSuccess;
}

TEST_F(PublicIdTest, FUNC_LifestuffCardOnlineOfflineContacts) {
  // Connect two public ids
  EXPECT_EQ(kSuccess, CreateAndConnectTwoIds(*public_id1_,
                                             public_identity1_,
                                             session1_,
                                             *public_id2_,
                                             public_identity2_,
                                             session2_));

  AsioService asio_service3(5);
  Session session3;
  std::shared_ptr<priv::chunk_store::RemoteChunkStore> remote_chunk_store3;
  std::shared_ptr<PublicId> public_id3;
  NonEmptyString public_identity3("User 3 " + RandomAlphaNumericString(8));
  EXPECT_EQ(kSuccess, CreatePublicIdObject(public_id3,
                                           asio_service3,
                                           session3,
                                           remote_chunk_store3,
                                           test_dir_,
                                           public_identity3));
  EXPECT_EQ(kSuccess, public_id3->StartCheckingForNewContacts(timer_interval_));

  EXPECT_EQ(kSuccess, ConnectTwoIds(*public_id1_,
                                    public_identity1_,
                                    *public_id3,
                                    public_identity3));

  std::mutex mutex2, mutex3;
  std::condition_variable cond_var2, cond_var3;
  bool done2(false), done3(false);
  public_id2_->ConnectToLifestuffCardUpdatedSignal(
        [&] (const NonEmptyString& /*own_public_id*/,
             const NonEmptyString& /*contact_public_id*/,
             const NonEmptyString& /*timestamp*/) {
          LifestuffCardSlot(&mutex2, &cond_var2, &done2);
        });
  public_id3->ConnectToLifestuffCardUpdatedSignal(
      [&] (const NonEmptyString& /*own_public_id*/,
           const NonEmptyString& /*contact_public_id*/,
           const NonEmptyString& /*timestamp*/) {
        LifestuffCardSlot(&mutex3, &cond_var3, &done3);
      });

  SocialInfoMap social_info_map(CreateRandomSocialInfoMap(10));
  ASSERT_EQ(kSuccess, public_id1_->SetLifestuffCard(public_identity1_, social_info_map));
  {
    std::unique_lock<std::mutex> loch(mutex3);
    ASSERT_FALSE(cond_var3.wait_for(loch, interval_ * 2, [&] ()->bool { return done3; }));  // NOLINT (Dan)
  }
  ASSERT_TRUE(done2);
  ASSERT_FALSE(done3);

  public_id3->StopCheckingForNewContacts();
  asio_service3.Stop();
  remote_chunk_store3->WaitForCompletion();
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
