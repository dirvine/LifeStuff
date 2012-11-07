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
#ifndef MAIDSAFE_LIFESTUFF_TESTS_API_API_TEST_RESOURCES_H_
#define MAIDSAFE_LIFESTUFF_TESTS_API_API_TEST_RESOURCES_H_

#include <functional>
#include <sstream>
#include <utility>
#include <string>
#include <vector>

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/lifestuff_api.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/message_handler.h"
#include "maidsafe/lifestuff/detail/public_id.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/user_credentials.h"
#include "maidsafe/lifestuff/detail/user_storage.h"
#include "maidsafe/lifestuff/tests/network_helper.h"

namespace args = std::placeholders;
namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

namespace test {

struct TestingVariables {
  TestingVariables()
      : chat_message(),
        chat_message_received(false),
        file_name(),
        file_id(),
        file_transfer_received(false),
        newly_contacted(false),
        confirmed(false),
        picture_updated(false),
        presence_announced(false),
        removal_message(),
        removed(false),
        contact_request_message(),
        social_info_map_changed(false),
        immediate_quit_required(false) {}
  std::string chat_message;
  bool chat_message_received;
  std::string file_name, file_id;
  bool file_transfer_received,
       newly_contacted,
       confirmed,
       picture_updated,
       presence_announced;
  std::string removal_message;
  bool removed;
  std::string contact_request_message;
  bool social_info_map_changed;
  bool immediate_quit_required;
};

void ChatSlot(const NonEmptyString&,
              const NonEmptyString&,
              const NonEmptyString& signal_message,
              const NonEmptyString&,
              std::string* slot_message,
              volatile bool* done);

void FileTransferSlot(const NonEmptyString&,
                      const NonEmptyString&,
                      const NonEmptyString& signal_file_name,
                      const NonEmptyString& signal_file_id,
                      const NonEmptyString&,
                      std::string* slot_file_name,
                      std::string* slot_file_id,
                      volatile bool* done);

void MultipleFileTransferSlot(const NonEmptyString&,
                              const NonEmptyString&,
                              const NonEmptyString& signal_file_name,
                              const NonEmptyString& signal_file_id,
                              const NonEmptyString&,
                              std::vector<std::string>* ids,
                              std::vector<std::string>* names,
                              size_t* total_files,
                              volatile bool* done);

void NewContactSlot(const NonEmptyString&,
                    const NonEmptyString&,
                    const NonEmptyString&,
                    const NonEmptyString&,
                    volatile bool* done,
                    NonEmptyString* contact_request_message);

void ContactConfirmationSlot(const NonEmptyString&,
                             const NonEmptyString&,
                             const NonEmptyString&,
                             volatile bool* done);

void ContactProfilePictureSlot(const NonEmptyString&,
                               const NonEmptyString&,
                               const NonEmptyString&,
                               volatile bool* done);

void ContactPresenceSlot(const NonEmptyString&,
                         const NonEmptyString&,
                         const NonEmptyString&,
                         ContactPresence,
                         volatile bool* done);

void ContactDeletionSlot(const NonEmptyString&,
                         const NonEmptyString&,
                         const NonEmptyString& signal_message,
                         const NonEmptyString&,
                         NonEmptyString* slot_message,
                         volatile bool* done);

void LifestuffCardSlot(const NonEmptyString&,
                       const NonEmptyString&,
                       const NonEmptyString&,
                       volatile bool* done);

void ImmediateQuitRequiredSlot(volatile bool* done);

int DoFullCreateUser(LifeStuff& test_elements,
                     const NonEmptyString& keyword,
                     const NonEmptyString& pin,
                     const NonEmptyString& password);

int DoFullLogIn(LifeStuff& test_elements,
                const NonEmptyString& keyword,
                const NonEmptyString& pin,
                const NonEmptyString& password);

int DoFullLogOut(LifeStuff& test_elements);

int CreateAndConnectTwoPublicIds(LifeStuff& test_elements1,
                                 LifeStuff& test_elements2,
                                 TestingVariables& testing_variables1,
                                 TestingVariables& testing_variables2,
                                 const fs::path& test_dir,
                                 const NonEmptyString& keyword1,
                                 const NonEmptyString& pin1,
                                 const NonEmptyString& password1,
                                 const NonEmptyString& public_id1,
                                 const NonEmptyString& keyword2,
                                 const NonEmptyString& pin2,
                                 const NonEmptyString& password2,
                                 const NonEmptyString& public_id2,
                                 bool several_files = false,
                                 std::vector<std::string>* ids = nullptr,
                                 std::vector<std::string>* names = nullptr,
                                 size_t* total_files = nullptr);

int InitialiseAndConnect(LifeStuff& test_elements,
                         TestingVariables& testing_variables,
                         const fs::path& test_dir,
                         bool several_files = false,
                         std::vector<std::string>* ids = nullptr,
                         std::vector<std::string>* names = nullptr,
                         size_t* total_files = nullptr);

int CreateAccountWithPublicId(LifeStuff& test_elements,
                              TestingVariables& testing_variables,
                              const fs::path& test_dir,
                              const NonEmptyString& keyword,
                              const NonEmptyString& pin,
                              const NonEmptyString& password,
                              const NonEmptyString& public_id,
                              bool several_files = false,
                              std::vector<std::string>* ids = nullptr,
                              std::vector<std::string>* names = nullptr,
                              size_t* total_files = nullptr);

int ConnectTwoPublicIds(LifeStuff& test_elements1,
                        LifeStuff& test_elements2,
                        TestingVariables& testing_variables1,
                        TestingVariables& testing_variables2,
                        const NonEmptyString& keyword1,
                        const NonEmptyString& pin1,
                        const NonEmptyString& password1,
                        const NonEmptyString& public_id1,
                        const NonEmptyString& keyword2,
                        const NonEmptyString& pin2,
                        const NonEmptyString& password2,
                        const NonEmptyString& public_id2);

namespace sleepthreads {

void RandomSleep(const std::pair<int, int> sleeps);

void RunChangePin(LifeStuff& test_elements,
                  int& result,
                  const NonEmptyString& new_pin,
                  const NonEmptyString& password,
                  const std::pair<int, int> sleeps = std::make_pair(0, 0));

void RunChangeKeyword(LifeStuff& test_elements,
                      int& result,
                      const NonEmptyString& new_keyword,
                      const NonEmptyString& password,
                      const std::pair<int, int> sleeps = std::make_pair(0, 0));

void RunChangePassword(LifeStuff& test_elements,
                       int& result,
                       const NonEmptyString& new_password,
                       const NonEmptyString& password,
                       const std::pair<int, int> sleeps);

void RunCreatePublicId(LifeStuff& test_elements,
                       int& result,
                       const NonEmptyString& new_id,
                       const std::pair<int, int> sleeps);

void RunCreateUser(LifeStuff& test_elements,
                   int& result,
                   const NonEmptyString& keyword,
                   const NonEmptyString& pin,
                   const NonEmptyString& password,
                   const std::pair<int, int> sleeps = std::make_pair(0, 0));

void RunChangeProfilePicture(LifeStuff& test_elements_,
                             int& result,
                             const NonEmptyString public_id,
                             const NonEmptyString file_content);

void RunLogIn(LifeStuff& test_elements,
              int& result,
              const NonEmptyString& keyword,
              const NonEmptyString& pin,
              const NonEmptyString& password,
              const std::pair<int, int> sleeps);

}  // namespace sleepthreads

class OneUserApiTest : public testing::Test {
 public:
  OneUserApiTest()
    : test_dir_(maidsafe::test::CreateTestPath()),
      keyword_(RandomAlphaNumericString(6)),
      pin_(CreatePin()),
      password_(RandomAlphaNumericString(6)),
      network_(),
      error_code_(),
      done_(),
      test_elements_(lifestuff_slots_, *test_dir_ / "elements1") {}

 protected:
  maidsafe::test::TestPath test_dir_;
  NonEmptyString keyword_;
  NonEmptyString pin_;
  NonEmptyString password_;
  NetworkHelper network_;
  boost::system::error_code error_code_;
  volatile bool done_;
  Slots lifestuff_slots_;
  LifeStuff test_elements_;

  virtual void SetUp();

  virtual void TearDown();
};

class TwoInstancesApiTest : public OneUserApiTest {
 public:
  TwoInstancesApiTest()
    : lifestuff_slots_2_(),
      test_elements_2_(lifestuff_slots_2_, *test_dir_ / "elements2"),
      testing_variables_1_(),
      testing_variables_2_() {}

 protected:
  Slots lifestuff_slots_2_;
  LifeStuff test_elements_2_;
  TestingVariables testing_variables_1_;
  TestingVariables testing_variables_2_;

  virtual void SetUp();

  virtual void TearDown();
};

class TwoUsersApiTest : public testing::Test {
 public:
  TwoUsersApiTest()
    : test_dir_(maidsafe::test::CreateTestPath()),
      keyword_1_(RandomAlphaNumericString(6)),
      pin_1_(CreatePin()),
      password_1_(RandomAlphaNumericString(6)),
      public_id_1_(RandomAlphaNumericString(5)),
      keyword_2_(RandomAlphaNumericString(6)),
      pin_2_(CreatePin()),
      password_2_(RandomAlphaNumericString(6)),
      public_id_2_(RandomAlphaNumericString(5)),
      testing_variables_1_(),
      testing_variables_2_(),
      lifestuff_slots_1_(),
      lifestuff_slots_2_(),
      test_elements_1_(lifestuff_slots_1_, *test_dir_ / "elements1"),
      test_elements_2_(lifestuff_slots_2_, *test_dir_ / "elements2"),
      network_() {}

 protected:
  maidsafe::test::TestPath test_dir_;
  NonEmptyString keyword_1_;
  NonEmptyString pin_1_;
  NonEmptyString password_1_;
  NonEmptyString public_id_1_;
  NonEmptyString keyword_2_;
  NonEmptyString pin_2_;
  NonEmptyString password_2_;
  NonEmptyString public_id_2_;
  TestingVariables testing_variables_1_;
  TestingVariables testing_variables_2_;
  Slots lifestuff_slots_1_;
  Slots lifestuff_slots_2_;
  LifeStuff test_elements_1_;
  LifeStuff test_elements_2_;
  NetworkHelper network_;

  virtual void SetUp();

  virtual void TearDown();
};

class TwoUsersMutexApiTest : public TwoUsersApiTest {
 public:
  TwoUsersMutexApiTest()
    : mutex_() {}

 protected:
  boost::mutex mutex_;

  virtual void SetUp();

  virtual void TearDown();
};

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_TESTS_API_API_TEST_RESOURCES_H_

