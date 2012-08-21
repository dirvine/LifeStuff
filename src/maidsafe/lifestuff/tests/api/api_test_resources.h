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

namespace args = std::placeholders;
namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;
namespace maidsafe {

namespace lifestuff {

namespace test {

namespace testresources {

struct ShareChangeLog {
  ShareChangeLog()
      : share_name(),
        target_path(),
        num_of_entries(1),
        old_path(),
        new_path(),
        op_type() {}
  ShareChangeLog(const std::string& share_name_in,
                 const fs::path& target_path_in,
                 const uint32_t& num_of_entries_in,
                 const fs::path& old_path_in,
                 const fs::path& new_path_in,
                 const int& op_type_in)
      : share_name(share_name_in),
        target_path(target_path_in),
        num_of_entries(num_of_entries_in),
        old_path(old_path_in),
        new_path(new_path_in),
        op_type(op_type_in) {}

  std::string share_name;
  fs::path target_path;
  uint32_t num_of_entries;
  fs::path old_path;
  fs::path new_path;
  int op_type;
};

typedef std::vector<ShareChangeLog> ShareChangeLogBook;

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
        new_private_share_name(),
        new_private_share_id(),
        new_private_access_level(-1),
        privately_invited(false),
        new_open_share_id(),
        openly_invited(false),
        deleted_private_share_name(),
        private_share_deleted(false),
        access_private_share_name(),
        private_member_access(0),
        private_member_access_changed(false),
        old_share_name(),
        new_share_name(),
        share_renamed(false),
        share_changes(),
        contact_request_message(),
        social_info_map(),
        social_info_map_changed(false) {}
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
  std::string new_private_share_name, new_private_share_id;
  int new_private_access_level;
  bool privately_invited;
  std::string new_open_share_id;
  bool openly_invited;
  std::string deleted_private_share_name;
  bool private_share_deleted;
  std::string access_private_share_name;
  int private_member_access;
  bool private_member_access_changed;
  std::string old_share_name;
  std::string new_share_name;
  bool share_renamed;
  ShareChangeLogBook share_changes;
  std::string contact_request_message;
  SocialInfoMap social_info_map;
  bool social_info_map_changed;
};

void ChatSlot(const std::string&,
              const std::string&,
              const std::string& signal_message,
              const std::string&,
              std::string* slot_message,
              volatile bool* done);

void FileTransferSlot(const std::string&,
                      const std::string&,
                      const std::string& signal_file_name,
                      const std::string& signal_file_id,
                      const std::string&,
                      std::string* slot_file_name,
                      std::string* slot_file_id,
                      volatile bool* done);

void MultipleFileTransferSlot(const std::string&,
                              const std::string&,
                              const std::string& signal_file_name,
                              const std::string& signal_file_id,
                              const std::string&,
                              std::vector<std::string>* ids,
                              std::vector<std::string>* names,
                              size_t* total_files,
                              volatile bool* done);

void NewContactSlot(const std::string&,
                    const std::string&,
                    const std::string&,
                    const std::string&,
                    volatile bool* done,
                    std::string* contact_request_message);

void ContactConfirmationSlot(const std::string&,
                             const std::string&,
                             const std::string&,
                             volatile bool* done);

void ContactProfilePictureSlot(const std::string&,
                               const std::string&,
                               const std::string&,
                               volatile bool* done);

void ContactPresenceSlot(const std::string&,
                         const std::string&,
                         const std::string&,
                         ContactPresence,
                         volatile bool* done);

void ContactDeletionSlot(const std::string&,
                         const std::string&,
                         const std::string& signal_message,
                         const std::string&,
                         std::string* slot_message,
                         volatile bool* done);

void PrivateShareInvitationSlot(const std::string&,
                                const std::string&,
                                const std::string& signal_share_name,
                                const std::string& signal_share_id,
                                int access_level,
                                const std::string&,
                                std::string* slot_share_name,
                                std::string* slot_share_id,
                                int* slot_access_level,
                                volatile bool* done);

void PrivateShareDeletionSlot(const std::string&,
                              const std::string& signal_share_name,
                              const std::string&,
                              const std::string&,
                              const std::string&,
                              std::string* slot_share_name,
                              volatile bool* done);

void PrivateMemberAccessChangeSlot(const std::string&,
                                   const std::string&,
                                   const std::string&,
                                   const std::string&,
                                   int signal_member_access,
                                   const std::string&  /*slot_share_name*/,
                                   int* slot_member_access,
                                   volatile bool* done);

void OpenShareInvitationSlot(const std::string&,
                             const std::string&,
                             const std::string&,
                             const std::string& signal_share_id,
                             const std::string&,
                             std::string* slot_share_id,
                             volatile bool* done);

void ShareRenameSlot(const std::string& old_share_name,
                     const std::string& new_share_name,
                     std::string* slot_old_share_name,
                     std::string* slot_new_share_name,
                     volatile bool* done);

void ShareChangedSlot(const std::string& share_name,
                      const fs::path& target_path,
                      const uint32_t& num_of_entries,
                      const fs::path& old_path,
                      const fs::path& new_path,
                      const int& op_type,
                      boost::mutex* mutex,
                      ShareChangeLogBook* share_changes);

void LifestuffCardSlot(const SocialInfoMap& map_in, volatile bool* done, SocialInfoMap* map);

int CreateAndConnectTwoPublicIds(LifeStuff& test_elements1,
                                 LifeStuff& test_elements2,
                                 testresources::TestingVariables& testing_variables1,
                                 testresources::TestingVariables& testing_variables2,
                                 const fs::path& test_dir,
                                 const std::string& keyword1,
                                 const std::string& pin1,
                                 const std::string& password1,
                                 const std::string& public_id1,
                                 const std::string& keyword2,
                                 const std::string& pin2,
                                 const std::string& password2,
                                 const std::string& public_id2,
                                 bool several_files = false,
                                 std::vector<std::string>* ids = nullptr,
                                 std::vector<std::string>* names = nullptr,
                                 size_t* total_files = nullptr,
                                 boost::mutex* mutex = nullptr);

int CreatePublicId(LifeStuff& test_elements,
                   testresources::TestingVariables& testing_variables,
                   const fs::path& test_dir,
                   const std::string& keyword,
                   const std::string& pin,
                   const std::string& password,
                   const std::string& public_id,
                   bool several_files = false,
                   std::vector<std::string>* ids = nullptr,
                   std::vector<std::string>* names = nullptr,
                   size_t* total_files = nullptr,
                   boost::mutex* mutex = nullptr);

int ConnectTwoPublicIds(LifeStuff& test_elements1,
                        LifeStuff& test_elements2,
                        testresources::TestingVariables& testing_variables1,
                        testresources::TestingVariables& testing_variables2,
                        const std::string& keyword1,
                        const std::string& pin1,
                        const std::string& password1,
                        const std::string& public_id1,
                        const std::string& keyword2,
                        const std::string& pin2,
                        const std::string& password2,
                        const std::string& public_id2);

}  // namespace testresources

namespace sleepthreads {

void RandomSleep(const std::pair<int, int> sleeps);

void RunChangePin(LifeStuff& test_elements,
                  int& result,
                  const std::string& new_pin,
                  const std::string& password,
                  const std::pair<int, int> sleeps);

void RunChangeKeyword(LifeStuff& test_elements,
                      int& result,
                      const std::string& new_keyword,
                      const std::string& password,
                      const std::pair<int, int> sleeps);

void RunChangePassword(LifeStuff& test_elements,
                       int& result,
                       const std::string& new_password,
                       const std::string& password,
                       const std::pair<int, int> sleeps);

void RunCreatePublicId(LifeStuff& test_elements,
                       int& result,
                       const std::string& new_id,
                       const std::pair<int, int> sleeps);

void RunCreateUser(LifeStuff& test_elements,
                   int& result,
                   const std::string& keyword,
                   const std::string& pin,
                   const std::string& password,
                   const std::pair<int, int> sleeps);

void RunChangeProfilePicture(LifeStuff& test_elements_,
                             int& result,
                             const std::string public_id,
                             const std::string file_content);

void RunLogIn(LifeStuff& test_elements,
              int& result,
              const std::string& keyword,
              const std::string& pin,
              const std::string& password,
              const std::pair<int, int> sleeps);

}  // namespace sleepthreads

class OneUserApiTest : public testing::Test {
 public:
  OneUserApiTest()
    :  test_dir_(maidsafe::test::CreateTestPath()),
      keyword_(RandomAlphaNumericString(6)),
      pin_(CreatePin()),
      password_(RandomAlphaNumericString(6)),
      error_code_(),
      done_(),
      test_elements_() {}

 protected:
  maidsafe::test::TestPath test_dir_;
  std::string keyword_;
  std::string pin_;
  std::string password_;
  boost::system::error_code error_code_;
  volatile bool done_;
  LifeStuff test_elements_;

  virtual void SetUp();

  virtual void TearDown();
};

class TwoInstancesApiTest : public OneUserApiTest {
 public:
  TwoInstancesApiTest()
    : test_elements_2_(),
      testing_variables_1_(),
      testing_variables_2_() {}

 protected:
  LifeStuff test_elements_2_;
  testresources::TestingVariables testing_variables_1_;
  testresources::TestingVariables testing_variables_2_;

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
      test_elements_1_(),
      test_elements_2_(),
      testing_variables_1_(),
      testing_variables_2_() {}

 protected:
  maidsafe::test::TestPath test_dir_;
  std::string keyword_1_;
  std::string pin_1_;
  std::string password_1_;
  std::string public_id_1_;
  std::string keyword_2_;
  std::string pin_2_;
  std::string password_2_;
  std::string public_id_2_;
  LifeStuff test_elements_1_;
  LifeStuff test_elements_2_;
  testresources::TestingVariables testing_variables_1_;
  testresources::TestingVariables testing_variables_2_;

  virtual void SetUp();

  virtual void TearDown();
};

class PrivateSharesApiTest : public ::testing::TestWithParam<int> {
 public:
  PrivateSharesApiTest() : rights_(GetParam()),
    test_dir_(maidsafe::test::CreateTestPath()),
    keyword_1_(RandomAlphaNumericString(6)),
    pin_1_(CreatePin()),
    password_1_(RandomAlphaNumericString(6)),
    public_id_1_(RandomAlphaNumericString(5)),
    keyword_2_(RandomAlphaNumericString(6)),
    pin_2_(CreatePin()),
    password_2_(RandomAlphaNumericString(6)),
    public_id_2_(RandomAlphaNumericString(5)),
    test_elements_1_(),
    test_elements_2_(),
    testing_variables_1_(),
    testing_variables_2_(),
    share_name_1_(RandomAlphaNumericString(5)) {}

 protected:
  int rights_;
  maidsafe::test::TestPath test_dir_;
  std::string keyword_1_;
  std::string pin_1_;
  std::string password_1_;
  std::string public_id_1_;
  std::string keyword_2_;
  std::string pin_2_;
  std::string password_2_;
  std::string public_id_2_;
  LifeStuff test_elements_1_;
  LifeStuff test_elements_2_;
  testresources::TestingVariables testing_variables_1_;
  testresources::TestingVariables testing_variables_2_;
  std::string share_name_1_;

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
};

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_TESTS_API_API_TEST_RESOURCES_H_

