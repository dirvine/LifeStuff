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

#include <functional>
#include <sstream>

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
#include "maidsafe/lifestuff/tests/api/api_test_resources.h"

namespace args = std::placeholders;
namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

namespace test {

TEST_F(OneUserApiTest, FUNC_CreateDirectoryLogoutLoginCheckDirectory) {
  // Create directory
  std::string tail;
  fs::path test(CreateTestDirectory(test_elements_.mount_path(), &tail));
  EXPECT_TRUE(fs::exists(test, error_code_));
  EXPECT_EQ(0, error_code_.value());

  // Log out - Log in
  EXPECT_EQ(kSuccess, test_elements_.LogOut());
  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));

  // Check directory exists
  EXPECT_TRUE(fs::exists(test, error_code_));
  EXPECT_EQ(0, error_code_.value());
}

TEST_F(OneUserApiTest, FUNC_LargeFileForMemoryCheck) {
  // Create directory
  std::string tail;
  EXPECT_EQ(kSuccess, CreateTestFile(test_elements_.mount_path(), 500, &tail));
  EXPECT_TRUE(fs::exists(test_elements_.mount_path() / tail, error_code_));
  EXPECT_EQ(0, error_code_.value());

  // Log out - Log in
  EXPECT_EQ(kSuccess, test_elements_.LogOut());
  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));

  // Check directory exists
  EXPECT_TRUE(fs::exists(test_elements_.mount_path() / tail, error_code_));
  EXPECT_EQ(0, error_code_.value());
}

TEST_F(OneUserApiTest, FUNC_TryCreateInvalidPublicId) {
  EXPECT_NE(kSuccess, test_elements_.CreatePublicId(""));
  EXPECT_NE(kSuccess, test_elements_.CreatePublicId(RandomAlphaNumericString(31)));
  EXPECT_NE(kSuccess, test_elements_.CreatePublicId(" "));
  EXPECT_NE(kSuccess,
            test_elements_.CreatePublicId(" " + RandomAlphaNumericString(RandomUint32() % 26 + 4)));
  EXPECT_NE(kSuccess,
            test_elements_.CreatePublicId(RandomAlphaNumericString(RandomUint32() % 26 + 4) + " "));
  EXPECT_NE(kSuccess,
            test_elements_.CreatePublicId(RandomAlphaNumericString(RandomUint32() % 13 + 2) + "  " +
                                          RandomAlphaNumericString(RandomUint32() % 14 + 1)));
  EXPECT_NE(kSuccess,
            test_elements_.CreatePublicId(" " + RandomAlphaNumericString(RandomUint32() % 13 + 1)
                                          + "  " +
                                          RandomAlphaNumericString(RandomUint32() % 13 + 1) + " "));
  EXPECT_EQ(kSuccess,
            test_elements_.CreatePublicId(RandomAlphaNumericString(RandomUint32() % 14 + 1) + " " +
                                          RandomAlphaNumericString(RandomUint32() % 15 + 1)));
}

TEST_F(OneUserApiTest, FUNC_CreateSamePublicIdConsecutively) {
  std::string new_public_id(RandomAlphaNumericString(6));
  EXPECT_EQ(kSuccess, test_elements_.CreatePublicId(new_public_id));
  EXPECT_NE(kSuccess, test_elements_.CreatePublicId(new_public_id));
}

TEST_F(OneUserApiTest, FUNC_CreateSamePublicIdSimultaneously) {
  std::string new_public_id(RandomAlphaNumericString(6));
  int result_1(0);
  int result_2(0);

  std::vector<std::pair<int, int> > sleep_values;
  sleep_values.push_back(std::make_pair(0, 0));
  sleep_values.push_back(std::make_pair(100, 200));
  sleep_values.push_back(std::make_pair(100, 150));
  sleep_values.push_back(std::make_pair(0, 10));

  for (size_t i = 0; i < sleep_values.size(); ++i) {
    boost::thread thread_1([&] {
                             sleepthreads::RunCreatePublicId(test_elements_,
                                                             std::ref(result_1),
                                                             new_public_id,
                                                             sleep_values.at(i));
                           });
    boost::thread thread_2([&] {
                             sleepthreads::RunCreatePublicId(test_elements_,
                                                             std::ref(result_2),
                                                             new_public_id,
                                                             sleep_values.at(i));
                           });
    thread_1.join();
    thread_2.join();

    LOG(kInfo) << "result_1: " << result_1;
    LOG(kInfo) << "result_2: " << result_2;

    EXPECT_TRUE((result_1 == kSuccess && result_2 != kSuccess) ||
                (result_1 != kSuccess && result_2 == kSuccess))
        << "Value of result 1: " << result_1 << "\nValue of result 2: " << result_2 <<
        "\nAttempt number " << i;

    EXPECT_EQ(kSuccess, test_elements_.LogOut());

    EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));

    int new_instances(0);
    std::vector<std::string>::iterator it;
    std::vector<std::string> names(test_elements_.PublicIdsList());
    for (it = names.begin(); it < names.end(); it++) {
      if (*it == new_public_id)
        ++new_instances;
    }
    EXPECT_EQ(new_instances, 1);
    new_public_id = RandomAlphaNumericString(new_public_id.length() + 1);
  }
}

TEST_F(OneUserApiTest, FUNC_AddInvalidContact) {
  std::string own_public_id(RandomAlphaNumericString(5));
  std::string public_id_1(RandomAlphaNumericString(6));
  std::string public_id_2(RandomAlphaNumericString(7));
  test_elements_.CreatePublicId(own_public_id);
  EXPECT_NE(kSuccess, test_elements_.AddContact(own_public_id, ""));
  EXPECT_NE(kSuccess, test_elements_.AddContact(own_public_id, public_id_1));
  EXPECT_NE(kSuccess, test_elements_.AddContact(public_id_1, public_id_2));
}

TEST_F(OneUserApiTest, FUNC_AddOwnPublicIdAsContact) {
  std::string public_id_1(RandomAlphaNumericString(6));
  std::string public_id_2(RandomAlphaNumericString(7));
  test_elements_.CreatePublicId(public_id_1);
  test_elements_.CreatePublicId(public_id_2);

  EXPECT_NE(kSuccess, test_elements_.AddContact(public_id_1, public_id_1));
  EXPECT_NE(kSuccess, test_elements_.AddContact(public_id_1, public_id_2));
}

TEST_F(OneUserApiTest, FUNC_ChangeProfilePictureAfterSaveSession) {
  std::string public_id(RandomAlphaNumericString(5));
  EXPECT_EQ(kSuccess, test_elements_.CreatePublicId(public_id));
  for (int n(1001); n > 1; n-=100) {
    std::string profile_picture1(RandomString(1177 * n)), profile_picture2(RandomString(1177 * n));
    EXPECT_EQ(kSuccess, test_elements_.ChangeProfilePicture(public_id, profile_picture1));
    std::string retrieved_picture(test_elements_.GetOwnProfilePicture(public_id));
    EXPECT_TRUE(profile_picture1 == retrieved_picture);
    EXPECT_EQ(kSuccess, test_elements_.LogOut());

    LOG(kError) << "\n\n\n";
    EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
    retrieved_picture = test_elements_.GetOwnProfilePicture(public_id);
    EXPECT_TRUE(profile_picture1 == retrieved_picture);
    EXPECT_EQ(kSuccess, test_elements_.ChangeProfilePicture(public_id, profile_picture2));
    retrieved_picture = test_elements_.GetOwnProfilePicture(public_id);
    EXPECT_TRUE(profile_picture2 == retrieved_picture);
    EXPECT_EQ(kSuccess, test_elements_.LogOut());

    LOG(kError) << "\n\n\n";
    EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
    retrieved_picture = test_elements_.GetOwnProfilePicture(public_id);
    EXPECT_TRUE(profile_picture2 == retrieved_picture);
    EXPECT_EQ(kSuccess, test_elements_.ChangeProfilePicture(public_id, profile_picture1));
    retrieved_picture = test_elements_.GetOwnProfilePicture(public_id);
    EXPECT_TRUE(profile_picture1 == retrieved_picture);
    EXPECT_EQ(kSuccess, test_elements_.LogOut());

    LOG(kError) << "\n\n\n";
    EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
    retrieved_picture = test_elements_.GetOwnProfilePicture(public_id);
    EXPECT_TRUE(profile_picture1 == retrieved_picture);
  }
}

TEST_F(TwoUsersApiTest, FUNC_CreateSamePublicIdConsecutively) {
  EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
  std::string new_public_id(RandomAlphaNumericString(6));

  EXPECT_EQ(kSuccess, test_elements_1_.CreatePublicId(new_public_id));
  EXPECT_NE(kSuccess, test_elements_1_.CreatePublicId(new_public_id));
  EXPECT_EQ(kSuccess, test_elements_1_.LogOut());

  EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
  EXPECT_NE(kSuccess, test_elements_2_.CreatePublicId(new_public_id));
  EXPECT_EQ(kSuccess, test_elements_2_.LogOut());

  EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
  int new_instances(0);
  std::vector<std::string>::iterator it;
  std::vector<std::string> names(test_elements_1_.PublicIdsList());
  for (it = names.begin(); it < names.end(); it++) {
    if (*it == new_public_id)
      ++new_instances;
  }
  EXPECT_EQ(new_instances, 1);
  EXPECT_EQ(kSuccess, test_elements_1_.LogOut());

  EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
  names = test_elements_2_.PublicIdsList();
  for (it = names.begin(); it < names.end(); it++) {
    if (*it == new_public_id)
      ++new_instances;
  }
  EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
}

#ifndef MAIDSAFE_APPLE
TEST_F(TwoUsersApiTest, FUNC_CreateSamePublicIdSimultaneously) {
  EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
  EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));

  std::string new_public_id(RandomAlphaNumericString(6));
  int result_1(0), result_2(0);

  std::vector<std::pair<int, int> > sleep_values;
  sleep_values.push_back(std::make_pair(0, 200));
  sleep_values.push_back(std::make_pair(100, 200));
  sleep_values.push_back(std::make_pair(100, 150));
  sleep_values.push_back(std::make_pair(0, 10));

  for (size_t i = 0; i < sleep_values.size(); ++i) {
    boost::thread thread_1([&] {
                             sleepthreads::RunCreatePublicId(test_elements_1_,
                                                             std::ref(result_1),
                                                             new_public_id,
                                                             sleep_values.at(i));
                           });
    boost::thread thread_2([&] {
                             sleepthreads::RunCreatePublicId(test_elements_2_,
                                                             std::ref(result_2),
                                                             new_public_id,
                                                             sleep_values.at(i));
                           });

    thread_1.join();
    thread_2.join();

    EXPECT_TRUE((result_1 == kSuccess && result_2 != kSuccess) ||
                (result_1 != kSuccess && result_2 == kSuccess))
        << "Value of result 1: " << result_1 << "\nValue of result 2: " << result_2 <<
        "\nAttempt number " << i;

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());

    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));

    int new_instances(0);
    std::vector<std::string>::iterator it;
    std::vector<std::string> names(test_elements_1_.PublicIdsList());
    for (it = names.begin(); it < names.end(); it++) {
      if (*it == new_public_id)
        ++new_instances;
    }
    names = test_elements_2_.PublicIdsList();
    for (it = names.begin(); it < names.end(); it++) {
      if (*it == new_public_id)
        ++new_instances;
    }
    EXPECT_EQ(new_instances, 1);
    new_public_id = RandomAlphaNumericString(new_public_id.length() + 1);
  }

  EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
}
#endif

TEST_F(TwoUsersApiTest, FUNC_SendFileSaveToGivenPath) {
  boost::system::error_code error_code;
  fs::path file_path1;
  std::string file_name1(RandomAlphaNumericString(8)),
              file_content1(RandomString(5 * 1024)),
              file_name2(RandomAlphaNumericString(8));

  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    file_path1 = test_elements_1_.mount_path() / file_name1;
    std::ofstream ofstream(file_path1.c_str(), std::ios::binary);
    ofstream << file_content1;
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements_1_.SendFile(public_id_1_, public_id_2_, file_path1));

    Sleep(bptime::seconds(2));
    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.file_transfer_received)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables_2_.file_id.empty());
    EXPECT_EQ(file_name1, testing_variables_2_.file_name);
    EXPECT_NE(kSuccess, test_elements_2_.AcceptSentFile(testing_variables_2_.file_id));
    EXPECT_NE(kSuccess, test_elements_2_.AcceptSentFile(testing_variables_2_.file_id,
                                                      test_elements_2_.mount_path() / file_name2,
                                                      &file_name2));
    EXPECT_EQ(kSuccess, test_elements_2_.AcceptSentFile(testing_variables_2_.file_id,
                                                      test_elements_2_.mount_path() / file_name2));

    EXPECT_TRUE(fs::exists(test_elements_2_.mount_path() / file_name2, error_code));
    EXPECT_EQ(0, error_code.value());

    Sleep(bptime::seconds(2));
    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_SendFileSaveToDefaultLocation) {
  boost::system::error_code error_code;
  fs::path file_path1;
  std::string file_name1(RandomAlphaNumericString(8)),
              file_content1(RandomString(5 * 1024));
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    file_path1 = test_elements_1_.mount_path() / file_name1;
    std::ofstream ofstream(file_path1.c_str(), std::ios::binary);
    ofstream << file_content1;
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements_1_.SendFile(public_id_1_, public_id_2_, file_path1));

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.file_transfer_received)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.file_id.empty());
    EXPECT_EQ(file_name1, testing_variables_2_.file_name);
    std::string saved_file_name;
    EXPECT_EQ(kSuccess, test_elements_2_.AcceptSentFile(testing_variables_2_.file_id,
                                                      fs::path(),
                                                      &saved_file_name));
    EXPECT_EQ(file_name1, saved_file_name);
    fs::path path2(test_elements_2_.mount_path() / kMyStuff / kDownloadStuff / saved_file_name);
    EXPECT_TRUE(fs::exists(path2, error_code));
    EXPECT_EQ(0, error_code.value());
    std::string file_content2;
    EXPECT_TRUE(ReadFile(path2, &file_content2));
    EXPECT_EQ(file_content1, file_content2);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    file_path1 = test_elements_1_.mount_path() / file_name1;
    std::ofstream ofstream(file_path1.c_str(), std::ios::binary);
    ofstream << file_content1;
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements_1_.SendFile(public_id_1_, public_id_2_, file_path1));

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    testing_variables_2_.file_transfer_received = false;
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.file_transfer_received)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.file_id.empty());
    EXPECT_EQ(file_name1, testing_variables_2_.file_name);
    std::string saved_file_name;
    EXPECT_EQ(kSuccess, test_elements_2_.AcceptSentFile(testing_variables_2_.file_id,
                                                      fs::path(),
                                                      &saved_file_name));
    EXPECT_EQ(file_name1 + " (1)", saved_file_name);
    fs::path path2a(test_elements_2_.mount_path() / kMyStuff / kDownloadStuff / file_name1),
             path2b(test_elements_2_.mount_path() / kMyStuff / kDownloadStuff / saved_file_name);

    EXPECT_TRUE(fs::exists(path2a, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(path2b, error_code));
    EXPECT_EQ(0, error_code.value());
    std::string file_content2;
    EXPECT_TRUE(ReadFile(path2b, &file_content2));
    EXPECT_TRUE(file_content1 == file_content2);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_SendFileAcceptToDeletedDefaultLocation) {
  boost::system::error_code error_code;
  fs::path file_path1;
  std::string file_name1(RandomAlphaNumericString(8)),
              file_content1(RandomString(5 * 1024));

  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    file_path1 = test_elements_1_.mount_path() / file_name1;
    std::ofstream ofstream(file_path1.c_str(), std::ios::binary);
    ofstream << file_content1;
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements_1_.SendFile(public_id_1_, public_id_2_, file_path1));

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    testing_variables_2_.file_transfer_received = false;
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.file_transfer_received)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.file_id.empty());
    EXPECT_EQ(file_name1, testing_variables_2_.file_name);

    // Delete accepted files dir
    fs::remove_all(test_elements_2_.mount_path() / kMyStuff, error_code);
    EXPECT_EQ(0, error_code.value());
    EXPECT_FALSE(fs::exists(test_elements_2_.mount_path() / kMyStuff, error_code));
    EXPECT_NE(0, error_code.value());

    std::string saved_file_name;
    EXPECT_EQ(kSuccess, test_elements_2_.AcceptSentFile(testing_variables_2_.file_id,
                                                      fs::path(),
                                                      &saved_file_name));
    EXPECT_EQ(file_name1, saved_file_name);
    fs::path path2(test_elements_2_.mount_path() / kMyStuff / kDownloadStuff / saved_file_name);
    EXPECT_TRUE(fs::exists(path2, error_code));
    EXPECT_EQ(0, error_code.value());
    std::string file_content2;
    EXPECT_TRUE(ReadFile(path2, &file_content2));
    EXPECT_EQ(file_content1, file_content2);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST(IndependentFullTest, FUNC_SendFileWithRejection) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string keyword1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string keyword2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  testresources::TestingVariables testing_variables1, testing_variables2;
  int file_count(0), file_max(10);
  size_t files_expected(file_max);
  std::vector<fs::path> file_paths;
  std::vector<std::string> file_contents, received_ids, received_names;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   keyword1, pin1, password1,
                                                   public_id1,
                                                   keyword2, pin2, password2,
                                                   public_id2,
                                                   true,
                                                   &received_ids,
                                                   &received_names,
                                                   &files_expected));

  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(keyword1, pin1, password1));

    for (; file_count < file_max; ++file_count) {
      file_paths.push_back(fs::path(test_elements1.mount_path() / RandomAlphaNumericString(8)));
      std::ofstream ofstream(file_paths[file_count].c_str(), std::ios::binary);
      file_contents.push_back(RandomString(5 * 1024));
      ofstream << file_contents[file_count];
      ofstream.close();
      EXPECT_TRUE(fs::exists(file_paths[file_count], error_code));
      EXPECT_EQ(0, error_code.value());
      EXPECT_EQ(kSuccess, test_elements1.SendFile(public_id1, public_id2, file_paths[file_count]));
    }

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(keyword2, pin2, password2));
    while (!testing_variables2.file_transfer_received)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(files_expected, received_ids.size());
    EXPECT_EQ(files_expected, received_names.size());
    fs::path path2(test_elements2.mount_path() / kMyStuff / kDownloadStuff);
    for (size_t st(0); st < received_ids.size(); ++st) {
      EXPECT_EQ(file_paths[st].filename().string(), received_names[st]);
      EXPECT_EQ(kSuccess, test_elements2.RejectSentFile(received_ids[st]));
      EXPECT_FALSE(fs::exists(path2 / received_names[st], error_code));
      EXPECT_NE(0, error_code.value());
      std::string hidden(received_ids[st] + kHiddenFileExtension), content;
      EXPECT_NE(kSuccess, test_elements2.ReadHiddenFile(test_elements2.mount_path() / hidden,
                                                        &content));
    }

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST_F(TwoUsersApiTest, FUNC_ProfilePicture) {
  std::string file_content1, file_content2(RandomString(5 * 1024));
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    // Setting of profile image
    EXPECT_EQ(kSuccess, test_elements_2_.ChangeProfilePicture(public_id_2_, file_content2));
    Sleep(bptime::seconds(1));

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    while (!testing_variables_1_.picture_updated)
      Sleep(bptime::milliseconds(100));

    file_content1 = test_elements_1_.GetContactProfilePicture(public_id_1_, public_id_2_);
    EXPECT_TRUE(file_content2 == file_content1);
    EXPECT_NE(kSuccess, test_elements_1_.ChangeProfilePicture(public_id_1_, ""));

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    // Setting of profile image
    EXPECT_EQ(kSuccess, test_elements_2_.ChangeProfilePicture(public_id_2_, kBlankProfilePicture));

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    testing_variables_1_.picture_updated = false;
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    while (!testing_variables_1_.picture_updated)
      Sleep(bptime::milliseconds(100));

    file_content1 = test_elements_1_.GetContactProfilePicture(public_id_1_, public_id_2_);
    EXPECT_TRUE(kBlankProfilePicture == file_content1);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_ProfilePictureAndLogOut) {
  std::string file_content1, file_content2(RandomString(5 * 1024));
  EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
  // Setting of profile image
  EXPECT_EQ(kSuccess, test_elements_2_.ChangeProfilePicture(public_id_2_, file_content2));
  EXPECT_EQ(kSuccess, test_elements_2_.LogOut());

  EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
  file_content1 = test_elements_1_.GetContactProfilePicture(public_id_1_, public_id_2_);
  EXPECT_TRUE(file_content2 == file_content1);
  EXPECT_NE(kSuccess, test_elements_1_.ChangeProfilePicture(public_id_1_, ""));
  EXPECT_EQ(kSuccess, test_elements_1_.LogOut());

  EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
  // Setting of profile image
  EXPECT_EQ(kSuccess, test_elements_2_.ChangeProfilePicture(public_id_2_, kBlankProfilePicture));
  EXPECT_EQ(kSuccess, test_elements_2_.LogOut());

  testing_variables_1_.picture_updated = false;
  EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
  file_content1 = test_elements_1_.GetContactProfilePicture(public_id_1_, public_id_2_);
  EXPECT_TRUE(kBlankProfilePicture == file_content1);
  EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
}

TEST_F(TwoUsersApiTest, FUNC_RemoveContact) {
  std::string removal_message("It's not me, it's you.");
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    EXPECT_EQ(kSuccess, test_elements_1_.RemoveContact(public_id_1_, public_id_2_,
                                                       removal_message));
    EXPECT_TRUE(test_elements_1_.GetContacts(public_id_1_).empty());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.removed)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(removal_message, testing_variables_2_.removal_message);
    bool contact_deleted(false);
    while (!contact_deleted)
      contact_deleted = test_elements_2_.GetContacts(public_id_2_).empty();
    EXPECT_TRUE(contact_deleted);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_RemoveContactAddContact) {
  for (int i = 0; i < 2; ++i) {
    std::string removal_message(RandomAlphaNumericString(RandomUint32() % 20 + 10));
    {
      EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

      EXPECT_EQ(kSuccess, test_elements_1_.RemoveContact(public_id_1_, public_id_2_,
                                                         removal_message));
      EXPECT_TRUE(test_elements_1_.GetContacts(public_id_1_).empty());

      EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
    }
    {
      EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
      while (!testing_variables_2_.removed)
        Sleep(bptime::milliseconds(100));

      EXPECT_EQ(removal_message, testing_variables_2_.removal_message);
      bool contact_deleted(false);
      while (!contact_deleted)
        contact_deleted = test_elements_2_.GetContacts(public_id_2_).empty();
      EXPECT_TRUE(contact_deleted);

      EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
    }

    const std::string request_message(RandomAlphaNumericString(RandomUint32() % 20 + 10));

    if (i % 2 == 0) {
      testing_variables_2_.newly_contacted = false;
      test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_);
      test_elements_1_.AddContact(public_id_1_, public_id_2_, request_message);
      EXPECT_EQ(kSuccess, test_elements_1_.LogOut());

      test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_);
      while (!testing_variables_2_.newly_contacted)
        Sleep(bptime::milliseconds(100));
      EXPECT_EQ(testing_variables_2_.contact_request_message, request_message);
      test_elements_2_.ConfirmContact(public_id_2_, public_id_1_);
      EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
    } else {
      testing_variables_1_.newly_contacted = false;
      test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_);
      test_elements_2_.AddContact(public_id_2_, public_id_1_, request_message);
      EXPECT_EQ(kSuccess, test_elements_2_.LogOut());

      test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_);
      while (!testing_variables_1_.newly_contacted)
        Sleep(bptime::milliseconds(100));
      EXPECT_EQ(testing_variables_1_.contact_request_message, request_message);
      test_elements_1_.ConfirmContact(public_id_1_, public_id_2_);
      EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
    }
  }
}

TEST_F(TwoUsersApiTest, FUNC_AddContactWithMessage) {
  test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_);
  const std::string public_id_3(RandomAlphaNumericString(RandomUint32() % 30 + 1));
  test_elements_1_.CreatePublicId(public_id_3);
  testing_variables_1_.newly_contacted = false;
  EXPECT_EQ(kSuccess, test_elements_1_.LogOut());

  test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_);
  const std::string message(RandomAlphaNumericString(RandomUint32() % 90 + 10));
  test_elements_2_.AddContact(public_id_2_, public_id_3, message);
  EXPECT_EQ(kSuccess, test_elements_2_.LogOut());

  test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_);
  while (!testing_variables_1_.newly_contacted)
    Sleep(bptime::milliseconds(100));
  EXPECT_EQ(testing_variables_1_.contact_request_message, message);
  test_elements_1_.ConfirmContact(public_id_1_, public_id_3);
  EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
}

TEST_F(TwoUsersApiTest, FUNC_AddThenRemoveOfflineUser) {
  test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_);

  const std::string public_id_3(RandomAlphaNumericString(RandomUint32() % 30 + 1));
  test_elements_1_.CreatePublicId(public_id_3);

  const std::string add_message(RandomAlphaNumericString(RandomUint32() % 90));
  EXPECT_EQ(kSuccess, test_elements_1_.AddContact(public_id_3, public_id_2_, add_message));

  const std::string remove_message(RandomAlphaNumericString(RandomUint32() % 90));
  EXPECT_EQ(kSuccess, test_elements_1_.RemoveContact(public_id_3, public_id_2_, remove_message));

  EXPECT_TRUE(test_elements_1_.GetContacts(public_id_3).empty());

  test_elements_1_.LogOut();

  testing_variables_2_.newly_contacted = false;
  testing_variables_2_.removed = false;
  test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_);

  int i(0);
  while (!testing_variables_2_.newly_contacted && i < 60) {
    ++i;
    Sleep(bptime::milliseconds(100));
  }
  EXPECT_TRUE(testing_variables_2_.newly_contacted);
  EXPECT_EQ(add_message, testing_variables_2_.contact_request_message);

  i = 0;
  while (!testing_variables_2_.removed && i < 60) {
    ++i;
    Sleep(bptime::milliseconds(100));
  }
  EXPECT_TRUE(testing_variables_2_.removed);
  EXPECT_EQ(remove_message, testing_variables_2_.removal_message);

  EXPECT_EQ(1, test_elements_2_.GetContacts(public_id_2_).size());

  test_elements_2_.LogOut();
}

TEST_F(TwoUsersApiTest, FUNC_CreateEmptyOpenShare) {
  std::string share_name(RandomAlphaNumericString(5)),
              file_name(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(50));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap  results;
    std::vector<std::string> contacts;
    contacts.push_back(public_id_2_);
    results.insert(std::make_pair(public_id_2_, kGeneralError));
    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyOpenShare(public_id_1_, contacts, &share_name, &results));
    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.openly_invited)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables_2_.new_open_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptOpenShareInvitation(public_id_2_,
                                                         public_id_1_,
                                                         testing_variables_2_.new_open_share_id,
                                                         &share_name));
    fs::path share(test_elements_2_.mount_path() / kSharedStuff / share_name);
    EXPECT_TRUE(fs::is_directory(share, error_code));
    fs::path file_path(share / file_name);
    EXPECT_TRUE(WriteFile(file_path, file_content1));
    EXPECT_TRUE(fs::exists(file_path, error_code));
    EXPECT_EQ(0, error_code.value());

    std::string file_content;
    EXPECT_TRUE(ReadFile(file_path, &file_content));
    EXPECT_EQ(file_content1, file_content);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    fs::path share(test_elements_1_.mount_path() / kSharedStuff / share_name);
    fs::path file_path(share / file_name);
    std::string file_content;
    EXPECT_TRUE(ReadFile(file_path, &file_content));
    EXPECT_EQ(file_content1, file_content);
    EXPECT_TRUE(WriteFile(file_path, file_content2));
    EXPECT_TRUE(ReadFile(file_path, &file_content));
    EXPECT_EQ(file_content2, file_content);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    fs::path share(test_elements_1_.mount_path() / kSharedStuff / share_name);
    fs::path file_path(share / file_name);
    std::string file_content;
    EXPECT_TRUE(ReadFile(file_path, &file_content));
    EXPECT_EQ(file_content2, file_content);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));

    fs::path share(test_elements_2_.mount_path() / kSharedStuff / share_name);
    fs::path file_path(share / file_name);
    EXPECT_TRUE(fs::exists(file_path, error_code)) << file_path;
    EXPECT_EQ(0, error_code.value());
    uintmax_t size(fs::file_size(file_path, error_code));
    EXPECT_EQ(file_content2.size(), size) << file_path;

    std::string file_content;
    EXPECT_TRUE(ReadFile(file_path, &file_content));
    EXPECT_EQ(file_content2, file_content);
    EXPECT_NE(file_content1, file_content);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_CreateOpenShare) {
  std::string directory_name(RandomAlphaNumericString(5)),
              share_name(RandomAlphaNumericString(5)),
              file1_name(RandomAlphaNumericString(5)),
              file2_name(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    fs::path directory(test_elements_1_.mount_path() /
                       kMyStuff / directory_name);
    EXPECT_TRUE(fs::create_directory(directory, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file1_path(directory / file1_name);
    EXPECT_TRUE(WriteFile(file1_path, file_content1));
    EXPECT_TRUE(fs::exists(file1_path, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path share_directory(directory / share_name);
    EXPECT_TRUE(fs::create_directory(share_directory, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file2_path(share_directory / file2_name);
    EXPECT_TRUE(WriteFile(file2_path, file_content2));
    EXPECT_TRUE(fs::exists(file2_path, error_code));
    EXPECT_EQ(0, error_code.value());

    StringIntMap  results;
    std::vector<std::string> contacts;
    contacts.push_back(public_id_2_);
    results.insert(std::make_pair(public_id_2_, kGeneralError));
    EXPECT_EQ(kSuccess, test_elements_1_.CreateOpenShareFromExistingDirectory(public_id_1_,
                                                                            share_directory,
                                                                            contacts,
                                                                            &share_name,
                                                                            &results));
    fs::path share(test_elements_1_.mount_path() / kSharedStuff / share_name);
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share / file2_name, error_code));
    EXPECT_EQ(0, error_code.value());

    int count(0), limit(30);
    while ((fs::exists(directory / share_name, error_code) && !error_code) &&
           count++ < limit) {
      Sleep(bptime::milliseconds(100));
    }
    EXPECT_FALSE(fs::exists(directory / share_name, error_code));
    EXPECT_NE(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.openly_invited)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables_2_.new_open_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.RejectOpenShareInvitation(public_id_2_,
                                                         testing_variables_2_.new_open_share_id));
    fs::path share(test_elements_2_.mount_path() / kSharedStuff / share_name),
             file_path(share / file2_name);
    EXPECT_FALSE(fs::exists(share, error_code));
    EXPECT_NE(0, error_code.value());
    EXPECT_FALSE(fs::exists(file_path, error_code));
    EXPECT_NE(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    fs::path share(test_elements_1_.mount_path() / kSharedStuff / share_name);
    fs::path file_path(share / file2_name);
    std::string file_stuff;
    EXPECT_TRUE(ReadFile(file_path, &file_stuff));
    EXPECT_EQ(file_content2, file_stuff);
    EXPECT_TRUE(WriteFile(file_path, file_content1));

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_InviteOpenShareMembers) {
  std::string directory_name(RandomAlphaNumericString(5)),
              share1_name(RandomAlphaNumericString(5)),
              share2_name(RandomAlphaNumericString(5)),
              file1_name(RandomAlphaNumericString(5)),
              file2_name(RandomAlphaNumericString(5)),
              file3_name(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20)),
              file_content3(RandomString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    fs::path directory(test_elements_1_.mount_path() / kMyStuff / directory_name);
    EXPECT_TRUE(fs::create_directory(directory, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file1_path(directory / file1_name);
    EXPECT_TRUE(WriteFile(file1_path, file_content1));
    EXPECT_TRUE(fs::exists(file1_path, error_code));
    EXPECT_EQ(0, error_code.value());

    fs::path share_directory1(directory / share1_name);
    EXPECT_TRUE(fs::create_directory(share_directory1, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file2_path(share_directory1 / file2_name);
    EXPECT_TRUE(WriteFile(file2_path, file_content2));
    EXPECT_TRUE(fs::exists(file2_path, error_code));
    EXPECT_EQ(0, error_code.value());

    fs::path share_directory2(directory / share2_name);
    EXPECT_TRUE(fs::create_directory(share_directory2, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file3_path(share_directory2 / file3_name);
    EXPECT_TRUE(WriteFile(file3_path, file_content3));
    EXPECT_TRUE(fs::exists(file3_path, error_code));
    EXPECT_EQ(0, error_code.value());

    StringIntMap  results;
    std::vector<std::string> contacts;
    contacts.push_back(public_id_2_);
    results.insert(std::make_pair(public_id_2_, kGeneralError));
    EXPECT_EQ(kSuccess, test_elements_1_.CreateOpenShareFromExistingDirectory(public_id_1_,
                                                                              share_directory1,
                                                                              contacts,
                                                                              &share1_name,
                                                                              &results));
    fs::path share(test_elements_1_.mount_path() / kSharedStuff / share1_name);
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share / file2_name, error_code));
    EXPECT_EQ(0, error_code.value());

    int count(0), limit(30);
    while ((fs::exists(directory / share1_name, error_code) && !error_code) && count++ < limit)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::exists(directory / share1_name, error_code));
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.openly_invited)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables_2_.new_open_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.RejectOpenShareInvitation(public_id_2_,
                                                         testing_variables_2_.new_open_share_id));
    fs::path share(test_elements_2_.mount_path() / kSharedStuff / share1_name),
             file_path(share / file2_name);
    EXPECT_FALSE(fs::exists(share, error_code));
    EXPECT_NE(0, error_code.value());
    EXPECT_FALSE(fs::exists(file_path, error_code));
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    fs::path share1(test_elements_1_.mount_path() / kSharedStuff / share1_name);
    fs::path file_path(share1 / file2_name);
    std::string file_stuff;
    EXPECT_TRUE(ReadFile(file_path, &file_stuff));
    EXPECT_EQ(file_content2, file_stuff);
    EXPECT_TRUE(WriteFile(file_path, file_content1));

    fs::path directory(test_elements_1_.mount_path() / kMyStuff / directory_name);
    StringIntMap results;
    std::vector<std::string> contacts;
    fs::path share_directory2(directory / share2_name);
    EXPECT_EQ(kSuccess, test_elements_1_.CreateOpenShareFromExistingDirectory(public_id_1_,
                                                                              share_directory2,
                                                                              contacts,
                                                                              &share2_name,
                                                                              &results));
    fs::path share2(test_elements_1_.mount_path() / kSharedStuff / share2_name);
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    EXPECT_TRUE(fs::exists(share2, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share2 / file3_name, error_code));
    EXPECT_EQ(0, error_code.value());

    int count(0), limit(30);
    while (fs::exists(directory / share2_name, error_code) && !error_code && count++ < limit)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::exists(directory / share2_name, error_code));
    EXPECT_NE(0, error_code.value());

    std::vector<std::string> shares;
    EXPECT_EQ(kSuccess, test_elements_1_.GetOpenShareList(public_id_1_, &shares));
    EXPECT_EQ(2, shares.size());

    StringIntMap members;
    EXPECT_EQ(kSuccess, test_elements_1_.GetOpenShareMembers(public_id_1_, share2_name, &members));
    EXPECT_EQ(0, members.size());

    contacts.push_back(public_id_2_);
    results.insert(std::make_pair(public_id_2_, kGeneralError));
    EXPECT_EQ(kSuccess,
              test_elements_1_.InviteMembersToOpenShare(public_id_1_, contacts, share2_name,
                                                        &results));
    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.openly_invited)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables_2_.new_open_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptOpenShareInvitation(public_id_2_,
                                                       public_id_1_,
                                                       testing_variables_2_.new_open_share_id,
                                                       &share2_name));
    fs::path share(test_elements_2_.mount_path() / kSharedStuff / share2_name),
             file_path(share / file3_name);
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(file_path, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(WriteFile(file_path, file_content2));

    std::vector<std::string> shares;
    EXPECT_EQ(kSuccess, test_elements_2_.GetOpenShareList(public_id_2_, &shares));
    EXPECT_EQ(1, shares.size());

    StringIntMap members;
    EXPECT_EQ(kSuccess, test_elements_2_.GetOpenShareMembers(public_id_2_, share2_name, &members));
    EXPECT_EQ(1, members.size());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_LeaveOpenShare) {
  std::string directory_name(RandomAlphaNumericString(5)),
              share_name(RandomAlphaNumericString(5)),
              file1_name(RandomAlphaNumericString(5)),
              file2_name(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    fs::path directory(test_elements_1_.mount_path() / kMyStuff / directory_name);
    EXPECT_TRUE(fs::create_directory(directory, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file1_path(directory / file1_name);
    EXPECT_TRUE(WriteFile(file1_path, file_content1));
    EXPECT_TRUE(fs::exists(file1_path, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path share_directory(directory / share_name);
    EXPECT_TRUE(fs::create_directory(share_directory, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file2_path(share_directory / file2_name);
    EXPECT_TRUE(WriteFile(file2_path, file_content2));
    EXPECT_TRUE(fs::exists(file2_path, error_code));
    EXPECT_EQ(0, error_code.value());

    StringIntMap  results;
    std::vector<std::string> contacts;
    contacts.push_back(public_id_2_);
    results.insert(std::make_pair(public_id_2_, kGeneralError));
    EXPECT_EQ(kSuccess, test_elements_1_.CreateOpenShareFromExistingDirectory(public_id_1_,
                                                                              share_directory,
                                                                              contacts,
                                                                              &share_name,
                                                                              &results));
    fs::path share(test_elements_1_.mount_path() / kSharedStuff / share_name);
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share / file2_name, error_code));
    EXPECT_EQ(0, error_code.value());

    int count(0), limit(30);
    while ((fs::exists(directory / share_name, error_code) && !error_code) && count++ < limit)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::exists(directory / share_name, error_code));
    EXPECT_NE(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.openly_invited)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables_2_.new_open_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptOpenShareInvitation(public_id_2_,
                                                         public_id_1_,
                                                         testing_variables_2_.new_open_share_id,
                                                         &share_name));
    fs::path share(test_elements_2_.mount_path() / kSharedStuff / share_name),
             file_path(share / file2_name);
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(file_path, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    fs::path share(test_elements_1_.mount_path() / kSharedStuff / share_name);
    fs::path file_path(share / file2_name);
    std::string file_stuff;
    EXPECT_TRUE(ReadFile(file_path, &file_stuff));
    EXPECT_EQ(file_content2, file_stuff);
    EXPECT_TRUE(WriteFile(file_path, file_content1));

    EXPECT_EQ(kSuccess, test_elements_1_.LeaveOpenShare(public_id_1_, share_name));
    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    fs::path share(test_elements_2_.mount_path() / kSharedStuff / share_name),
             file_path(share / file2_name);
    std::string file_stuff;
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(file_path, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(ReadFile(file_path, &file_stuff));
    EXPECT_EQ(file_content1, file_stuff);

    std::vector<std::string> shares;
    EXPECT_EQ(kSuccess, test_elements_2_.GetOpenShareList(public_id_2_, &shares));
    EXPECT_EQ(1, shares.size());

    StringIntMap members;
    EXPECT_EQ(kSuccess, test_elements_2_.GetOpenShareMembers(public_id_2_, share_name, &members));
    EXPECT_EQ(0, members.size());

    EXPECT_EQ(kSuccess, test_elements_2_.LeaveOpenShare(public_id_2_, share_name));
    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_SameOpenShareName) {
  std::string directory0_name(RandomAlphaNumericString(5)),
              directory1_name(RandomAlphaNumericString(5)),
              directory2_name(RandomAlphaNumericString(5)),
              directory3_name(RandomAlphaNumericString(5)),
              directory4_name(RandomAlphaNumericString(5)),
              file1_name(RandomAlphaNumericString(5)),
              file2_name(RandomAlphaNumericString(5)),
              file3_name(RandomAlphaNumericString(5)),
              file4_name(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20)),
              file_content3(RandomString(20)),
              file_content4(RandomString(20)),
              share_name(RandomAlphaNumericString(5)),
              stored_share_name(share_name);
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    fs::path directory0(test_elements_1_.mount_path() / kMyStuff / directory0_name);
    EXPECT_TRUE(fs::create_directory(directory0, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path directory1(directory0 / directory1_name);
    EXPECT_TRUE(fs::create_directory(directory1, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path directory2(directory0 / directory2_name);
    EXPECT_TRUE(fs::create_directory(directory2, error_code));
    EXPECT_EQ(0, error_code.value());

    fs::path share_directory1(directory1 / share_name);
    EXPECT_TRUE(fs::create_directory(share_directory1, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path share_directory2(directory2 / share_name);
    EXPECT_TRUE(fs::create_directory(share_directory2, error_code));
    EXPECT_EQ(0, error_code.value());

    fs::path file1_path(share_directory1 / file1_name);
    EXPECT_TRUE(WriteFile(file1_path, file_content1));
    EXPECT_TRUE(fs::exists(file1_path, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file2_path(share_directory2 / file2_name);
    EXPECT_TRUE(WriteFile(file2_path, file_content2));
    EXPECT_TRUE(fs::exists(file2_path, error_code));
    EXPECT_EQ(0, error_code.value());

    fs::path directory3(share_directory1 / directory3_name);
    EXPECT_TRUE(fs::create_directory(directory3, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path directory4(share_directory2 / directory4_name);
    EXPECT_TRUE(fs::create_directory(directory4, error_code));
    EXPECT_EQ(0, error_code.value());

    fs::path file3_path(directory3 / file3_name);
    EXPECT_TRUE(WriteFile(file3_path, file_content3));
    EXPECT_TRUE(fs::exists(file3_path, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file4_path(directory4 / file4_name);
    EXPECT_TRUE(WriteFile(file4_path, file_content4));
    EXPECT_TRUE(fs::exists(file4_path, error_code));
    EXPECT_EQ(0, error_code.value());

    StringIntMap  results;
    std::vector<std::string> contacts;
    EXPECT_EQ(kSuccess, test_elements_1_.CreateOpenShareFromExistingDirectory(public_id_1_,
                                                                              share_directory1,
                                                                              contacts,
                                                                              &share_name,
                                                                              &results));
    fs::path share1(test_elements_1_.mount_path() / kSharedStuff / share_name);
    EXPECT_TRUE(fs::exists(share1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share1 / file1_name, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(stored_share_name, share_name);

    int count(0), limit(30);
    while ((fs::exists(directory1 / share_name, error_code) && !error_code) && count++ < limit)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::exists(directory1 / share_name, error_code));
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_1_.CreateOpenShareFromExistingDirectory(public_id_1_,
                                                                              share_directory2,
                                                                              contacts,
                                                                              &share_name,
                                                                              &results));
    fs::path share2(test_elements_1_.mount_path() / kSharedStuff / share_name);
    EXPECT_TRUE(fs::exists(share2, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share2 / file2_name, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_NE(stored_share_name, share_name);
    EXPECT_EQ(stored_share_name + " (1)", share_name);

    EXPECT_FALSE(fs::exists(directory2 / share_name, error_code));
    EXPECT_NE(0, error_code.value());

    std::vector<std::string> shares;
    EXPECT_EQ(kSuccess, test_elements_1_.GetOpenShareList(public_id_1_, &shares));
    EXPECT_EQ(2, shares.size());

    StringIntMap members;
    EXPECT_EQ(kSuccess, test_elements_1_.GetOpenShareMembers(public_id_1_, share_name, &members));
    EXPECT_EQ(0, members.size());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
}

INSTANTIATE_TEST_CASE_P(ReadOnlyReadWrite,
                        PrivateSharesApiTest,
                        testing::Values(kShareReadOnly, kShareReadWrite));

TEST_P(PrivateSharesApiTest, FUNC_CreateEmptyPrivateShare) {
  std::string file_name1(RandomAlphaNumericString(5)),
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, rights_));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyPrivateShare(public_id_1_, contacts,
                                                       &share_name_1_, &results));

    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(share_name_1_, testing_variables_2_.new_private_share_name);
    EXPECT_EQ(rights_, testing_variables_2_.new_private_access_level);
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name_1_));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));

    fs::path a_file_path(share_path / file_name1);
    if (rights_ == kShareReadOnly) {
      EXPECT_FALSE(WriteFile(a_file_path, file_content2));
      EXPECT_FALSE(fs::exists(a_file_path, error_code));
      EXPECT_NE(0, error_code.value());
    } else {
      EXPECT_TRUE(WriteFile(a_file_path, file_content2));
      EXPECT_TRUE(fs::exists(a_file_path, error_code));
      EXPECT_EQ(0, error_code.value());
    }

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name_1_);
    fs::path a_file_path(share_path / file_name1);
    if (rights_ == kShareReadOnly) {
      EXPECT_TRUE(WriteFile(a_file_path, file_content1));
      EXPECT_TRUE(fs::exists(a_file_path, error_code));
      EXPECT_EQ(0, error_code.value());
    } else {
      std::string file_stuff;
      EXPECT_TRUE(ReadFile(a_file_path, &file_stuff));
      EXPECT_EQ(file_content2, file_stuff);
      EXPECT_TRUE(WriteFile(a_file_path, file_content1));
      EXPECT_TRUE(fs::exists(a_file_path, error_code));
    }

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
    fs::path a_file_path(share_path / file_name1);
    EXPECT_TRUE(fs::exists(a_file_path, error_code)) << a_file_path;
    EXPECT_EQ(0, error_code.value());

    std::string a_file_content;
    EXPECT_TRUE(ReadFile(a_file_path, &a_file_content));
    EXPECT_EQ(file_content1, a_file_content);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_P(PrivateSharesApiTest, FUNC_FromExistingDirectoryPrivateShare) {
  std::string file_name1(RandomAlphaNumericString(5)),
              file_name2(RandomAlphaNumericString(5)),
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create directory with contents to share
    fs::path share_path(test_elements_1_.mount_path() / kMyStuff / share_name_1_);
    fs::create_directories(share_path, error_code);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value()) << share_path;
    EXPECT_TRUE(WriteFile(share_path / file_name1, file_content1)) << (share_path / file_name1);


    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, rights_));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreatePrivateShareFromExistingDirectory(public_id_1_,
                                                                                 share_path,
                                                                                 contacts,
                                                                                 &share_name_1_,
                                                                                 &results));

    int count(0), limit(30);
    while ((fs::exists(share_path, error_code) && !error_code) && count++ < limit)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::exists(share_path, error_code)) << share_path;
    share_path = test_elements_1_.mount_path() / kSharedStuff / share_name_1_;
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(share_name_1_, testing_variables_2_.new_private_share_name);
    EXPECT_EQ(rights_, testing_variables_2_.new_private_access_level);
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name_1_));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));
    EXPECT_EQ(0, error_code.value());

    // Read the existing file
    std::string file_in_share_content;
    EXPECT_TRUE(ReadFile(share_path / file_name1, &file_in_share_content));
    EXPECT_EQ(file_content1, file_in_share_content);

    fs::path a_file_path(share_path / file_name2);
    if (rights_ == kShareReadOnly) {
      EXPECT_FALSE(WriteFile(a_file_path, file_content2));
      EXPECT_FALSE(fs::exists(a_file_path, error_code));
      EXPECT_NE(0, error_code.value());
    } else {
      EXPECT_TRUE(WriteFile(a_file_path, file_content2));
      EXPECT_TRUE(fs::exists(a_file_path, error_code));
      EXPECT_EQ(0, error_code.value());
    }

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name_1_);
    fs::path a_file_path(share_path / file_name2);
    std::string file_stuff;
    if (rights_ == kShareReadOnly) {
      EXPECT_FALSE(ReadFile(a_file_path, &file_stuff));
      EXPECT_TRUE(file_stuff.empty());
    } else {
      EXPECT_TRUE(ReadFile(a_file_path, &file_stuff));
      EXPECT_EQ(file_content2, file_stuff);
    }
    EXPECT_TRUE(WriteFile(a_file_path, file_content1));
    EXPECT_TRUE(fs::exists(a_file_path, error_code));

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
    fs::path a_file_path(share_path / file_name2);
    std::string a_file_content;

    EXPECT_TRUE(ReadFile(a_file_path, &a_file_content));
    EXPECT_EQ(file_content1, a_file_content);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_P(PrivateSharesApiTest, FUNC_RejectInvitationPrivateShare) {
  std::string file_name1(RandomAlphaNumericString(5)),
              file_content1(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create directory with contents to share
    fs::path share_path(test_elements_1_.mount_path() / kMyStuff / share_name_1_);
    fs::create_directories(share_path, error_code);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value()) << share_path;
    EXPECT_TRUE(WriteFile(share_path / file_name1, file_content1)) << (share_path / file_name1);


    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, rights_));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreatePrivateShareFromExistingDirectory(public_id_1_,
                                                                                 share_path,
                                                                                 contacts,
                                                                                 &share_name_1_,
                                                                                 &results));

    int count(0), limit(30);
    while ((fs::exists(share_path, error_code) && !error_code) && count++ < limit)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::exists(share_path, error_code)) << share_path;
    share_path = test_elements_1_.mount_path() / kSharedStuff / share_name_1_;
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.RejectPrivateShareInvitation(
              public_id_2_, testing_variables_2_.new_private_share_id));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_FALSE(fs::exists(share_path, error_code));
    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_P(PrivateSharesApiTest, FUNC_DeletePrivateShare) {
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, rights_));  // Read only rights
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyPrivateShare(public_id_1_, contacts,
                                                       &share_name_1_, &results));

    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name_1_));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));
    EXPECT_EQ(0, error_code.value());

    // Check only owner can delete
    EXPECT_NE(kSuccess, test_elements_2_.DeletePrivateShare(public_id_2_, share_name_1_, true));
    EXPECT_TRUE(fs::is_directory(share_path, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    EXPECT_EQ(kSuccess, test_elements_1_.DeletePrivateShare(public_id_1_, share_name_1_, false));
    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.private_share_deleted)
      Sleep(bptime::milliseconds(100));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_FALSE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_P(PrivateSharesApiTest, FUNC_LeavePrivateShare) {
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, rights_));  // Read only rights
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyPrivateShare(public_id_1_, contacts,
                                                       &share_name_1_, &results));

    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);

    // Check owner can't leave
    EXPECT_EQ(kOwnerTryingToLeave, test_elements_1_.LeavePrivateShare(public_id_1_, share_name_1_));
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name_1_));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LeavePrivateShare(public_id_2_, share_name_1_));

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    // TODO(Team): Wait till message from member arrives
    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));

    // Still using share_id to identify the share, instead of share_name
    // And when leaving, Deletion Signal won't get fired
//     EXPECT_EQ(share_name_1_, testing_variables2.deleted_private_share_name);
    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_FALSE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_RenamePrivateShare) {
  std::string share_name1(RandomAlphaNumericString(5)),
              share_name2(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_content2(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyPrivateShare(public_id_1_, contacts,
                                                       &share_name1, &results));
    EXPECT_EQ(kSuccess, results[public_id_2_]);

    EXPECT_EQ(kSuccess, test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1,
                                                                &results));
    EXPECT_EQ(1U, results.size());
    EXPECT_TRUE(results.end() == results.find(public_id_1_));
    EXPECT_EQ(kShareReadWriteUnConfirmed, results.find(public_id_2_)->second);

    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name1));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));

    fs::path a_file_path(share_path / file_name1);
    EXPECT_TRUE(WriteFile(a_file_path, file_content2));
    EXPECT_TRUE(fs::exists(a_file_path, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap results;
    EXPECT_EQ(kSuccess, test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                                                share_name1,
                                                                &results));
    EXPECT_EQ(1U, results.size());
    EXPECT_TRUE(results.end() == results.find(public_id_1_));
    EXPECT_FALSE(results.end() == results.find(public_id_2_));
    fs::path old_share_path(test_elements_1_.mount_path() / kSharedStuff / share_name1);
    fs::path new_share_path(test_elements_1_.mount_path() / kSharedStuff / share_name2);
    fs::rename(old_share_path, new_share_path, error_code);
    EXPECT_EQ(0, error_code.value());
    while (!testing_variables_1_.share_renamed)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::is_directory(old_share_path, error_code));
    fs::path a_file_path(new_share_path / file_name1);
    std::string local_content;
    EXPECT_TRUE(ReadFile(a_file_path, &local_content));
    EXPECT_EQ(file_content2, local_content);

    EXPECT_EQ(share_name1, testing_variables_1_.old_share_name);
    EXPECT_EQ(share_name2, testing_variables_1_.new_share_name);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    fs::path new_share_path(test_elements_2_.mount_path() / kSharedStuff / share_name2);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));
    EXPECT_FALSE(fs::is_directory(new_share_path, error_code));

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  std::string sub_directory_name(RandomAlphaNumericString(8));
  std::string new_sub_directory_name(RandomAlphaNumericString(8));
  std::string new_file_name(RandomAlphaNumericString(8));
  {
    testing_variables_1_.share_renamed = false;
    testing_variables_1_.old_share_name.clear();
    testing_variables_1_.new_share_name.clear();

    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name2);
    fs::path sub_directory(share_path / sub_directory_name);
    EXPECT_TRUE(fs::create_directory(sub_directory, error_code));
    EXPECT_TRUE(fs::exists(sub_directory, error_code));

    // This additional sleep is required as the merging of directory_listing has a gap of 1.5s
    // because of the UTC time being used (rounded to seconds)
    Sleep(bptime::seconds(2));

    fs::path sub_directory_new(share_path / new_sub_directory_name);
    fs::rename(sub_directory, sub_directory_new, error_code);

    fs::path a_file_path(share_path / file_name1);
    fs::path new_a_file_path(share_path / new_file_name);
    fs::rename(a_file_path, new_a_file_path, error_code);

    Sleep(bptime::seconds(1));
    EXPECT_FALSE(testing_variables_1_.share_renamed);
    EXPECT_TRUE(testing_variables_1_.old_share_name.empty());
    EXPECT_TRUE(testing_variables_1_.new_share_name.empty());

    EXPECT_TRUE(fs::exists(sub_directory_new, error_code));
    EXPECT_FALSE(fs::exists(sub_directory, error_code));
    EXPECT_TRUE(fs::exists(new_a_file_path, error_code));
    EXPECT_FALSE(fs::exists(a_file_path, error_code));

    std::string local_content;
    EXPECT_TRUE(ReadFile(new_a_file_path, &local_content));
    EXPECT_EQ(file_content2, local_content);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    fs::path sub_directory(share_path / sub_directory_name);
    fs::path sub_directory_new(share_path / new_sub_directory_name);
    fs::path a_file_path(share_path / file_name1);
    fs::path a_file_path_new(share_path / new_file_name);

    EXPECT_TRUE(fs::exists(sub_directory_new, error_code));
    EXPECT_FALSE(fs::exists(sub_directory, error_code));
    EXPECT_TRUE(fs::exists(a_file_path_new, error_code));
    EXPECT_FALSE(fs::exists(a_file_path, error_code));

    std::string local_content;
    EXPECT_TRUE(ReadFile(a_file_path_new, &local_content));
    EXPECT_EQ(file_content2, local_content);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_P(PrivateSharesApiTest, FUNC_CreateDeletePrivateShare) {
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, rights_));  // Read only rights
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name_1_,
                                                                 &results));
    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name_1_),
             my_path(test_elements_1_.mount_path() / kMyStuff / share_name_1_);
    EXPECT_TRUE(fs::exists(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    EXPECT_EQ(kSuccess, test_elements_1_.DeletePrivateShare(public_id_1_,
                                                            share_name_1_,
                                                            false));

    int count(0), limit(30);
    while ((fs::exists(share_path, error_code) && !error_code) && count++ < limit)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::exists(share_path, error_code)) << share_path;
    EXPECT_NE(0, error_code.value());
    EXPECT_TRUE(fs::exists(my_path, error_code)) << my_path;
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(
        kNoShareTarget,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name_1_));
    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_FALSE(fs::exists(share_path, error_code));
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_MembershipDowngradePrivateShare) {
  std::string share_name1(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyPrivateShare(public_id_1_, contacts,
                                                       &share_name1, &results));
    EXPECT_EQ(kSuccess, results[public_id_2_]);

    EXPECT_EQ(kSuccess, test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1,
                                                                &results));
    EXPECT_EQ(1U, results.size());
    EXPECT_TRUE(results.end() == results.find(public_id_1_));
    EXPECT_EQ(kShareReadWriteUnConfirmed, results.find(public_id_2_)->second);

    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name1));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));

    fs::path a_file_path(share_path / file_name1);
    EXPECT_TRUE(WriteFile(a_file_path, file_content2));
    EXPECT_TRUE(fs::exists(a_file_path, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap results;
    EXPECT_EQ(kSuccess, test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                                                share_name1,
                                                                &results));
    EXPECT_EQ(1U, results.size());
    EXPECT_TRUE(results.end() == results.find(public_id_1_));
    EXPECT_FALSE(results.end() == results.find(public_id_2_));

    StringIntMap amendments;
    results.clear();
    amendments.insert(std::make_pair(public_id_2_, kShareReadOnly));
    EXPECT_EQ(kSuccess, test_elements_1_.EditPrivateShareMembers(public_id_1_,
                                                                 amendments,
                                                                 share_name1,
                                                                 &results));
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    results[public_id_2_] = -1;
    EXPECT_EQ(kSuccess, test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                                                share_name1,
                                                                &results));
    EXPECT_EQ(0, results[public_id_2_]);  // ro now

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.private_member_access_changed)
      Sleep(bptime::milliseconds(100));
    StringIntMap shares;
    EXPECT_EQ(kSuccess, test_elements_2_.GetPrivateShareList(public_id_2_, &shares));

    EXPECT_EQ(1U, shares.size());
    EXPECT_FALSE(shares.find(share_name1) == shares.end());
    EXPECT_EQ(kShareReadOnly, shares[share_name1]);

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    fs::path a_file_path(share_path / file_name1);
    EXPECT_FALSE(WriteFile(a_file_path, file_content1));

    std::string local_content;
    EXPECT_TRUE(ReadFile(a_file_path, &local_content));
    EXPECT_EQ(file_content2, local_content);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_MembershipUpgradePrivateShare) {
  std::string share_name1(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_content2(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadOnly));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyPrivateShare(public_id_1_, contacts,
                                                       &share_name1, &results));

    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name1));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));

    fs::path a_file_path(share_path / file_name1);
    EXPECT_FALSE(WriteFile(a_file_path, file_content2));
    EXPECT_FALSE(fs::exists(a_file_path, error_code));
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap amendments, results;
    amendments.insert(std::make_pair(public_id_2_, kShareReadWrite));
    EXPECT_EQ(kSuccess, test_elements_1_.EditPrivateShareMembers(public_id_1_,
                                                                 amendments,
                                                                 share_name1,
                                                                 &results));
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    results[public_id_2_] = -1;
    EXPECT_EQ(kSuccess, test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1,
                                                                &results));
    EXPECT_EQ(kShareReadWrite, results[public_id_2_]);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));

    while (!testing_variables_2_.private_member_access_changed)
      Sleep(bptime::milliseconds(100));
    StringIntMap shares;
    EXPECT_EQ(kSuccess, test_elements_2_.GetPrivateShareList(public_id_2_, &shares));

    EXPECT_EQ(1U, shares.size());
    EXPECT_FALSE(shares.find(share_name1) == shares.end());
    EXPECT_EQ(kShareReadWrite, shares[share_name1]);

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    fs::path a_file_path(share_path / file_name1);
    EXPECT_TRUE(WriteFile(a_file_path, file_content2));
    EXPECT_TRUE(fs::exists(a_file_path, error_code));
    EXPECT_EQ(0, error_code.value());

    std::string local_content;
    EXPECT_TRUE(ReadFile(a_file_path, &local_content));
    EXPECT_EQ(file_content2, local_content);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_PrivateShareOwnerRemoveNonOwnerContact) {
  std::string removal_message("It's not me, it's you.");
  std::string share_name1(RandomAlphaNumericString(5));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadOnly));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name1,
                                                                 &results));

    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;

    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1, &shares_members);
    EXPECT_EQ(1, shares_members.size());
    EXPECT_EQ(kShareReadOnlyUnConfirmed, shares_members.find(public_id_2_)->second);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptPrivateShareInvitation(
                  public_id_2_,
                  public_id_1_,
                  testing_variables_2_.new_private_share_id,
                  &share_name1));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap results;
    EXPECT_EQ(kSuccess, test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                                                share_name1,
                                                                &results));
    EXPECT_EQ(1U, results.size());

    EXPECT_EQ(kSuccess, test_elements_1_.RemoveContact(public_id_1_,
                                                       public_id_2_,
                                                       removal_message));
    EXPECT_TRUE(test_elements_1_.GetContacts(public_id_1_).empty());
    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1, &shares_members);
    EXPECT_EQ(0, shares_members.size());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.removed)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(removal_message, testing_variables_2_.removal_message);
    bool contact_deleted(false);
    while (!contact_deleted)
      contact_deleted = test_elements_2_.GetContacts(public_id_2_).empty();
    EXPECT_TRUE(contact_deleted);

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(fs::is_directory(share_path, error_code));

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_PrivateShareNonOwnerRemoveOwnerContact) {
  std::string removal_message("It's not me, it's you.");
  std::string share_name1(RandomAlphaNumericString(5));
  fs::path directory1, directory2;
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadOnly));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyPrivateShare(public_id_1_, contacts,
                                                       &share_name1, &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;

    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1, &shares_members);
    EXPECT_EQ(1, shares_members.size());
    EXPECT_EQ(kShareReadOnlyUnConfirmed, shares_members.find(public_id_2_)->second);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name1));
    directory2 = test_elements_2_.mount_path()/ kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    EXPECT_EQ(kSuccess, test_elements_2_.RemoveContact(public_id_2_, public_id_1_,
                                                       removal_message));
    EXPECT_TRUE(test_elements_2_.GetContacts(public_id_2_).empty());
    // OS will cache the directory info for about 1 seconds
    while (fs::exists(directory2, error_code))
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(fs::is_directory(directory2, error_code)) << directory2;

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    while (!testing_variables_1_.removed)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(removal_message, testing_variables_1_.removal_message);
    bool contact_deleted(false);
    while (!contact_deleted)
      contact_deleted = test_elements_1_.GetContacts(public_id_1_).empty();
    EXPECT_TRUE(contact_deleted);

    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1, &shares_members);
    EXPECT_EQ(0, shares_members.size());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_PrivateShareNonOwnerRemoveNonOwnerContact) {
  LifeStuff test_elements3;
  testresources::TestingVariables testing_variables3;
  std::string keyword3(RandomAlphaNumericString(6)),
              pin3(CreatePin()),
              password3(RandomAlphaNumericString(6)),
              public_id3(RandomAlphaNumericString(5));
  test_elements3.Initialise(*test_dir_);
  test_elements3.ConnectToSignals(
        [&] (const std::string& own_public_id,
             const std::string& contact_public_id,
             const std::string& signal_message,
             const std::string& timestamp) {
          testresources::ChatSlot(own_public_id, contact_public_id, signal_message,
                                  timestamp,
                                  &testing_variables3.chat_message,
                                  &testing_variables3.chat_message_received);
        },
        [&] (const std::string& own_public_id,
             const std::string& contact_public_id,
             const std::string& signal_file_name,
             const std::string& signal_file_id,
             const std::string& timestamp) {
          testresources::FileTransferSlot(own_public_id, contact_public_id, signal_file_name,
                                          signal_file_id,
                                          timestamp,
                                          &testing_variables3.file_name,
                                          &testing_variables3.file_id,
                                          &testing_variables3.file_transfer_received);
        },
        [&] (const std::string& own_public_id,
             const std::string& contact_public_id,
             const std::string& message,
             const std::string& timestamp) {
          testresources::NewContactSlot(own_public_id, contact_public_id, message, timestamp,
                                        &testing_variables3.newly_contacted,
                                        &testing_variables3.contact_request_message);
        },
        [&] (const std::string& own_public_id,
             const std::string& contact_public_id,
             const std::string& timestamp) {
          testresources::ContactConfirmationSlot(own_public_id, contact_public_id, timestamp,
                                                 &testing_variables3.confirmed);
        },
        [&] (const std::string& own_public_id,
             const std::string& contact_public_id,
             const std::string& timestamp) {
          testresources::ContactProfilePictureSlot(own_public_id, contact_public_id,
                                                   timestamp,
                                                   &testing_variables3.picture_updated);
        },
        [&] (const std::string& own_public_id,
             const std::string& contact_public_id,
             const std::string& timestamp,
            ContactPresence cp) {
          testresources::ContactPresenceSlot(own_public_id, contact_public_id, timestamp, cp,
                                             &testing_variables3.presence_announced);
        },
        [&] (const std::string& own_public_id,
             const std::string& contact_public_id,
             const std::string& signal_message,
             const std::string& timestamp) {
          testresources::ContactDeletionSlot(own_public_id, contact_public_id,
                                             signal_message,
                                             timestamp,
                                             &testing_variables3.removal_message,
                                             &testing_variables3.removed);
},
        [&] (const std::string& own_public_id,
             const std::string& contact_public_id,
             const std::string& signal_share_name,
             const std::string& signal_share_id,
             int access_level,
             const std::string& timestamp) {
          testresources::PrivateShareInvitationSlot(
              own_public_id, contact_public_id, signal_share_name, signal_share_id, access_level,
              timestamp,
              &testing_variables3.new_private_share_name,
              &testing_variables3.new_private_share_id,
              &testing_variables3.new_private_access_level,
              &testing_variables3.privately_invited);
        },
        [&] (const std::string& own_public_id,
             const std::string& contact_public_id,
             const std::string& signal_share_name,
             const std::string& signal_share_id,
             const std::string& timestamp) {
          testresources::PrivateShareDeletionSlot(
              own_public_id, contact_public_id, signal_share_name, signal_share_id, timestamp,
              &testing_variables3.deleted_private_share_name,
              &testing_variables3.private_share_deleted);
        },
        [&] (const std::string& own_public_id,
             const std::string& contact_public_id,
             const std::string& signal_share_name,
             const std::string& signal_share_id,
             int signal_member_access,
             const std::string /*&timestamp*/) {
          testresources::PrivateMemberAccessChangeSlot(
              own_public_id, contact_public_id, signal_share_name, signal_share_id,
              signal_member_access,
              testing_variables3.access_private_share_name,
              &testing_variables3.private_member_access,
              &testing_variables3.private_member_access_changed);
        },
        [&] (const std::string& own_public_id,
             const std::string& contact_public_id,
             const std::string& signal_share_name,
             const std::string& signal_share_id,
             const std::string& timestamp) {
          testresources::OpenShareInvitationSlot(own_public_id, contact_public_id,
                                                 signal_share_name,
                                                 signal_share_id,
                                                 timestamp,
                                                 &testing_variables3.new_open_share_id,
                                                 &testing_variables3.openly_invited);
        },
        [&] (const std::string& old_share_name,
             const std::string& new_share_name) {
          testresources::ShareRenameSlot(old_share_name, new_share_name,
                                         &testing_variables3.old_share_name,
                                         &testing_variables3.new_share_name,
                                         &testing_variables3.share_renamed);
        },
        ShareChangedFunction());
  test_elements3.CreateUser(keyword3, pin3, password3);
  test_elements3.CreatePublicId(public_id3);
  test_elements3.AddContact(public_id3, public_id_1_);
  test_elements3.AddContact(public_id3, public_id_2_);
  test_elements3.LogOut();

  testing_variables_1_.newly_contacted = false;
  test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_);
  while (!testing_variables_1_.newly_contacted)
    Sleep(bptime::milliseconds(100));
  test_elements_1_.ConfirmContact(public_id_1_, public_id3);
  test_elements_1_.LogOut();

  testing_variables_2_.newly_contacted = false;
  test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_);
  while (!testing_variables_2_.newly_contacted)
    Sleep(bptime::milliseconds(100));
  test_elements_2_.ConfirmContact(public_id_2_, public_id3);
  test_elements_2_.LogOut();

  test_elements3.LogIn(keyword3, pin3, password3);
    while (!testing_variables3.confirmed)
      Sleep(bptime::milliseconds(100));
  test_elements3.LogOut();

  std::string removal_message("It's not me, it's you.");
  std::string share_name1(RandomAlphaNumericString(5));
  fs::path directory1, directory2, directory3;
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadOnly));
    contacts.insert(std::make_pair(public_id3, kShareReadOnly));
    results.insert(std::make_pair(public_id_2_, kGeneralError));
    results.insert(std::make_pair(public_id3, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyPrivateShare(public_id_1_, contacts,
                                                       &share_name1, &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1, &shares_members);
    EXPECT_EQ(2U, shares_members.size());
    EXPECT_EQ(kShareReadOnlyUnConfirmed, shares_members.find(public_id_2_)->second);
    EXPECT_EQ(kShareReadOnlyUnConfirmed, shares_members.find(public_id3)->second);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name1));
    directory2 = test_elements_2_.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements3.LogIn(keyword3, pin3, password3));
    while (!testing_variables3.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables3.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements3.AcceptPrivateShareInvitation(public_id3,
                                                          public_id_1_,
                                                          testing_variables3.new_private_share_id,
                                                          &share_name1));
    directory3 = test_elements3.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory3, error_code)) << directory3;

    EXPECT_EQ(kSuccess, test_elements3.RemoveContact(public_id3, public_id_2_, removal_message));
    EXPECT_EQ(1U, test_elements3.GetContacts(public_id3).size());

    EXPECT_TRUE(fs::is_directory(directory3, error_code)) << directory3;

    EXPECT_EQ(kSuccess, test_elements3.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.removed)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(removal_message, testing_variables_2_.removal_message);
    bool contact_deleted(false);
    while (!contact_deleted) {
      Sleep(bptime::milliseconds(1000));
      ContactMap map(test_elements_2_.GetContacts(public_id_2_));
      contact_deleted = map.find(public_id3) == map.end();
    }
    EXPECT_TRUE(contact_deleted);

    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;
    EXPECT_EQ(0, error_code.value());


    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory2;
    EXPECT_EQ(0, error_code.value());
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1, &shares_members);
    EXPECT_EQ(2U, shares_members.size());
    EXPECT_EQ(2U, test_elements_1_.GetContacts(public_id_1_).size());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements_1_.Finalise());
  EXPECT_EQ(kSuccess, test_elements_2_.Finalise());
  EXPECT_EQ(kSuccess, test_elements3.Finalise());
}

TEST_F(TwoUsersMutexApiTest, FUNC_AddModifyRemoveOneFile) {
  std::string share_name1(RandomAlphaNumericString(5)),
              file_name(RandomAlphaNumericString(5)),
              file_content(RandomAlphaNumericString(20));
  fs::path directory1, directory2, file_path;

  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name1,
                                                                 &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1, &shares_members);
    EXPECT_EQ(1U, shares_members.size());
    EXPECT_EQ(kShareReadWriteUnConfirmed, shares_members.find(public_id_2_)->second);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptPrivateShareInvitation(
                  public_id_2_,
                  public_id_1_,
                  testing_variables_2_.new_private_share_id,
                  &share_name1));
    directory2 = test_elements_2_.mount_path()/ kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    file_path =  directory2 / file_name;
    std::ofstream ofstream(file_path.c_str(), std::ios::binary);
    ofstream << file_content;
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path, error_code));
    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_2_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1, &shares_members);
    EXPECT_EQ(1U, shares_members.size());

    uint8_t attempts(0);
    uint8_t expected_num_of_logs(1);
    while ((testing_variables_1_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_1_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_1_.share_changes.begin());
    EXPECT_EQ(1, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name1, share_change_entry.share_name);
    EXPECT_EQ(fs::path("/").make_preferred() / file_name,
              share_change_entry.target_path.string());
    EXPECT_TRUE(share_change_entry.old_path.empty());
    EXPECT_TRUE(share_change_entry.new_path.empty());
    EXPECT_EQ(drive::kAdded, share_change_entry.op_type);

    file_path = directory1 / file_name;
    testing_variables_1_.share_changes.clear();

    std::ofstream ofstream(file_path.c_str(),
                           std::ios_base::out | std::ios_base::binary);
    std::string new_file_content(RandomAlphaNumericString(100));
    ofstream << new_file_content;
    ofstream.close();
    Sleep(bptime::milliseconds(500));

    EXPECT_TRUE(fs::remove(file_path, error_code));
    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_1_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    uint8_t attempts(0);
    // Modify and Remove will be logged seperate as in real usage,
    // Remove shall not happen immediately afer Modify
    uint8_t expected_num_of_logs(2);
    while ((testing_variables_2_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_2_.share_changes.size());
    uint8_t num_of_removal_entries(0), num_of_modify_entries(0);
    for (auto it = testing_variables_2_.share_changes.begin();
         it != testing_variables_2_.share_changes.end(); ++it) {
      EXPECT_EQ(1, (*it).num_of_entries);
      EXPECT_EQ(share_name1, (*it).share_name);
      EXPECT_EQ(fs::path("/").make_preferred() / file_name,
                (*it).target_path.string());
      EXPECT_TRUE((*it).old_path.empty());
      EXPECT_TRUE((*it).new_path.empty());
      if ((*it).op_type == drive::kRemoved)
        ++num_of_removal_entries;
      if ((*it).op_type == drive::kModified)
        ++num_of_modify_entries;
    }
    EXPECT_EQ(1, num_of_removal_entries);
    EXPECT_EQ(1, num_of_modify_entries);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersMutexApiTest, FUNC_AddRemoveMultipleNodes) {
  std::string share_name(RandomAlphaNumericString(5));
  fs::path directory1, directory2;
  std::string sub_directory_name(RandomAlphaNumericString(5));
  std::string further_sub_directory_name(RandomAlphaNumericString(5));
  int num_of_nodes(5 + RandomInt32() % 6);
  int num_of_further_nodes(5 + RandomInt32() % 6);
  std::vector<std::string> names_of_nodes;

  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name,
                                                                 &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                            share_name,
                                            &shares_members);
    EXPECT_EQ(1U, shares_members.size());
    EXPECT_EQ(kShareReadWriteUnConfirmed, shares_members.find(public_id_2_)->second);

    fs::path sub_directory(directory1 / sub_directory_name);
    fs::path further_sub_director(sub_directory / further_sub_directory_name);
    EXPECT_TRUE(fs::create_directory(sub_directory, error_code));
    EXPECT_TRUE(fs::create_directory(further_sub_director, error_code));

    for (int i = 0; i < num_of_further_nodes; ++i) {
      int file_or_dir(RandomInt32() % 2);
      if (file_or_dir == 0) {
        std::string file_name(RandomAlphaNumericString(4));
        fs::path file_path(further_sub_director / file_name);
        std::string file_content(RandomAlphaNumericString(100));
        std::ofstream ofstream(file_path.c_str(), std::ios::binary);
        ofstream << file_content;
        ofstream.close();
        EXPECT_TRUE(fs::exists(file_path, error_code)) << file_path;
        names_of_nodes.push_back(file_name);
      } else {
        std::string dir_name(RandomAlphaNumericString(6));
        fs::path directory(further_sub_director / dir_name);
        EXPECT_TRUE(fs::create_directory(directory, error_code)) << directory;
        names_of_nodes.push_back(dir_name);
      }
    }

    EXPECT_EQ(0, error_code.value());
    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_1_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptPrivateShareInvitation(
                  public_id_2_,
                  public_id_1_,
                  testing_variables_2_.new_private_share_id,
                  &share_name));
    directory2 = test_elements_2_.mount_path()/ kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    fs::path sub_director(directory2 / sub_directory_name);
    for (int i = 0; i < num_of_nodes; ++i) {
      int file_or_dir(RandomInt32() % 2);
      if (file_or_dir == 0) {
        std::string file_name(RandomAlphaNumericString(4));
        fs::path file_path(sub_director / file_name);
        std::string file_content(RandomAlphaNumericString(100));
        std::ofstream ofstream(file_path.c_str(), std::ios::binary);
        ofstream << file_content;
        ofstream.close();
        EXPECT_TRUE(fs::exists(file_path, error_code)) << file_path;
      } else {
        std::string dir_name(RandomAlphaNumericString(6));
        fs::path directory(sub_director / dir_name);
        EXPECT_TRUE(fs::create_directory(directory, error_code)) << directory;
      }
    }

    fs::path further_sub_director(sub_director / further_sub_directory_name);
    for (auto it = names_of_nodes.begin(); it != names_of_nodes.end(); ++it) {
      fs::path node_path(further_sub_director / (*it));
      fs::remove(node_path, error_code);
    }

    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_EQ(1, testing_variables_2_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_2_.share_changes.begin());
    EXPECT_EQ(1, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name, share_change_entry.share_name);
    EXPECT_EQ(fs::path("/").make_preferred() / sub_directory_name,
              share_change_entry.target_path.string());
    EXPECT_TRUE(share_change_entry.old_path.empty());
    EXPECT_TRUE(share_change_entry.new_path.empty());
    EXPECT_EQ(drive::kAdded, share_change_entry.op_type);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name, &shares_members);
    EXPECT_EQ(1U, shares_members.size());

    uint8_t attempts(0);
    uint8_t expected_num_of_logs(2);
    while ((testing_variables_1_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_1_.share_changes.size());
    uint8_t num_of_added_entries(0), num_of_removal_entries(0);
    for (auto it = testing_variables_1_.share_changes.begin();
         it != testing_variables_1_.share_changes.end(); ++it) {
      EXPECT_EQ(share_name, (*it).share_name);
      EXPECT_TRUE((*it).old_path.empty());
      EXPECT_TRUE((*it).new_path.empty());
      if ((*it).op_type == drive::kRemoved) {
        EXPECT_EQ(fs::path("/").make_preferred() /
                      sub_directory_name / further_sub_directory_name,
                  (*it).target_path);
        EXPECT_EQ(num_of_further_nodes, (*it).num_of_entries);
        ++num_of_removal_entries;
      }
      if ((*it).op_type == drive::kAdded) {
        EXPECT_EQ(fs::path("/").make_preferred() / sub_directory_name,
                  (*it).target_path);
        EXPECT_EQ(num_of_nodes, (*it).num_of_entries);
        ++num_of_added_entries;
      }
    }
    EXPECT_EQ(1, num_of_removal_entries);
    EXPECT_EQ(1, num_of_added_entries);

    testing_variables_1_.share_changes.clear();
    fs::path directory(directory1 / sub_directory_name);
    EXPECT_GT(fs::remove_all(directory, error_code), 0);
    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_1_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    testing_variables_2_.share_changes.clear();
    uint8_t attempts(0);
    uint8_t expected_num_of_logs(2);
    while ((testing_variables_2_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_2_.share_changes.size());
    // The original add log will still be picked up, as the trace_back_time
    // has been reset
    uint8_t num_of_added_entries(0), num_of_removal_entries(0);
    for (auto it = testing_variables_2_.share_changes.begin();
         it != testing_variables_2_.share_changes.end(); ++it) {
      EXPECT_EQ(1, (*it).num_of_entries);
      EXPECT_EQ(share_name, (*it).share_name);
      EXPECT_EQ(fs::path("/").make_preferred() / sub_directory_name,
                (*it).target_path.string());
      EXPECT_TRUE((*it).old_path.empty());
      EXPECT_TRUE((*it).new_path.empty());
      if ((*it).op_type == drive::kRemoved)
        ++num_of_removal_entries;
      if ((*it).op_type == drive::kAdded)
        ++num_of_added_entries;
    }
    EXPECT_EQ(1, num_of_removal_entries);
    EXPECT_EQ(1, num_of_added_entries);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersMutexApiTest, FUNC_RenameOneNode) {
  std::string share_name(RandomAlphaNumericString(5)),
              file_name(RandomAlphaNumericString(5)),
              new_file_name(RandomAlphaNumericString(5)),
              file_content(RandomAlphaNumericString(20));
  fs::path directory1, directory2, file_path, new_file_path;

  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name,
                                                                 &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                            share_name,
                                            &shares_members);
    EXPECT_EQ(1U, shares_members.size());
    EXPECT_EQ(kShareReadWriteUnConfirmed, shares_members.find(public_id_2_)->second);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptPrivateShareInvitation(
                  public_id_2_,
                  public_id_1_,
                  testing_variables_2_.new_private_share_id,
                  &share_name));
    directory2 = test_elements_2_.mount_path()/ kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    file_path =  directory2 / file_name;
    std::ofstream ofstream(file_path.c_str(), std::ios::binary);
    ofstream << file_content;
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path, error_code));
    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_2_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name, &shares_members);
    EXPECT_EQ(1U, shares_members.size());

    uint8_t attempts(0);
    uint8_t expected_num_of_logs(1);
    while ((testing_variables_1_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_1_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_1_.share_changes.begin());
    EXPECT_EQ(1, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name, share_change_entry.share_name);
    EXPECT_EQ(fs::path("/").make_preferred() / file_name,
              share_change_entry.target_path.string());
    EXPECT_TRUE(share_change_entry.old_path.empty());
    EXPECT_TRUE(share_change_entry.new_path.empty());
    EXPECT_EQ(drive::kAdded, share_change_entry.op_type);

    file_path = directory1 / file_name;
    new_file_path = directory1 / new_file_name;
    testing_variables_1_.share_changes.clear();

    fs::rename(file_path, new_file_path, error_code);
    EXPECT_EQ(0, error_code.value());
    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_1_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    uint8_t attempts(0);
    uint8_t expected_num_of_logs(1);
    while ((testing_variables_2_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_2_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_2_.share_changes.begin());
    EXPECT_EQ(1, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name, share_change_entry.share_name);
    EXPECT_EQ(fs::path("/").make_preferred() / file_name,
              share_change_entry.target_path);
    EXPECT_EQ(fs::path("/").make_preferred() / file_name,
              share_change_entry.old_path);
    EXPECT_EQ(fs::path("/").make_preferred() / new_file_name,
              share_change_entry.new_path);
    EXPECT_EQ(drive::kRenamed, share_change_entry.op_type);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersMutexApiTest, FUNC_MoveNodeToShareAndMoveOut) {
  std::string share_name(RandomAlphaNumericString(5));
  fs::path directory1, directory2;
  std::string sub_directory_name(RandomAlphaNumericString(5));

  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name,
                                                                 &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                            share_name,
                                            &shares_members);
    EXPECT_EQ(1U, shares_members.size());
    EXPECT_EQ(kShareReadWriteUnConfirmed, shares_members.find(public_id_2_)->second);

    fs::path directory(test_elements_1_.mount_path() / sub_directory_name);
    EXPECT_TRUE(fs::create_directory(directory, error_code));

    fs::path sub_directory(directory1 / sub_directory_name);
    fs::rename(directory, sub_directory, error_code);
    EXPECT_EQ(0, error_code.value());

    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_1_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  LOG(kError) << "\n\n1\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptPrivateShareInvitation(
                  public_id_2_,
                  public_id_1_,
                  testing_variables_2_.new_private_share_id,
                  &share_name));
    directory2 = test_elements_2_.mount_path() / kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    fs::path directory(test_elements_2_.mount_path() / sub_directory_name);
    fs::path sub_directory(directory2 / sub_directory_name);
    fs::rename(sub_directory, directory, error_code);
    EXPECT_EQ(0, error_code.value());

    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_EQ(1, testing_variables_2_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_2_.share_changes.begin());
    EXPECT_EQ(1, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name, share_change_entry.share_name);
    EXPECT_EQ(fs::path("/").make_preferred() / sub_directory_name,
              share_change_entry.target_path);
    EXPECT_TRUE(share_change_entry.old_path.empty());
    EXPECT_TRUE(share_change_entry.new_path.empty());
    EXPECT_EQ(drive::kAdded, share_change_entry.op_type);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  LOG(kError) << "\n\n2\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name, &shares_members);
    EXPECT_EQ(1U, shares_members.size());

    uint8_t attempts(0);
    uint8_t expected_num_of_logs(1);
    while ((testing_variables_1_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_1_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_1_.share_changes.begin());
    EXPECT_EQ(1, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name, share_change_entry.share_name);
    EXPECT_EQ(fs::path("/").make_preferred() / sub_directory_name,
              share_change_entry.target_path);
    EXPECT_TRUE(share_change_entry.old_path.empty());
    EXPECT_TRUE(share_change_entry.new_path.empty());
    EXPECT_EQ(drive::kRemoved, share_change_entry.op_type);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  LOG(kError) << "\n\n3\n\n";
}

TEST_F(TwoUsersMutexApiTest, FUNC_MoveNodeInnerShare) {
  std::string share_name(RandomAlphaNumericString(5));
  fs::path directory1, directory2, file_path, new_file_path;
  std::string file_name(RandomAlphaNumericString(6)),
              file_content(RandomAlphaNumericString(20)),
              sub_directory_name(RandomAlphaNumericString(5));

  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name,
                                                                 &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                            share_name,
                                            &shares_members);
    EXPECT_EQ(1U, shares_members.size());
    EXPECT_EQ(kShareReadWriteUnConfirmed, shares_members.find(public_id_2_)->second);

    fs::path sub_directory(directory1 / sub_directory_name);
    EXPECT_TRUE(fs::create_directory(sub_directory, error_code));
    file_path =  directory1 / file_name;
    std::ofstream ofstream(file_path.c_str(), std::ios::binary);
    ofstream << file_content;
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path, error_code));

    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_1_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptPrivateShareInvitation(
                  public_id_2_,
                  public_id_1_,
                  testing_variables_2_.new_private_share_id,
                  &share_name));
    directory2 = test_elements_2_.mount_path() / kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    file_path = directory2 / file_name;
    new_file_path = directory2 / sub_directory_name / file_name;
    fs::rename(file_path, new_file_path, error_code);
    EXPECT_EQ(0, error_code.value());

    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_EQ(1, testing_variables_2_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_2_.share_changes.begin());
    EXPECT_EQ(2, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name, share_change_entry.share_name);
    // When log the notification, the share_root will be removed
    // (other users may have their own share_root for the same share)
    // i.e. the target, old and new path are relative path to share_root
    EXPECT_TRUE(share_change_entry.target_path.empty());
    EXPECT_TRUE(share_change_entry.old_path.empty());
    EXPECT_TRUE(share_change_entry.new_path.empty());
    EXPECT_EQ(drive::kAdded, share_change_entry.op_type);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name, &shares_members);
    EXPECT_EQ(1U, shares_members.size());

    uint8_t attempts(0);
    uint8_t expected_num_of_logs(1);
    while ((testing_variables_1_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_1_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_1_.share_changes.begin());
    EXPECT_EQ(1, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name, share_change_entry.share_name);
    EXPECT_EQ(fs::path("/").make_preferred() / file_name,
              share_change_entry.target_path);
    EXPECT_EQ("", share_change_entry.old_path.string());
    EXPECT_EQ(fs::path("/").make_preferred() / sub_directory_name,
              share_change_entry.new_path);
    EXPECT_EQ(drive::kMoved, share_change_entry.op_type);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
}

TEST_F(TwoUsersMutexApiTest, FUNC_MoveNodeInterShares) {
  std::string share_name1(RandomAlphaNumericString(5));
  std::string share_name2(RandomAlphaNumericString(5));
  fs::path directory1, directory2, file_path, new_file_path;
  std::string file_name(RandomAlphaNumericString(6)),
              file_content(RandomAlphaNumericString(20));

  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private shares
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name1,
                                                                 &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptPrivateShareInvitation(
                  public_id_2_,
                  public_id_1_,
                  testing_variables_2_.new_private_share_id,
                  &share_name1));
    directory1 = test_elements_2_.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;

    // Create empty private shares
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_1_, kShareReadWrite));
    results.insert(std::make_pair(public_id_1_, kGeneralError));
    EXPECT_EQ(kSuccess, test_elements_2_.CreateEmptyPrivateShare(public_id_2_,
                                                                 contacts,
                                                                 &share_name2,
                                                                 &results));
    directory2 = test_elements_2_.mount_path() / kSharedStuff / share_name2;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    file_path =  directory1 / file_name;
    std::ofstream ofstream(file_path.c_str(), std::ios::binary);
    ofstream << file_content;
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path, error_code));

    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_2_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    while (!testing_variables_1_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_1_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_1_.AcceptPrivateShareInvitation(
                  public_id_1_,
                  public_id_2_,
                  testing_variables_1_.new_private_share_id,
                  &share_name2));

    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name1;
    directory2 = test_elements_1_.mount_path() / kSharedStuff / share_name2;

    file_path =  directory1 / file_name;
    new_file_path = directory2 / file_name;
    fs::rename(file_path, new_file_path, error_code);
    EXPECT_EQ(0, error_code.value());

    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_EQ(1, testing_variables_1_.share_changes.size());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    uint8_t attempts(0);
    uint8_t expected_num_of_logs(2);
    while ((testing_variables_2_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    uint8_t num_of_added_entries(0), num_of_removal_entries(0);
    for (auto it = testing_variables_2_.share_changes.begin();
         it != testing_variables_2_.share_changes.end(); ++it) {
      EXPECT_EQ(1, (*it).num_of_entries);
      EXPECT_EQ(fs::path("/").make_preferred() / file_name,
                (*it).target_path);
      EXPECT_TRUE((*it).old_path.empty());
      EXPECT_TRUE((*it).new_path.empty());
      if ((*it).op_type == drive::kRemoved) {
        EXPECT_EQ(share_name1, (*it).share_name);
        ++num_of_removal_entries;
      }
      if ((*it).op_type == drive::kAdded) {
        EXPECT_EQ(share_name2, (*it).share_name);
        ++num_of_added_entries;
      }
    }
    EXPECT_EQ(1, num_of_removal_entries);
    EXPECT_EQ(1, num_of_added_entries);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

#ifndef WIN32
// Renaming items to hidden .Trash files under the same folder is used
// by Linux OS when delete files via file browser (enabling recycle bin)
// Windows OS doesn't have the same behaviour for mounted drives
TEST_F(TwoUsersMutexApiTest, FUNC_MoveNodeToTrashThenMoveBack) {
  std::string share_name(RandomAlphaNumericString(5)),
              file_name(RandomAlphaNumericString(5)),
              new_file_name(".Trash" + RandomAlphaNumericString(5)),
              file_content(RandomAlphaNumericString(20));
  fs::path directory1, directory2, file_path, new_file_path;

  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name,
                                                                 &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                            share_name,
                                            &shares_members);
    EXPECT_EQ(1U, shares_members.size());
    EXPECT_EQ(kShareReadWriteUnConfirmed, shares_members.find(public_id_2_)->second);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptPrivateShareInvitation(
                  public_id_2_,
                  public_id_1_,
                  testing_variables_2_.new_private_share_id,
                  &share_name));
    directory2 = test_elements_2_.mount_path()/ kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    file_path =  directory2 / file_name;
    std::ofstream ofstream(file_path.c_str(), std::ios::binary);
    ofstream << file_content;
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path, error_code));

    new_file_path = directory2 / new_file_name;
    fs::rename(file_path, new_file_path, error_code);
    EXPECT_EQ(0, error_code.value());

    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_2_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name, &shares_members);
    EXPECT_EQ(1U, shares_members.size());

    uint8_t attempts(0);
    uint8_t expected_num_of_logs(2);
    while ((testing_variables_1_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    uint8_t num_of_added_entries(0), num_of_removal_entries(0);
    for (auto it = testing_variables_1_.share_changes.begin();
         it != testing_variables_1_.share_changes.end(); ++it) {
      EXPECT_EQ(1, (*it).num_of_entries);
      EXPECT_EQ(share_name, (*it).share_name);
      EXPECT_EQ(fs::path("/").make_preferred() / file_name,
                (*it).target_path.string());
      EXPECT_TRUE((*it).old_path.empty());
      EXPECT_TRUE((*it).new_path.empty());
      if ((*it).op_type == drive::kRemoved)
        ++num_of_removal_entries;
      if ((*it).op_type == drive::kAdded)
        ++num_of_added_entries;
    }
    EXPECT_EQ(1, num_of_removal_entries);
    EXPECT_EQ(1, num_of_added_entries);

    file_path = directory1 / file_name;
    new_file_path = directory1 / new_file_name;
    testing_variables_1_.share_changes.clear();

    fs::rename(new_file_path, file_path, error_code);
    EXPECT_EQ(0, error_code.value());
    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_1_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    uint8_t attempts(0);
    uint8_t expected_num_of_logs(1);
    while ((testing_variables_2_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_2_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_2_.share_changes.begin());
    EXPECT_EQ(1, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name, share_change_entry.share_name);
    EXPECT_EQ(fs::path("/").make_preferred() / new_file_name,
              share_change_entry.target_path.string());
    EXPECT_EQ(fs::path("/").make_preferred() / new_file_name,
              share_change_entry.old_path.string());
    EXPECT_EQ(fs::path("/").make_preferred() / file_name,
              share_change_entry.new_path.string());
    EXPECT_EQ(drive::kRenamed, share_change_entry.op_type);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}
#endif

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
