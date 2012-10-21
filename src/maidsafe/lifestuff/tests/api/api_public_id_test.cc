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

TEST_F(OneUserApiTest, FUNC_TryCreateInvalidPublicId) {
  // EXPECT_NE(kSuccess, test_elements_.CreatePublicId(NonEmptyString("")));
  EXPECT_NE(kSuccess, test_elements_.CreatePublicId(NonEmptyString(RandomAlphaNumericString(31))));
  EXPECT_NE(kSuccess, test_elements_.CreatePublicId(NonEmptyString(" ")));
  EXPECT_NE(kSuccess,
            test_elements_.CreatePublicId(NonEmptyString(" " + RandomAlphaNumericString(RandomUint32() % 26 + 4))));
  EXPECT_NE(kSuccess,
            test_elements_.CreatePublicId(NonEmptyString(RandomAlphaNumericString(RandomUint32() % 26 + 4) + " ")));
  EXPECT_NE(kSuccess,
            test_elements_.CreatePublicId(NonEmptyString(RandomAlphaNumericString(RandomUint32() % 13 + 2) + "  " +
                                          RandomAlphaNumericString(RandomUint32() % 14 + 1))));
  EXPECT_NE(kSuccess,
            test_elements_.CreatePublicId(NonEmptyString(" " + RandomAlphaNumericString(RandomUint32() % 13 + 1)
                                          + "  " +
                                          RandomAlphaNumericString(RandomUint32() % 13 + 1) + " ")));
  EXPECT_EQ(kSuccess,
            test_elements_.CreatePublicId(NonEmptyString(RandomAlphaNumericString(RandomUint32() % 14 + 1) + " " +
                                          RandomAlphaNumericString(RandomUint32() % 15 + 1))));
}

TEST_F(OneUserApiTest, FUNC_CreateSamePublicIdConsecutively) {
  NonEmptyString new_public_id(RandomAlphaNumericString(6));
  EXPECT_EQ(kSuccess, test_elements_.CreatePublicId(new_public_id));
  EXPECT_NE(kSuccess, test_elements_.CreatePublicId(new_public_id));
}

TEST_F(OneUserApiTest, FUNC_CreateSamePublicIdSimultaneously) {
  NonEmptyString new_public_id(RandomAlphaNumericString(6));
  int result_1(0);
  int result_2(0);

  std::vector<std::pair<int, int>> sleep_values;
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

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));

    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, pin_, password_));

    int new_instances(0);
    std::vector<NonEmptyString>::iterator it;
    std::vector<NonEmptyString> names(test_elements_.PublicIdsList());
    for (it = names.begin(); it < names.end(); it++) {
      if (*it == new_public_id)
        ++new_instances;
    }
    EXPECT_EQ(new_instances, 1);
    new_public_id = NonEmptyString(RandomAlphaNumericString(new_public_id.string().length() + 1));
  }
}

TEST_F(OneUserApiTest, FUNC_AddInvalidContact) {
  NonEmptyString own_public_id(RandomAlphaNumericString(5));
  NonEmptyString public_id_1(RandomAlphaNumericString(6));
  NonEmptyString public_id_2(RandomAlphaNumericString(7));
  NonEmptyString message(RandomAlphaNumericString(5));
  test_elements_.CreatePublicId(own_public_id);
  EXPECT_NE(kSuccess, test_elements_.AddContact(own_public_id, NonEmptyString(" "), message));
  EXPECT_NE(kSuccess, test_elements_.AddContact(own_public_id, public_id_1, message));
  EXPECT_NE(kSuccess, test_elements_.AddContact(public_id_1, public_id_2, message));
}

TEST_F(OneUserApiTest, FUNC_AddOwnPublicIdAsContact) {
  NonEmptyString public_id_1(RandomAlphaNumericString(6));
  NonEmptyString public_id_2(RandomAlphaNumericString(7));
  NonEmptyString message(RandomAlphaNumericString(5));
  test_elements_.CreatePublicId(public_id_1);
  test_elements_.CreatePublicId(public_id_2);

  EXPECT_NE(kSuccess, test_elements_.AddContact(public_id_1, public_id_1, message));
  EXPECT_NE(kSuccess, test_elements_.AddContact(public_id_1, public_id_2,message));
}

TEST_F(OneUserApiTest, FUNC_ChangeProfilePictureAfterSaveSession) {
  NonEmptyString public_id(RandomAlphaNumericString(5));
  EXPECT_EQ(kSuccess, test_elements_.CreatePublicId(public_id));
  for (int n(1001); n > 1; n-=100) {
    NonEmptyString profile_picture1(RandomString(1177 * n)), profile_picture2(RandomString(1177 * n));
    EXPECT_EQ(kSuccess, test_elements_.ChangeProfilePicture(public_id, profile_picture1));
    NonEmptyString retrieved_picture(test_elements_.GetOwnProfilePicture(public_id));
    EXPECT_TRUE(profile_picture1 == retrieved_picture);
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));

    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, pin_, password_));
    retrieved_picture = test_elements_.GetOwnProfilePicture(public_id);
    EXPECT_TRUE(profile_picture1 == retrieved_picture);
    EXPECT_EQ(kSuccess, test_elements_.ChangeProfilePicture(public_id, profile_picture2));
    retrieved_picture = test_elements_.GetOwnProfilePicture(public_id);
    EXPECT_TRUE(profile_picture2 == retrieved_picture);
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));

    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, pin_, password_));
    retrieved_picture = test_elements_.GetOwnProfilePicture(public_id);
    EXPECT_TRUE(profile_picture2 == retrieved_picture);
    EXPECT_EQ(kSuccess, test_elements_.ChangeProfilePicture(public_id, profile_picture1));
    retrieved_picture = test_elements_.GetOwnProfilePicture(public_id);
    EXPECT_TRUE(profile_picture1 == retrieved_picture);
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));

    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, pin_, password_));
    retrieved_picture = test_elements_.GetOwnProfilePicture(public_id);
    EXPECT_TRUE(profile_picture1 == retrieved_picture);
  }
}

TEST_F(TwoUsersApiTest, FUNC_TrivialTest) {
  LOG(kInfo) << "\n\n\n\n";
  Sleep(bptime::seconds(10));
  LOG(kInfo) << "\n\n\n\n";
}

TEST_F(TwoUsersApiTest, FUNC_CreateSamePublicIdConsecutively) {
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
  NonEmptyString new_public_id(RandomAlphaNumericString(6));

  EXPECT_EQ(kSuccess, test_elements_1_.CreatePublicId(new_public_id));
  EXPECT_NE(kSuccess, test_elements_1_.CreatePublicId(new_public_id));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
  EXPECT_NE(kSuccess, test_elements_2_.CreatePublicId(new_public_id));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
  int new_instances(0);
  std::vector<NonEmptyString>::iterator it;
  std::vector<NonEmptyString> names(test_elements_1_.PublicIdsList());
  for (it = names.begin(); it < names.end(); it++) {
    if (*it == new_public_id)
      ++new_instances;
  }
  EXPECT_EQ(new_instances, 1);
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
  names = test_elements_2_.PublicIdsList();
  for (it = names.begin(); it < names.end(); it++) {
    if (*it == new_public_id)
      ++new_instances;
  }
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
}

TEST_F(TwoUsersApiTest, FUNC_CreateSamePublicIdSimultaneously) {
#ifdef MAIDSAFE_LINUX
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));

  std::string new_public_id(RandomAlphaNumericString(6));
  int result_1(0), result_2(0);

  std::vector<std::pair<int, int>> sleep_values;
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

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));

    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));

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

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
#endif
}

TEST_F(TwoUsersApiTest, FUNC_SendFileSaveToGivenPath) {
  boost::system::error_code error_code;
  fs::path file_path1;
  NonEmptyString file_name1(RandomAlphaNumericString(8)),
                 file_content1(RandomString(5 * 1024)),
                 file_name2(RandomAlphaNumericString(8));

  LOG(kError) << "1111";
  {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));

    file_path1 = test_elements_1_.mount_path() / file_name1.string();
    std::ofstream ofstream(file_path1.c_str(), std::ios::binary);
    ofstream << file_content1.string();
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements_1_.SendFile(public_id_1_, public_id_2_, file_path1));

//    Sleep(bptime::seconds(2));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
  }
  LOG(kError) << "2222";
  {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.file_transfer_received)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables_2_.file_id.string().empty());
    EXPECT_EQ(file_name1, testing_variables_2_.file_name);
    EXPECT_NE(kSuccess, test_elements_2_.AcceptSentFile(testing_variables_2_.file_id));
    EXPECT_NE(kSuccess, test_elements_2_.AcceptSentFile(
                                             testing_variables_2_.file_id,
                                             test_elements_2_.mount_path() / file_name2.string(),
                                             &file_name2));
    EXPECT_EQ(kSuccess, test_elements_2_.AcceptSentFile(
                                             testing_variables_2_.file_id,
                                             test_elements_2_.mount_path() / file_name2.string()));

    EXPECT_TRUE(fs::exists(test_elements_2_.mount_path() / file_name2.string(), error_code));
    EXPECT_EQ(0, error_code.value());

    Sleep(bptime::seconds(2));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
  }
}

TEST_F(TwoUsersApiTest, FUNC_SendFileSaveToDefaultLocation) {
  boost::system::error_code error_code;
  fs::path file_path1;
  NonEmptyString file_name1(RandomAlphaNumericString(8)),
                 file_content1(RandomString(5 * 1024));
  {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));

    file_path1 = test_elements_1_.mount_path() / file_name1.string();
    std::ofstream ofstream(file_path1.c_str(), std::ios::binary);
    ofstream << file_content1.string();
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements_1_.SendFile(public_id_1_, public_id_2_, file_path1));

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
  }
  {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.file_transfer_received)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.file_id.string().empty());
    EXPECT_EQ(file_name1, testing_variables_2_.file_name);
    NonEmptyString saved_file_name;
    EXPECT_EQ(kSuccess, test_elements_2_.AcceptSentFile(testing_variables_2_.file_id,
                                                        fs::path(),
                                                        &saved_file_name));
    EXPECT_EQ(file_name1, saved_file_name);
    fs::path path2(test_elements_2_.mount_path() / 
                     kMyStuff / kDownloadStuff / saved_file_name.string());
    EXPECT_TRUE(fs::exists(path2, error_code));
    EXPECT_EQ(0, error_code.value());
    NonEmptyString file_content2;
    EXPECT_TRUE(ReadFile(path2, const_cast<std::string*>(&file_content2.string())));
    EXPECT_EQ(file_content1, file_content2);

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
  }
  {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
    file_path1 = test_elements_1_.mount_path() / file_name1.string();
    std::ofstream ofstream(file_path1.c_str(), std::ios::binary);
    ofstream << file_content1.string();
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements_1_.SendFile(public_id_1_, public_id_2_, file_path1));

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
  }
  {
    testing_variables_2_.file_transfer_received = false;
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.file_transfer_received)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.file_id.string().empty());
    EXPECT_EQ(file_name1, testing_variables_2_.file_name);
    NonEmptyString saved_file_name;
    EXPECT_EQ(kSuccess, test_elements_2_.AcceptSentFile(testing_variables_2_.file_id,
                                                      fs::path(),
                                                      &saved_file_name));
    EXPECT_EQ(file_name1 + NonEmptyString(" (1)"), saved_file_name);
    fs::path path2a(test_elements_2_.mount_path() /
                      kMyStuff / kDownloadStuff / file_name1.string()),
             path2b(test_elements_2_.mount_path() /
                      kMyStuff / kDownloadStuff / saved_file_name.string());

    EXPECT_TRUE(fs::exists(path2a, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(path2b, error_code));
    EXPECT_EQ(0, error_code.value());
    NonEmptyString file_content2;
    EXPECT_TRUE(ReadFile(path2b, const_cast<std::string*>(&file_content2.string())));
    EXPECT_TRUE(file_content1 == file_content2);

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
  }
}

TEST_F(TwoUsersApiTest, FUNC_SendFileAcceptToDeletedDefaultLocation) {
  boost::system::error_code error_code;
  fs::path file_path1;
  NonEmptyString file_name1(RandomAlphaNumericString(8)),
                 file_content1(RandomString(5 * 1024));
  LOG(kInfo) << "POINT 1";
  {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));

    file_path1 = test_elements_1_.mount_path() / file_name1.string();
    std::ofstream ofstream(file_path1.c_str(), std::ios::binary);
    ofstream << file_content1.string();
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements_1_.SendFile(public_id_1_, public_id_2_, file_path1));

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
  }
  LOG(kInfo) << "POINT 2";
  {
    testing_variables_2_.file_transfer_received = false;
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.file_transfer_received)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.file_id.string().empty());
    EXPECT_EQ(file_name1, testing_variables_2_.file_name);

    // Delete accepted files dir
    fs::remove_all(test_elements_2_.mount_path() / kMyStuff, error_code);
    EXPECT_EQ(0, error_code.value());
    EXPECT_FALSE(fs::exists(test_elements_2_.mount_path() / kMyStuff, error_code));
    EXPECT_NE(0, error_code.value());

    NonEmptyString saved_file_name;
    EXPECT_EQ(kSuccess, test_elements_2_.AcceptSentFile(testing_variables_2_.file_id,
                                                      fs::path(),
                                                      &saved_file_name));
    EXPECT_EQ(file_name1, saved_file_name);
    fs::path path2(test_elements_2_.mount_path() /
                      kMyStuff / kDownloadStuff / saved_file_name.string());
    EXPECT_TRUE(fs::exists(path2, error_code));
    EXPECT_EQ(0, error_code.value());
    NonEmptyString file_content2;
    EXPECT_TRUE(ReadFile(path2, const_cast<std::string*>(&file_content2.string())));
    EXPECT_EQ(file_content1, file_content2);

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
  }
  LOG(kInfo) << "POINT 3";
}

TEST(IndependentFullTest, FUNC_SendFileWithRejection) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  NonEmptyString keyword1(RandomAlphaNumericString(6)),
                 pin1(CreatePin()),
                 password1(RandomAlphaNumericString(6)),
                 public_id1(RandomAlphaNumericString(5));
  NonEmptyString keyword2(RandomAlphaNumericString(6)),
                 pin2(CreatePin()),
                 password2(RandomAlphaNumericString(6)),
                 public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  int file_count(0), file_max(10);
  size_t files_expected(file_max);
  std::vector<fs::path> file_paths;
  std::vector<NonEmptyString> file_contents, received_ids, received_names;
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
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword1, pin1, password1));

    for (; file_count < file_max; ++file_count) {
      file_paths.push_back(fs::path(test_elements1.mount_path() / RandomAlphaNumericString(8)));
      std::ofstream ofstream(file_paths[file_count].c_str(), std::ios::binary);
      file_contents.push_back(NonEmptyString(RandomString(5 * 1024)));
      ofstream << file_contents[file_count].string();
      ofstream.close();
      EXPECT_TRUE(fs::exists(file_paths[file_count], error_code));
      EXPECT_EQ(0, error_code.value());
      EXPECT_EQ(kSuccess, test_elements1.SendFile(public_id1, public_id2, file_paths[file_count]));
    }

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }
  {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword2, pin2, password2));
    while (!testing_variables2.file_transfer_received)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(files_expected, received_ids.size());
    EXPECT_EQ(files_expected, received_names.size());
    fs::path path2(test_elements2.mount_path() / kMyStuff / kDownloadStuff);
    for (size_t st(0); st < received_ids.size(); ++st) {
      EXPECT_EQ(file_paths[st].filename().string(), received_names[st].string());
      EXPECT_EQ(kSuccess, test_elements2.RejectSentFile(received_ids[st]));
      EXPECT_FALSE(fs::exists(path2 / received_names[st].string(), error_code));
      EXPECT_NE(0, error_code.value());
      NonEmptyString hidden(received_ids[st].string() + kHiddenFileExtension), content;
      EXPECT_NE(kSuccess, test_elements2.ReadHiddenFile(test_elements2.mount_path() / hidden.string(),
                                                        const_cast<std::string*>(&content.string())));
    }

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }
  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST_F(TwoUsersApiTest, FUNC_ProfilePicture) {
  NonEmptyString file_content1, file_content2(RandomString(5 * 1024));
  {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
    // Setting of profile image
    EXPECT_EQ(kSuccess, test_elements_2_.ChangeProfilePicture(public_id_2_, file_content2));
    Sleep(bptime::seconds(1));

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
  }
  {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
    while (!testing_variables_1_.picture_updated)
      Sleep(bptime::milliseconds(100));

    file_content1 = test_elements_1_.GetContactProfilePicture(public_id_1_, public_id_2_);
    EXPECT_TRUE(file_content2 == file_content1);
    EXPECT_NE(kSuccess, test_elements_1_.ChangeProfilePicture(public_id_1_, NonEmptyString(" ")));

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
  }
  {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
    // Setting of profile image
    EXPECT_EQ(kSuccess, test_elements_2_.ChangeProfilePicture(public_id_2_, kBlankProfilePicture));

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
  }
  {
    testing_variables_1_.picture_updated = false;
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
    while (!testing_variables_1_.picture_updated)
      Sleep(bptime::milliseconds(100));

    file_content1 = test_elements_1_.GetContactProfilePicture(public_id_1_, public_id_2_);
    EXPECT_TRUE(kBlankProfilePicture == file_content1);

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
  }
}

TEST_F(TwoUsersApiTest, FUNC_ProfilePictureAndLogOut) {
  NonEmptyString file_content1, file_content2(RandomString(5 * 1024));
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
  // Setting of profile image
  EXPECT_EQ(kSuccess, test_elements_2_.ChangeProfilePicture(public_id_2_, file_content2));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
  file_content1 = test_elements_1_.GetContactProfilePicture(public_id_1_, public_id_2_);
  EXPECT_TRUE(file_content2 == file_content1);
  EXPECT_NE(kSuccess, test_elements_1_.ChangeProfilePicture(public_id_1_, NonEmptyString(" ")));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
  // Setting of profile image
  EXPECT_EQ(kSuccess, test_elements_2_.ChangeProfilePicture(public_id_2_, kBlankProfilePicture));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));

  testing_variables_1_.picture_updated = false;
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
  file_content1 = test_elements_1_.GetContactProfilePicture(public_id_1_, public_id_2_);
  EXPECT_TRUE(kBlankProfilePicture == file_content1);
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
}

TEST_F(TwoUsersApiTest, FUNC_RemoveContact) {
  NonEmptyString removal_message("It's not me, it's you.");
  {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));

    EXPECT_EQ(kSuccess, test_elements_1_.RemoveContact(public_id_1_, public_id_2_,
                                                       removal_message));
    EXPECT_TRUE(test_elements_1_.GetContacts(public_id_1_).empty());

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
  }
  {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.removed)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(removal_message, testing_variables_2_.removal_message);
    bool contact_deleted(false);
    while (!contact_deleted)
      contact_deleted = test_elements_2_.GetContacts(public_id_2_).empty();
    EXPECT_TRUE(contact_deleted);

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
  }
}

TEST_F(TwoUsersApiTest, FUNC_RemoveContactAddContact) {
  for (int i = 0; i < 2; ++i) {
    NonEmptyString removal_message(RandomAlphaNumericString(RandomUint32() % 20 + 10));
    {
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));

      EXPECT_EQ(kSuccess, test_elements_1_.RemoveContact(public_id_1_, public_id_2_,
                                                         removal_message));
      EXPECT_TRUE(test_elements_1_.GetContacts(public_id_1_).empty());

      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
    }
    {
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
      while (!testing_variables_2_.removed)
        Sleep(bptime::milliseconds(100));

      EXPECT_EQ(removal_message, testing_variables_2_.removal_message);
      bool contact_deleted(false);
      while (!contact_deleted)
        contact_deleted = test_elements_2_.GetContacts(public_id_2_).empty();
      EXPECT_TRUE(contact_deleted);

      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
    }

    const NonEmptyString request_message(RandomAlphaNumericString(RandomUint32() % 20 + 10));

    if (i % 2 == 0) {
      testing_variables_2_.newly_contacted = false;
      DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_);
      test_elements_1_.AddContact(public_id_1_, public_id_2_, request_message);
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));

      DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_);
      while (!testing_variables_2_.newly_contacted)
        Sleep(bptime::milliseconds(100));
      EXPECT_EQ(testing_variables_2_.contact_request_message, request_message);
      test_elements_2_.ConfirmContact(public_id_2_, public_id_1_);
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
    } else {
      testing_variables_1_.newly_contacted = false;
      DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_);
      test_elements_2_.AddContact(public_id_2_, public_id_1_, request_message);
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));

      DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_);
      while (!testing_variables_1_.newly_contacted)
        Sleep(bptime::milliseconds(100));
      EXPECT_EQ(testing_variables_1_.contact_request_message, request_message);
      test_elements_1_.ConfirmContact(public_id_1_, public_id_2_);
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
    }
  }
}

TEST_F(TwoUsersApiTest, FUNC_AddContactWithMessage) {
  DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_);
  const NonEmptyString public_id_3(RandomAlphaNumericString(RandomUint32() % 30 + 1));
  test_elements_1_.CreatePublicId(public_id_3);
  testing_variables_1_.newly_contacted = false;
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));

  DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_);
  const NonEmptyString message(RandomAlphaNumericString(RandomUint32() % 90 + 10));
  test_elements_2_.AddContact(public_id_2_, public_id_3, message);
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));

  DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_);
  while (!testing_variables_1_.newly_contacted)
    Sleep(bptime::milliseconds(100));
  EXPECT_EQ(testing_variables_1_.contact_request_message, message);
  test_elements_1_.ConfirmContact(public_id_1_, public_id_3);
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
}

TEST_F(TwoUsersApiTest, FUNC_AddThenRemoveOfflineUser) {
  DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_);

  const NonEmptyString public_id_3(RandomAlphaNumericString(RandomUint32() % 30 + 1));
  test_elements_1_.CreatePublicId(public_id_3);

  const NonEmptyString add_message(RandomAlphaNumericString(RandomUint32() % 90));
  EXPECT_EQ(kSuccess, test_elements_1_.AddContact(public_id_3, public_id_2_, add_message));

  const NonEmptyString remove_message(RandomAlphaNumericString(RandomUint32() % 90));
  EXPECT_EQ(kSuccess, test_elements_1_.RemoveContact(public_id_3, public_id_2_, remove_message));

  EXPECT_TRUE(test_elements_1_.GetContacts(public_id_3).empty());

  DoFullLogOut(test_elements_1_);

  testing_variables_2_.newly_contacted = false;
  testing_variables_2_.removed = false;
  DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_);

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

  DoFullLogOut(test_elements_2_);
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
