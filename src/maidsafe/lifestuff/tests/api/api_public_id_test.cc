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

TEST_F(OneUserApiTest, FUNC_CreatePublicIdCases) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  EXPECT_NE(kSuccess, test_elements.CreatePublicId(NonEmptyString(RandomAlphaNumericString(31))));
  EXPECT_NE(kSuccess, test_elements.CreatePublicId(NonEmptyString(" ")));
  EXPECT_NE(kSuccess,
            test_elements.CreatePublicId(NonEmptyString(" " +
                                                        RandomAlphaNumericString(RandomUint32() %
                                                                                 26 + 4))));
  EXPECT_NE(kSuccess,
            test_elements.CreatePublicId(NonEmptyString(RandomAlphaNumericString(RandomUint32() %
                                                                                 26 + 4) +
                                                        " ")));
  EXPECT_NE(kSuccess,
            test_elements.CreatePublicId(NonEmptyString(RandomAlphaNumericString(RandomUint32() %
                                                                                 13 + 2) +
                                                        "  " +
                                                        RandomAlphaNumericString(RandomUint32() %
                                                                                 14 + 1))));
  EXPECT_NE(kSuccess,
            test_elements.CreatePublicId(NonEmptyString(" " +
                                                        RandomAlphaNumericString(RandomUint32() %
                                                                                 13 + 1) +
                                                        "  " +
                                                        RandomAlphaNumericString(RandomUint32() %
                                                                                 13 + 1) +
                                                        " ")));
  NonEmptyString public_id(RandomAlphaNumericString(RandomUint32() % 14 + 1) +
                           " " +
                           RandomAlphaNumericString(RandomUint32() % 15 + 1));
  EXPECT_EQ(kSuccess, test_elements.CreatePublicId(public_id));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, FUNC_CreateSamePublicIdConsecutively) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  NonEmptyString new_public_id(RandomAlphaNumericString(6));
  EXPECT_EQ(kSuccess, test_elements.CreatePublicId(new_public_id));
  EXPECT_NE(kSuccess, test_elements.CreatePublicId(new_public_id));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, FUNC_CreateSamePublicIdSimultaneously) {
  NonEmptyString new_public_id(RandomAlphaNumericString(6));
  int result_1(0);
  int result_2(0);

  std::vector<std::pair<int, int> > sleep_values;
  sleep_values.push_back(std::make_pair(0, 0));
  sleep_values.push_back(std::make_pair(100, 200));
  sleep_values.push_back(std::make_pair(100, 150));
  sleep_values.push_back(std::make_pair(0, 10));

  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }

  for (size_t i = 0; i < sleep_values.size(); ++i) {
    {
      PopulateSlots(lifestuff_slots_, testing_variables_);
      LifeStuff test_elements(lifestuff_slots_, *test_dir_);
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, pin_, password_));
      boost::thread thread_1([&] {
                               sleepthreads::RunCreatePublicId(test_elements,
                                                               std::ref(result_1),
                                                               new_public_id,
                                                               sleep_values.at(i));
                             });
      boost::thread thread_2([&] {
                               sleepthreads::RunCreatePublicId(test_elements,
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

      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
    }

    {
      PopulateSlots(lifestuff_slots_, testing_variables_);
      LifeStuff test_elements(lifestuff_slots_, *test_dir_);
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, pin_, password_));

      int new_instances(0);
      std::vector<NonEmptyString>::iterator it;
      std::vector<NonEmptyString> names(test_elements.PublicIdsList());
      for (it = names.begin(); it < names.end(); it++) {
        if (*it == new_public_id)
          ++new_instances;
      }
      EXPECT_EQ(new_instances, 1);
      new_public_id = NonEmptyString(RandomAlphaNumericString(new_public_id.string().length() + 1));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
    }
  }
}

TEST_F(OneUserApiTest, FUNC_AddInvalidContact) {
  NonEmptyString own_public_id(RandomAlphaNumericString(5));
  NonEmptyString public_id_1(RandomAlphaNumericString(6));
  NonEmptyString public_id_2(RandomAlphaNumericString(7));
  NonEmptyString message(RandomAlphaNumericString(5));

  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  test_elements.CreatePublicId(own_public_id);
  EXPECT_NE(kSuccess,
            test_elements.AddContact(own_public_id, NonEmptyString(" "), message.string()));
  EXPECT_NE(kSuccess, test_elements.AddContact(own_public_id, public_id_1, message.string()));
  EXPECT_NE(kSuccess, test_elements.AddContact(public_id_1, public_id_2, message.string()));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, FUNC_AddOwnPublicIdAsContact) {
  NonEmptyString public_id_1(RandomAlphaNumericString(6));
  NonEmptyString public_id_2(RandomAlphaNumericString(7));
  NonEmptyString message(RandomAlphaNumericString(5));

  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  test_elements.CreatePublicId(public_id_1);
  test_elements.CreatePublicId(public_id_2);

  EXPECT_NE(kSuccess, test_elements.AddContact(public_id_1, public_id_1, message.string()));
  EXPECT_NE(kSuccess, test_elements.AddContact(public_id_1, public_id_2, message.string()));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, FUNC_ChangeProfilePictureAfterSaveSession) {
  NonEmptyString public_id(RandomAlphaNumericString(5)), retrieved_picture;
  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
    EXPECT_EQ(kSuccess, test_elements.CreatePublicId(public_id));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }

  for (int n(1001); n > 1; n-=100) {
    NonEmptyString profile_picture1(RandomString(1177 * n)),
                   profile_picture2(RandomString(1177 * n));
    {
      PopulateSlots(lifestuff_slots_, testing_variables_);
      LifeStuff test_elements(lifestuff_slots_, *test_dir_);
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, pin_, password_));
      EXPECT_EQ(kSuccess, test_elements.ChangeProfilePicture(public_id, profile_picture1));
      retrieved_picture = test_elements.GetOwnProfilePicture(public_id);
      EXPECT_TRUE(profile_picture1 == retrieved_picture);
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
    }

    {
      PopulateSlots(lifestuff_slots_, testing_variables_);
      LifeStuff test_elements(lifestuff_slots_, *test_dir_);
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, pin_, password_));
      retrieved_picture = test_elements.GetOwnProfilePicture(public_id);
      EXPECT_TRUE(profile_picture1 == retrieved_picture);
      EXPECT_EQ(kSuccess, test_elements.ChangeProfilePicture(public_id, profile_picture2));
      retrieved_picture = test_elements.GetOwnProfilePicture(public_id);
      EXPECT_TRUE(profile_picture2 == retrieved_picture);
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
    }

    {
      PopulateSlots(lifestuff_slots_, testing_variables_);
      LifeStuff test_elements(lifestuff_slots_, *test_dir_);
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, pin_, password_));
      retrieved_picture = test_elements.GetOwnProfilePicture(public_id);
      EXPECT_TRUE(profile_picture2 == retrieved_picture);
      EXPECT_EQ(kSuccess, test_elements.ChangeProfilePicture(public_id, profile_picture1));
      retrieved_picture = test_elements.GetOwnProfilePicture(public_id);
      EXPECT_TRUE(profile_picture1 == retrieved_picture);
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
    }

    {
      PopulateSlots(lifestuff_slots_, testing_variables_);
      LifeStuff test_elements(lifestuff_slots_, *test_dir_);
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, pin_, password_));
      retrieved_picture = test_elements.GetOwnProfilePicture(public_id);
      EXPECT_TRUE(profile_picture1 == retrieved_picture);
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
    }
  }
}

TEST_F(TwoUsersApiTest, FUNC_CreateSamePublicIdConsecutively) {
  NonEmptyString new_public_id(RandomAlphaNumericString(6));
  {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
    EXPECT_EQ(kSuccess, test_elements1.CreatePublicId(new_public_id));
    EXPECT_NE(kSuccess, test_elements1.CreatePublicId(new_public_id));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }

  {
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
    EXPECT_NE(kSuccess, test_elements2.CreatePublicId(new_public_id));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }

  int new_instances(0);
  std::vector<NonEmptyString>::iterator it;
  std::vector<NonEmptyString> names;
  {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
    names = test_elements1.PublicIdsList();
    for (it = names.begin(); it < names.end(); it++) {
      if (*it == new_public_id)
        ++new_instances;
    }
    EXPECT_EQ(new_instances, 1);
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }

  {
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
    names = test_elements2.PublicIdsList();
    for (it = names.begin(); it < names.end(); it++) {
      if (*it == new_public_id)
        ++new_instances;
    }
    EXPECT_EQ(new_instances, 1);
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }
}

/*
TEST_F(TwoUsersApiTest, DISABLED_FUNC_CreateSamePublicIdSimultaneously) {
#ifdef MAIDSAFE_LINUX
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));

  NonEmptyString new_public_id(RandomAlphaNumericString(6));
  int result_1(0), result_2(0);

  std::vector<std::pair<int, int>> sleep_values;
  sleep_values.push_back(std::make_pair(0, 200));
  sleep_values.push_back(std::make_pair(100, 200));
  sleep_values.push_back(std::make_pair(100, 150));
  sleep_values.push_back(std::make_pair(0, 10));

  for (size_t i = 0; i < sleep_values.size(); ++i) {
    boost::thread thread_1([&] {
                             sleepthreads::RunCreatePublicId(test_elements1,
                                                             std::ref(result_1),
                                                             new_public_id,
                                                             sleep_values.at(i));
                           });
    boost::thread thread_2([&] {
                             sleepthreads::RunCreatePublicId(test_elements2,
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

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));

    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));

    int new_instances(0);
    std::vector<NonEmptyString>::iterator it;
    std::vector<NonEmptyString> names(test_elements1.PublicIdsList());
    for (it = names.begin(); it < names.end(); it++) {
      if (*it == new_public_id)
        ++new_instances;
    }
    names = test_elements2.PublicIdsList();
    for (it = names.begin(); it < names.end(); it++) {
      if (*it == new_public_id)
        ++new_instances;
    }
    EXPECT_EQ(new_instances, 1);
    new_public_id = NonEmptyString(RandomAlphaNumericString(new_public_id.string().length() + 1));
  }

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
#endif
}
*/

TEST_F(TwoUsersApiTest, FUNC_SendFileSaveToGivenPath) {
  boost::system::error_code error_code;
  fs::path file_path1;
  NonEmptyString file_name1(RandomAlphaNumericString(8)), file_content1(RandomString(5 * 1024));
  std::string file_name2(RandomAlphaNumericString(8));

  {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
    EXPECT_TRUE(WriteFile(test_elements1.mount_path() / file_name1.string(),
                          file_content1.string()));
    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements1.SendFile(public_id_1_, public_id_2_, file_path1));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }
  {
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.file_transfer_received)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables_2_.file_id.empty());
    EXPECT_EQ(file_name1.string(), testing_variables_2_.file_name);
    EXPECT_NE(kSuccess,
              test_elements2.AcceptSentFile(NonEmptyString(testing_variables_2_.file_id)));
    EXPECT_NE(kSuccess,
              test_elements2.AcceptSentFile(NonEmptyString(testing_variables_2_.file_id),
                                            test_elements2.mount_path() / file_name2,
                                            &file_name2));
    EXPECT_EQ(kSuccess,
              test_elements2.AcceptSentFile(NonEmptyString(testing_variables_2_.file_id),
                                            test_elements2.mount_path() / file_name2));

    EXPECT_TRUE(fs::exists(test_elements2.mount_path() / file_name2, error_code));
    EXPECT_EQ(0, error_code.value());

    Sleep(bptime::seconds(2));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }
}

TEST_F(TwoUsersApiTest, FUNC_SendFileSaveToDefaultLocation) {
  boost::system::error_code error_code;
  fs::path file_path1;
  NonEmptyString file_name1(RandomAlphaNumericString(8)),
                 file_content1(RandomString(5 * 1024));
  {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
    EXPECT_TRUE(WriteFile(test_elements1.mount_path() / file_name1.string(),
                          file_content1.string()));
    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements1.SendFile(public_id_1_, public_id_2_, file_path1));

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }
  {
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.file_transfer_received)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.file_id.empty());
    EXPECT_EQ(file_name1.string(), testing_variables_2_.file_name);
    std::string saved_file_name;
    NonEmptyString file_id(testing_variables_2_.file_id);
    EXPECT_EQ(kSuccess, test_elements2.AcceptSentFile(file_id, fs::path(), &saved_file_name));
    EXPECT_EQ(file_name1.string(), saved_file_name);
    fs::path path2(test_elements2.mount_path() / kMyStuff / kDownloadStuff / saved_file_name);
    EXPECT_TRUE(fs::exists(path2, error_code));
    EXPECT_EQ(0, error_code.value());
    std::string file_content2;
    EXPECT_TRUE(ReadFile(path2, &file_content2));
    EXPECT_EQ(file_content1.string(), file_content2);

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }
  {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements1.SendFile(public_id_1_, public_id_2_, file_path1));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }
  {
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.file_transfer_received)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.file_id.empty());
    EXPECT_EQ(file_name1.string(), testing_variables_2_.file_name);
    std::string saved_file_name;
    NonEmptyString file_id(testing_variables_2_.file_id);
    EXPECT_EQ(kSuccess, test_elements2.AcceptSentFile(file_id, fs::path(), &saved_file_name));
    EXPECT_EQ((file_name1 + NonEmptyString(" (1)")).string(), saved_file_name);
    fs::path path2a(test_elements2.mount_path() / kMyStuff / kDownloadStuff / file_name1.string()),
             path2b(test_elements2.mount_path() / kMyStuff / kDownloadStuff / saved_file_name);

    EXPECT_TRUE(fs::exists(path2a, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(path2b, error_code));
    EXPECT_EQ(0, error_code.value());
    std::string file_content2;
    EXPECT_TRUE(ReadFile(path2b, &file_content2));
    EXPECT_TRUE(file_content1.string() == file_content2);
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }
}

TEST_F(TwoUsersApiTest, FUNC_SendFileAcceptToDeletedDefaultLocation) {
  boost::system::error_code error_code;
  fs::path file_path1;
  NonEmptyString file_name1(RandomAlphaNumericString(8)),
                 file_content1(RandomString(5 * 1024));
  {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
    file_path1 = test_elements1.mount_path() / file_name1.string();
    EXPECT_TRUE(WriteFile(test_elements1.mount_path() / file_name1.string(),
                          file_content1.string()));
    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements1.SendFile(public_id_1_, public_id_2_, file_path1));

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }
  {
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.file_transfer_received)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.file_id.empty());
    EXPECT_EQ(file_name1.string(), testing_variables_2_.file_name);

    // Delete accepted files dir
    fs::remove_all(test_elements2.mount_path() / kMyStuff, error_code);
    EXPECT_EQ(0, error_code.value());
    EXPECT_FALSE(fs::exists(test_elements2.mount_path() / kMyStuff, error_code));
    EXPECT_NE(0, error_code.value());

    std::string saved_file_name;
    NonEmptyString file_id(testing_variables_2_.file_id);
    EXPECT_EQ(kSuccess, test_elements2.AcceptSentFile(file_id, fs::path(), &saved_file_name));
    EXPECT_EQ(file_name1.string(), saved_file_name);
    fs::path path2(test_elements2.mount_path() / kMyStuff / kDownloadStuff / saved_file_name);
    EXPECT_TRUE(fs::exists(path2, error_code));
    EXPECT_EQ(0, error_code.value());
    std::string file_content2;
    EXPECT_TRUE(ReadFile(path2, &file_content2));
    EXPECT_EQ(file_content1.string(), file_content2);

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }
}

/*
TEST(TwoUsersApiTest, FUNC_SendFileWithRejection) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  NonEmptyString keyword1(RandomAlphaNumericString(6)),
                 pin1(CreatePin()),
                 password1(RandomAlphaNumericString(6)),
                 public_id1(RandomAlphaNumericString(5));
  NonEmptyString keyword2(RandomAlphaNumericString(6)),
                 pin2(CreatePin()),
                 password2(RandomAlphaNumericString(6)),
                 public_id2(RandomAlphaNumericString(5));
  TestingVariables testing_variables1, testing_variables2;
  Slots lifestuff_slots1, lifestuff_slots2;
  int file_count(0), file_max(10);
  size_t files_expected(file_max);
  std::vector<fs::path> file_paths;
  std::vector<std::string> file_contents, received_ids, received_names;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(lifestuff_slots1,
                                                   lifestuff_slots2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   keyword1, pin1, password1,
                                                   public_id1,
                                                   keyword2, pin2, password2,
                                                   public_id2));

  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword1, pin1, password1));

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
      EXPECT_EQ(file_paths[st].filename().string(), received_names[st]);
      EXPECT_EQ(kSuccess, test_elements2.RejectSentFile(NonEmptyString(received_ids[st])));
      EXPECT_FALSE(fs::exists(path2 / received_names[st], error_code));
      EXPECT_NE(0, error_code.value());
      std::string hidden(received_ids[st] + kHiddenFileExtension), content;
      EXPECT_NE(kSuccess, test_elements2.ReadHiddenFile(test_elements2.mount_path() / hidden,
                                                        &content));
    }

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }
}
*/

TEST_F(TwoUsersApiTest, FUNC_ProfilePicture) {
  NonEmptyString file_content1(RandomString(1)), file_content2(RandomString(5 * 1024));
  {
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
    // Setting of profile image
    EXPECT_EQ(kSuccess, test_elements2.ChangeProfilePicture(public_id_2_, file_content2));
    Sleep(bptime::seconds(1));

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }
  {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
    while (!testing_variables_1_.picture_updated)
      Sleep(bptime::milliseconds(100));

    file_content1 = test_elements1.GetContactProfilePicture(public_id_1_, public_id_2_);
    EXPECT_TRUE(file_content2 == file_content1);
    EXPECT_NE(kSuccess, test_elements1.ChangeProfilePicture(public_id_1_, NonEmptyString(" ")));

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }
  {
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
    // Setting of profile image
    EXPECT_EQ(kSuccess, test_elements2.ChangeProfilePicture(public_id_2_, kBlankProfilePicture));

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }
  {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
    while (!testing_variables_1_.picture_updated)
      Sleep(bptime::milliseconds(100));

    file_content1 = test_elements1.GetContactProfilePicture(public_id_1_, public_id_2_);
    EXPECT_TRUE(kBlankProfilePicture == file_content1);

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }
}

TEST_F(TwoUsersApiTest, FUNC_ProfilePictureAndLogOut) {
  NonEmptyString file_content1(RandomString(1)), file_content2(RandomString(5 * 1024));
  {
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
    // Setting of profile image
    EXPECT_EQ(kSuccess, test_elements2.ChangeProfilePicture(public_id_2_, file_content2));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }

  {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
    file_content1 = test_elements1.GetContactProfilePicture(public_id_1_, public_id_2_);
    EXPECT_TRUE(file_content2 == file_content1);
    EXPECT_NE(kSuccess, test_elements1.ChangeProfilePicture(public_id_1_, NonEmptyString(" ")));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }

  {
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
    // Setting of profile image
    EXPECT_EQ(kSuccess, test_elements2.ChangeProfilePicture(public_id_2_, kBlankProfilePicture));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }

  {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
    file_content1 = test_elements1.GetContactProfilePicture(public_id_1_, public_id_2_);
    EXPECT_TRUE(kBlankProfilePicture == file_content1);
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }
}

/*
TEST_F(TwoUsersApiTest, DISABLED_FUNC_RemoveContact) {
  NonEmptyString removal_message("It's not me, it's you.");
  {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));

    EXPECT_EQ(kSuccess, test_elements1.RemoveContact(public_id_1_, public_id_2_,
                                                       removal_message.string()));
    EXPECT_TRUE(test_elements1.GetContacts(public_id_1_).empty());

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }
  {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.removed)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(removal_message.string(), testing_variables_2_.removal_message);
    bool contact_deleted(false);
    while (!contact_deleted)
      contact_deleted = test_elements2.GetContacts(public_id_2_).empty();
    EXPECT_TRUE(contact_deleted);

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }
}
*/

/*
TEST_F(TwoUsersApiTest, DISABLED_FUNC_RemoveContactAddContact) {
  for (int i = 0; i < 2; ++i) {
    NonEmptyString removal_message(RandomAlphaNumericString(RandomUint32() % 20 + 10));
    {
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));

      EXPECT_EQ(kSuccess, test_elements1.RemoveContact(public_id_1_, public_id_2_,
                                                         removal_message.string()));
      EXPECT_TRUE(test_elements1.GetContacts(public_id_1_).empty());

      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
    }
    {
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
      while (!testing_variables_2_.removed)
        Sleep(bptime::milliseconds(100));

      EXPECT_EQ(removal_message.string(), testing_variables_2_.removal_message);
      bool contact_deleted(false);
      while (!contact_deleted)
        contact_deleted = test_elements2.GetContacts(public_id_2_).empty();
      EXPECT_TRUE(contact_deleted);

      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
    }

    const NonEmptyString request_message(RandomAlphaNumericString(RandomUint32() % 20 + 10));

    if (i % 2 == 0) {
      testing_variables_2_.newly_contacted = false;
      DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_);
      test_elements1.AddContact(public_id_1_, public_id_2_, request_message.string());
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));

      DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_);
      while (!testing_variables_2_.newly_contacted)
        Sleep(bptime::milliseconds(100));
      EXPECT_EQ(testing_variables_2_.contact_request_message, request_message.string());
      test_elements2.ConfirmContact(public_id_2_, public_id_1_);
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
    } else {
      testing_variables_1_.newly_contacted = false;
      DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_);
      test_elements2.AddContact(public_id_2_, public_id_1_, request_message.string());
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));

      DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_);
      while (!testing_variables_1_.newly_contacted)
        Sleep(bptime::milliseconds(100));
      EXPECT_EQ(testing_variables_1_.contact_request_message, request_message.string());
      test_elements1.ConfirmContact(public_id_1_, public_id_2_);
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
    }
  }
}
*/

TEST_F(TwoUsersApiTest, FUNC_AddContactWithMessage) {
  const NonEmptyString public_id_3(RandomAlphaNumericString(RandomUint32() % 30 + 1));
  {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_);
    test_elements1.CreatePublicId(public_id_3);
    testing_variables_1_.newly_contacted = false;
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }

  const NonEmptyString message(RandomAlphaNumericString(RandomUint32() % 90 + 10));
  {
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_);
    test_elements2.AddContact(public_id_2_, public_id_3, message.string());
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }

  {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_);
    while (!testing_variables_1_.newly_contacted)
      Sleep(bptime::milliseconds(100));
    EXPECT_EQ(testing_variables_1_.contact_request_message, message.string());
    test_elements1.ConfirmContact(public_id_1_, public_id_3);
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }
}

/*
TEST_F(TwoUsersApiTest, DISABLED_FUNC_AddThenRemoveOfflineUser) {
  DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_);

  const NonEmptyString public_id_3(RandomAlphaNumericString(RandomUint32() % 30 + 1));
  test_elements1.CreatePublicId(public_id_3);

  const NonEmptyString add_message(RandomAlphaNumericString(RandomUint32() % 90));
  EXPECT_EQ(kSuccess, test_elements1.AddContact(public_id_3, public_id_2_, add_message.string()));

  const NonEmptyString remove_message(RandomAlphaNumericString(RandomUint32() % 90));
  EXPECT_EQ(kSuccess,
            test_elements1.RemoveContact(public_id_3, public_id_2_, remove_message.string()));

  EXPECT_TRUE(test_elements1.GetContacts(public_id_3).empty());

  DoFullLogOut(test_elements1);

  testing_variables_2_.newly_contacted = false;
  testing_variables_2_.removed = false;
  DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_);

  int i(0);
  while (!testing_variables_2_.newly_contacted && i < 60) {
    ++i;
    Sleep(bptime::milliseconds(100));
  }
  EXPECT_TRUE(testing_variables_2_.newly_contacted);
  EXPECT_EQ(add_message.string(), testing_variables_2_.contact_request_message);

  i = 0;
  while (!testing_variables_2_.removed && i < 60) {
    ++i;
    Sleep(bptime::milliseconds(100));
  }
  EXPECT_TRUE(testing_variables_2_.removed);
  EXPECT_EQ(remove_message.string(), testing_variables_2_.removal_message);

  EXPECT_EQ(1, test_elements2.GetContacts(public_id_2_).size());

  DoFullLogOut(test_elements2);
}
*/

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
