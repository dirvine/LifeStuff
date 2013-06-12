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
#include "maidsafe/lifestuff/tests/test_utils.h"

namespace maidsafe {

namespace lifestuff {

namespace test {

TEST_F(OneUserApiTest, BEH_CopyEmptyDirectoryToDrive) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  fs::path directory(CreateTestDirectory(*test_dir_));
  ASSERT_TRUE(fs::exists(directory));
  fs::copy_directory(directory, test_elements.mount_path() / directory.filename());
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename()));

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, BEH_CopyNonemptyDirectoryToDriveThenDelete) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create empty directory on disk...
  fs::path directory(CreateTestDirectory(*test_dir_));
  ASSERT_TRUE(fs::exists(directory, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Create a file in newly created directory...
  fs::path file(CreateTestFile(directory, file_size));
  // Copy directory and file to the drive...
  ASSERT_TRUE(CopyDirectories(directory, test_elements.mount_path()));
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename() / file.filename(),
                         error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Delete the directory along with its contents...
  ASSERT_EQ(2U, fs::remove_all(test_elements.mount_path() / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(test_elements.mount_path() / directory.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(test_elements.mount_path() / directory.filename() / file.filename()));

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, BEH_CopyNonemptyDirectoryToDriveDeleteThenRecopy) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  int64_t file_size(0);
  // Create empty directory on disk...
  fs::path directory(CreateTestDirectory(*test_dir_));
  ASSERT_TRUE(fs::exists(directory));
  // Create a file in newly created directory...
  fs::path file(CreateTestFile(directory, file_size));
  // Copy directory and file to virtual drive...
  ASSERT_TRUE(CopyDirectories(directory, test_elements.mount_path()));
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename()));
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename() / file.filename()));
  // Delete the directory along with its contents...
  boost::system::error_code error_code;
  ASSERT_EQ(2U, fs::remove_all(test_elements.mount_path() / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(test_elements.mount_path() / directory.filename()));
  ASSERT_FALSE(fs::exists(test_elements.mount_path() / directory.filename() / file.filename()));
  // Re-copy directory and file to virtual drive...
  ASSERT_TRUE(CopyDirectories(directory, test_elements.mount_path()));
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename()));
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename() / file.filename()));

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, BEH_CopyNonemptyDirectoryThenRename) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create empty directory on disk...
  fs::path directory(CreateTestDirectory(*test_dir_));
  ASSERT_TRUE(fs::exists(directory, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Create a file in newly created directory...
  fs::path file(CreateTestFile(directory, file_size));
  // Copy directory and file to virtual drive...
  ASSERT_TRUE(CopyDirectories(directory, test_elements.mount_path()));
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename() / file.filename(),
                         error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Rename the directory...
  fs::path new_directory_name(test_elements.mount_path() / maidsafe::RandomAlphaNumericString(5));
  fs::rename(test_elements.mount_path() / directory.filename(), new_directory_name, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(test_elements.mount_path() / directory.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(new_directory_name, error_code));
  ASSERT_EQ(error_code.value(), 0);

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, BEH_CopyNonemptyDirectoryRenameThenRecopy) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create empty directory on disk...
  fs::path directory(CreateTestDirectory(*test_dir_));
  ASSERT_TRUE(fs::exists(directory, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Create a file in newly created directory...
  fs::path file(CreateTestFile(directory, file_size));
  // Copy directory and file to virtual drive...
  ASSERT_TRUE(CopyDirectories(directory, test_elements.mount_path()));
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename() / file.filename(),
                         error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Rename the directory...
  fs::path new_directory_name(test_elements.mount_path() / maidsafe::RandomAlphaNumericString(5));
  fs::rename(test_elements.mount_path() / directory.filename(), new_directory_name, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(test_elements.mount_path() / directory.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(new_directory_name));
  // Re-copy disk directory and file to virtual drive...
  ASSERT_TRUE(CopyDirectories(directory, test_elements.mount_path()));
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename() / file.filename(),
                         error_code));
  ASSERT_EQ(error_code.value(), 0);

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, FUNC_CopyDirectoryContainingFiles) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  boost::system::error_code error_code;
  // Create directory with random number of files...
  fs::path directory(CreateDirectoryContainingFiles(*test_dir_));
  ASSERT_FALSE(directory.empty());
  // Copy directory to virtual drive...
  ASSERT_TRUE(CopyDirectories(directory, test_elements.mount_path()));
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, FUNC_CopyDirectoryContainingFilesAndDirectories) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  boost::system::error_code error_code;
  // Create directories hierarchy some of which containing files...
  fs::path directories(CreateTestDirectoriesAndFiles(*test_dir_));
  ASSERT_TRUE(fs::exists(directories));
  // Copy hierarchy to virtual drive...
  ASSERT_TRUE(CopyDirectories(directories, test_elements.mount_path()));
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directories.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, FUNC_CopyFileThenCopyCopiedFile) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file, test_elements.mount_path() / file.filename(),
                fs::copy_option::fail_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive again...
  fs::copy_file(file,
                test_elements.mount_path() / file.filename(),
                fs::copy_option::overwrite_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0) << error_code.message();
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, FUNC_CopyFileDeleteThenRecopy) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file, test_elements.mount_path() / file.filename(),
                fs::copy_option::fail_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Delete the file...
  fs::remove(test_elements.mount_path() / file.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  // Copy file to virtual drive again...
  fs::copy_file(file, test_elements.mount_path() / file.filename(),
                fs::copy_option::fail_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, FUNC_CopyFileRenameThenRecopy) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file, test_elements.mount_path() / file.filename(),
                fs::copy_option::fail_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Rename the file...
  fs::path new_file_name(test_elements.mount_path() / (RandomAlphaNumericString(5) + ".txt"));
  fs::rename(test_elements.mount_path() / file.filename(), new_file_name, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(new_file_name, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive again...
  fs::copy_file(file, test_elements.mount_path() / file.filename(),
                fs::copy_option::fail_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(*test_dir_ / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, BEH_CopyFileThenRead) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file, test_elements.mount_path() / file.filename(),
                fs::copy_option::fail_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Write virtual drive file back to a disk file...
  fs::path test_file(*test_dir_ / (RandomAlphaNumericString(5) + ".txt"));
  fs::copy_file(test_elements.mount_path() / file.filename(),
                test_file,
                fs::copy_option::overwrite_if_exists);
  ASSERT_TRUE(fs::exists(test_file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Compare content in the two files...
  ASSERT_EQ(fs::file_size(test_file), fs::file_size(file));
  ASSERT_TRUE(CompareFileContents(test_file, file));

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, FUNC_CopyFileRenameThenRead) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file, test_elements.mount_path() / file.filename(),
                fs::copy_option::fail_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Rename the file...
  fs::path new_file_name(test_elements.mount_path() / (RandomAlphaNumericString(5) + ".txt"));
  fs::rename(test_elements.mount_path() / file.filename(), new_file_name, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(new_file_name, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Write virtual drive file back to a disk file...
  fs::path test_file(*test_dir_ / new_file_name.filename());
  fs::copy_file(new_file_name, test_file, fs::copy_option::overwrite_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Compare content in the two files...
  ASSERT_TRUE(CompareFileContents(test_file, file));

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, FUNC_CopyFileDeleteThenTryToRead) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file, test_elements.mount_path() / file.filename(),
                fs::copy_option::fail_if_exists);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Delete the file...
  fs::remove(test_elements.mount_path() / file.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  // Write virtual drive file back to a disk file...
  fs::path test_file(*test_dir_ / (RandomAlphaNumericString(5) + ".txt"));
  fs::copy_file(test_elements.mount_path() / file.filename(),
                test_file,
                fs::copy_option::overwrite_if_exists,
                error_code);
  ASSERT_NE(error_code.value(), 0);
  // Compare content in the two files...
  ASSERT_FALSE(CompareFileContents(test_file, file));

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, BEH_CreateFileOnDriveThenRead) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on virtual drive...
  fs::path file(CreateTestFile(test_elements.mount_path(), file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Write virtual drive file out to disk...
  fs::path test_file(*test_dir_ / file.filename());
  fs::copy_file(file, test_file, fs::copy_option::overwrite_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, BEH_CopyFileModifyThenRead) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file, test_elements.mount_path() / file.filename(),
                fs::copy_option::fail_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Modify the file...
  ASSERT_TRUE(ModifyFile(test_elements.mount_path() / file.filename(), file_size));
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Write virtual drive file back to a disk file...
  fs::path test_file(*test_dir_ / (RandomAlphaNumericString(5) + ".txt"));
  fs::copy_file(test_elements.mount_path() / file.filename(),
                test_file,
                fs::copy_option::overwrite_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0);
  // Compare content in the two files...
  ASSERT_FALSE(CompareFileContents(test_file, file));

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, FUNC_CheckFailures) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file0(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file0, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file0, test_elements.mount_path() / file0.filename(),
                fs::copy_option::fail_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy same file to virtual drive again...
  fs::copy_file(file0, test_elements.mount_path() / file0.filename(),
                fs::copy_option::fail_if_exists,
                error_code);
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Create a file with the same name on the virtual drive...
  ASSERT_TRUE(CreateFileAt(test_elements.mount_path() / file0.filename()));
  ASSERT_TRUE(fs::exists(file0, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Create another file on disk...
  fs::path file1(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file1, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy it to virtual drive...
  fs::copy_file(file1, test_elements.mount_path() / file1.filename(),
                fs::copy_option::fail_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file1.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);

  // Rename to first file name...
  fs::rename(test_elements.mount_path() / file1.filename(),
             test_elements.mount_path() / file0.filename(),
             error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file0.filename(), error_code));
  ASSERT_FALSE(fs::exists(test_elements.mount_path() / file1.filename(), error_code));
  ASSERT_EQ(crypto::HashFile<crypto::Tiger>(file1),
            crypto::HashFile<crypto::Tiger>(test_elements.mount_path() / file0.filename()));
  // Rename mirror likewise...
  fs::rename(*test_dir_ / file1.filename(), *test_dir_ / file0.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(*test_dir_ / file0.filename(), error_code));
  ASSERT_FALSE(fs::exists(*test_dir_ / file1.filename(), error_code));
  // Delete the first file...
  ASSERT_TRUE(fs::remove(test_elements.mount_path() / file0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(test_elements.mount_path() / file0.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  // Delete the first file again...
  ASSERT_FALSE(fs::remove(test_elements.mount_path() / file0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(test_elements.mount_path() / file0.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);

  // Repeat above for directories
  // Create directory on disk...
  fs::path directory0(CreateTestDirectory(*test_dir_));
  ASSERT_TRUE(fs::exists(directory0, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy directory to virtual drive...
  fs::copy_directory(directory0, test_elements.mount_path() / directory0.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy same directory to virtual drive again...
  fs::copy_directory(directory0, test_elements.mount_path() / directory0.filename(), error_code);
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Create a directory with the same name on the virtual drive...
  ASSERT_FALSE(fs::create_directory(test_elements.mount_path() / directory0.filename(),
                                    error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(directory0, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Create another directory on disk...
  fs::path directory1(CreateTestDirectory(*test_dir_));
  ASSERT_TRUE(fs::exists(directory1, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy it to virtual drive...
  fs::copy_directory(directory1, test_elements.mount_path() / directory1.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory1.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);

  // Rename to first directory name...
  fs::rename(test_elements.mount_path() / directory1.filename(),
             test_elements.mount_path() / directory0.filename(),
             error_code);

  // From boost filesystem docs: if new_p resolves to an existing directory,
  // it is removed if empty on POSIX but is an error on Windows.
#ifdef WIN32
  ASSERT_NE(error_code.value(), 0);
#else
  ASSERT_EQ(error_code.value(), 0);
#endif
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory0.filename(), error_code));
  // Delete the first directory...
  ASSERT_TRUE(fs::remove(test_elements.mount_path() / directory0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(test_elements.mount_path() / directory0.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);

  // Delete the first directory again...
  ASSERT_FALSE(fs::remove(test_elements.mount_path() / directory0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(test_elements.mount_path() / directory0.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  // TODO(Fraser#5#): 2011-05-30 - Add similar test for non-empty directory.

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, FUNC_FunctionalTest) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
  Sleep(boost::posix_time::seconds(5));

  // Test drive...
  EXPECT_TRUE(DoRandomEvents(test_elements.mount_path(), *test_dir_));

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
