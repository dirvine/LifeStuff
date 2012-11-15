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

namespace maidsafe {

namespace lifestuff {

namespace test {

fs::path CreateTestFileWithContent(fs::path const& parent, const std::string &content) {
  fs::path file(parent / (RandomAlphaNumericString(5) + ".txt"));
  std::ofstream ofs;
  ofs.open(file.native().c_str(), std::ios_base::out | std::ios_base::binary);
  if (ofs.bad()) {
    LOG(kError) << "Can't open " << file;
  } else {
    ofs << content;
    ofs.close();
  }
  boost::system::error_code ec;
  EXPECT_TRUE(fs::exists(file, ec)) << file;
  EXPECT_EQ(0, ec.value());
  return file;
}

fs::path CreateTestFileWithSize(fs::path const& parent, size_t size) {
  std::string file_content = RandomString(size);
  return CreateTestFileWithContent(parent, file_content);
}

fs::path CreateTestFile(fs::path const& parent, int64_t &file_size) {
  size_t size = RandomUint32() % 4096;
  file_size = size;
  return CreateTestFileWithSize(parent, size);
}

bool CreateFileAt(fs::path const& path) {
  EXPECT_TRUE(fs::exists(path));
  size_t size = maidsafe::RandomInt32() % 1048576;  // 2^20

  LOG(kInfo) << "CreateFileAt: filename = " << path << " size " << size;

  std::string file_content = maidsafe::RandomAlphaNumericString(size);
  std::ofstream ofs;
  ofs.open(path.native().c_str(), std::ios_base::out | std::ios_base::binary);
  if (ofs.bad()) {
    LOG(kError) << "Can't open " << path;
    return false;
  } else {
    ofs << file_content;
    ofs.close();
  }
  EXPECT_TRUE(fs::exists(path));
  return true;
}

bool CompareFileContents(fs::path const& path1, fs::path const& path2) {
  std::ifstream efile, ofile;
  efile.open(path1.c_str());
  ofile.open(path2.c_str());

  if (efile.bad() || ofile.bad())
    return false;
  while (efile.good() && ofile.good())
    if (efile.get() != ofile.get())
      return false;
  if (!(efile.eof() && ofile.eof()))
    return false;
  return true;
}

bool ModifyFile(fs::path const& path, int64_t &file_size) {
  size_t size = maidsafe::RandomInt32() % 1048576;  // 2^20
  file_size = size;
  LOG(kInfo) << "ModifyFile: filename = " << path << " new size " << size;

  std::string new_file_content(maidsafe::RandomAlphaNumericString(size));
  std::ofstream ofs(path.c_str(), std::ios_base::out | std::ios_base::binary);
  if (!ofs.is_open() || ofs.bad()) {
    LOG(kError) << "Can't open " << path;
    return false;
  } else {
    try {
      ofs << new_file_content;
      if (ofs.bad()) {
        ofs.close();
        return false;
      }
      ofs.close();
    }
    catch(...) {
      LOG(kError) << "Write exception thrown.";
      return false;
    }
  }
  return true;
}

fs::path CreateTestDirectory(fs::path const& parent) {
  fs::path directory(parent / RandomAlphaNumericString(5));
  boost::system::error_code error_code;
  EXPECT_TRUE(fs::create_directories(directory, error_code)) << directory
              << ": " << error_code.message();
  EXPECT_EQ(0, error_code.value()) << directory << ": "
                                   << error_code.message();
  EXPECT_TRUE(fs::exists(directory, error_code)) << directory << ": "
                                                 << error_code.message();
  return directory;
}

fs::path CreateDirectoryContainingFiles(fs::path const& path) {
  int64_t file_size(0);
  LOG(kInfo) << "CreateDirectoryContainingFiles: directory = " << path;
  try {
    size_t r1 = 0;
    do {
      r1 = RandomUint32() % 11;
    } while (r1 < 2);

    fs::path directory(CreateTestDirectory(path)), check;

    for (size_t i = 0; i != r1; ++i) {
      check = CreateTestFile(directory, file_size);
      EXPECT_TRUE(fs::exists(check));
    }
    return directory;
  }
  catch(const std::exception &e) {
    LOG(kError) << e.what();
    return "";
  }
}

bool CopyDirectories(fs::path const& from, fs::path const& to) {
  LOG(kInfo) << "CopyDirectories: from " << from << " to " << (to / from.filename());

  fs::directory_iterator begin(from), end;

  if (!fs::exists(to / from.filename()))
    fs::create_directory(to / from.filename());
  EXPECT_TRUE(fs::exists(to / from.filename()));
  try {
    for (; begin != end; ++begin) {
      if (fs::is_directory(*begin)) {
        EXPECT_TRUE(CopyDirectories((*begin).path(), to / from.filename()));
      } else if (fs::is_regular_file(*begin)) {
        fs::copy_file((*begin).path(),
                      to / from.filename() / (*begin).path().filename(),
                      fs::copy_option::fail_if_exists);
        EXPECT_TRUE(fs::exists(to / from.filename() / (*begin).path().filename()));
      } else {
        if (fs::exists(*begin))
          LOG(kInfo) << "CopyDirectories: unknown type found.";
        else
          LOG(kInfo) << "CopyDirectories: nonexistant type found.";
        return false;
      }
    }
  }
  catch(...) {
    LOG(kError) << "CopyDirectories: Failed";
    return false;
  }
  return true;
}

bool RemoveDirectories(fs::path const& path) {
  LOG(kInfo) << "RemoveDirectories: " << path;
  boost::system::error_code error_code;
  fs::directory_iterator begin(path), end;
  try {
    for (; begin != end; ++begin) {
      if (fs::is_directory(*begin)) {
        EXPECT_TRUE(RemoveDirectories((*begin).path()));
        EXPECT_TRUE(fs::remove((*begin).path(), error_code));
        if (error_code.value() != 0) {
          EXPECT_TRUE(fs::remove((*begin).path(), error_code));
          if (error_code.value() != 0) {
            LOG(kError) << "Failed to remove " << (*begin).path();
            return false;
          }
        }
      } else if (fs::is_regular_file(*begin)) {
        EXPECT_TRUE(fs::remove((*begin).path(), error_code));
        if (error_code.value() != 0) {
          EXPECT_TRUE(fs::remove((*begin).path(), error_code));
          if (error_code.value() != 0) {
            LOG(kError) << "Failed to remove " << (*begin).path();
            return false;
          }
        }
      } else {
        EXPECT_TRUE(fs::remove((*begin).path(), error_code));
        if (error_code.value() != 0) {
          EXPECT_TRUE(fs::remove((*begin).path(), error_code));
          if (error_code.value() != 0) {
            LOG(kError) << "Failed to remove " << (*begin).path();
            return false;
          }
        }
      }
    }
  } catch(...) {
    LOG(kError) << "RemoveDirectories: Failed";
    return false;
  }
  return true;
}

fs::path CreateTestDirectoriesAndFiles(fs::path const& parent) {
  const size_t kMaxPathLength(200);
  size_t r1 = RandomUint32() % 6, r2, r3, r4;
  fs::path directory(CreateTestDirectory(parent)), check;
  int64_t file_size(0);

  boost::system::error_code error_code;
  for (size_t i = 0; i != r1; ++i) {
    r2 = RandomUint32() % 6;
    r3 = RandomUint32() % 6;
    if (parent.string().size() > kMaxPathLength)
      break;
    if (r2 < r3) {
      check = CreateTestDirectoriesAndFiles(directory);
      EXPECT_TRUE(fs::exists(check, error_code)) << check << ": "
                                                 << error_code.message();
      EXPECT_EQ(0, error_code.value()) << check << ": "
                                       << error_code.message();
    } else if (r2 > r3) {
      r4 = RandomUint32() % 6;
      for (size_t j = 0; j != r4; ++j) {
        check = CreateTestFile(directory, file_size);
        EXPECT_TRUE(fs::exists(check, error_code)) << check << ": "
                                                   << error_code.message();
        EXPECT_EQ(0, error_code.value()) << check << ": "
                                         << error_code.message();
      }
    } else {
      r4 = RandomUint32() % 6;
      for (size_t j = 0; j != r4; ++j) {
        check = CreateTestDirectory(directory);
        EXPECT_TRUE(fs::exists(check, error_code)) << check << ": "
                                                   << error_code.message();
        EXPECT_EQ(0, error_code.value()) << check << ": "
                                         << error_code.message();
      }
    }
  }
  return directory;
}

fs::path LocateNthFile(fs::path const& path, size_t n) {
  fs::recursive_directory_iterator begin(path), end;
  fs::path temp_path;
  size_t m = 0;
  try {
    for (; begin != end; ++begin) {
      if (fs::is_regular_file(*begin)) {
        temp_path = (*begin).path();
        if (++m == n)
          return temp_path;
      }
    }
  }
  catch(...) {
    LOG(kError) << "Test LocateNthFile: Failed";
    return fs::path();
  }
  // Return a potentially empty path whose index is less than n...
  return temp_path;
}

fs::path LocateNthDirectory(fs::path const& path, size_t n) {
  fs::recursive_directory_iterator begin(path), end;
  fs::path temp_path;
  size_t m = 0;
  try {
    for (; begin != end; ++begin) {
      if (fs::is_directory(*begin)) {
        temp_path = (*begin).path();
        if (++m == n)
          return temp_path;
      }
    }
  }
  catch(...) {
    LOG(kError) << "Test LocateNthDirectory: Failed";
    return fs::path();
  }
  // Return a potentially empty path whose index is less than n...
  return temp_path;
}

fs::path FindDirectoryOrFile(fs::path const& path,
                             fs::path const& find) {
  fs::recursive_directory_iterator begin(path), end;
  try {
    for (; begin != end; ++begin) {
        if ((*begin).path().filename() == find)
          return (*begin).path();
    }
  }
  catch(...) {
    LOG(kError) << "Test FindDirectoryOrFile: Failed";
    return fs::path();
  }
  // Failed to find 'find'...
  return fs::path();
}

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
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename() / file.filename(), error_code));
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
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename() / file.filename(), error_code));
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
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename() / file.filename(), error_code));
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
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / directory.filename() / file.filename(), error_code));
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
  fs::copy_file(file, test_elements.mount_path() / file.filename(), fs::copy_option::fail_if_exists, error_code);
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
  fs::copy_file(file, test_elements.mount_path() / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Delete the file...
  fs::remove(test_elements.mount_path() / file.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  // Copy file to virtual drive again...
  fs::copy_file(file, test_elements.mount_path() / file.filename(), fs::copy_option::fail_if_exists, error_code);
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
  fs::copy_file(file, test_elements.mount_path() / file.filename(), fs::copy_option::fail_if_exists, error_code);
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
  fs::copy_file(file, test_elements.mount_path() / file.filename(), fs::copy_option::fail_if_exists, error_code);
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
  fs::copy_file(file, test_elements.mount_path() / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Write virtual drive file back to a disk file...
  fs::path test_file(*test_dir_ / (RandomAlphaNumericString(5) + ".txt"));
  fs::copy_file(test_elements.mount_path() / file.filename(), test_file, fs::copy_option::overwrite_if_exists);
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
  fs::copy_file(file, test_elements.mount_path() / file.filename(), fs::copy_option::fail_if_exists, error_code);
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
  fs::copy_file(file, test_elements.mount_path() / file.filename(), fs::copy_option::fail_if_exists);
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
  fs::copy_file(file, test_elements.mount_path() / file.filename(), fs::copy_option::fail_if_exists, error_code);
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
  fs::copy_file(file0, test_elements.mount_path() / file0.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy same file to virtual drive again...
  fs::copy_file(file0, test_elements.mount_path() / file0.filename(), fs::copy_option::fail_if_exists, error_code);
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
  fs::copy_file(file1, test_elements.mount_path() / file1.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_elements.mount_path() / file1.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);

  // Rename to first file name...
  fs::rename(test_elements.mount_path() / file1.filename(), test_elements.mount_path() / file0.filename(), error_code);
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
  ASSERT_FALSE(fs::create_directory(test_elements.mount_path() / directory0.filename(), error_code));
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
  fs::rename(test_elements.mount_path() / directory1.filename(), test_elements.mount_path() / directory0.filename(), error_code);

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
  boost::system::error_code error_code;
  size_t count(15 + RandomUint32() % 5);
  int64_t file_size(0);

  for (size_t i = 0; i != count; ++i) {
    switch (RandomUint32() % 10) {
      case 0: {
        fs::path directories(CreateTestDirectoriesAndFiles(*test_dir_));
        EXPECT_TRUE(fs::exists(directories, error_code));
        EXPECT_TRUE(CopyDirectories(directories, test_elements.mount_path()));
        EXPECT_TRUE(fs::exists(test_elements.mount_path() / directories.filename(), error_code));
        EXPECT_EQ(error_code.value(), 0);
        break;
      }
      case 1: {
        fs::path file(CreateTestFile(test_elements.mount_path(), file_size));
        EXPECT_TRUE(fs::exists(file, error_code));
        fs::copy_file(file, *test_dir_ / file.filename());
        EXPECT_TRUE(fs::exists(*test_dir_ / file.filename(), error_code));
        EXPECT_EQ(error_code.value(), 0);
        break;
      }
      case 2: {
        fs::path directory(CreateDirectoryContainingFiles(*test_dir_));
        EXPECT_FALSE(directory.empty());
        if (!directory.empty()) {
          EXPECT_TRUE(CopyDirectories(directory, test_elements.mount_path()));
          EXPECT_TRUE(fs::exists(test_elements.mount_path() / directory.filename(), error_code));
          EXPECT_EQ(error_code.value(), 0);
        }
        break;
      }
      case 3: {
        fs::path file(LocateNthFile(test_elements.mount_path(), RandomUint32() % 30));
        if (file != fs::path()) {
          fs::path found(FindDirectoryOrFile(*test_dir_, file.filename()));
          EXPECT_NE(found, fs::path());
          fs::remove(file, error_code);
          EXPECT_FALSE(fs::exists(file, error_code));
          EXPECT_EQ(error_code.value(), 2);
          fs::remove(found, error_code);
          EXPECT_FALSE(fs::exists(found, error_code));
          EXPECT_EQ(error_code.value(), 2);
        }
        break;
      }
      case 4: {
        // as above...
        fs::path directory(LocateNthDirectory(test_elements.mount_path(), RandomUint32() % 30));
        if (directory != fs::path()) {
          fs::path found(FindDirectoryOrFile(*test_dir_, directory.filename()));
          EXPECT_NE(found, fs::path());
          fs::remove_all(directory, error_code);
          EXPECT_FALSE(fs::exists(directory, error_code));
          EXPECT_EQ(error_code.value(), 2);
          fs::remove_all(found, error_code);
          EXPECT_FALSE(fs::exists(found, error_code));
          EXPECT_EQ(error_code.value(), 2);
        }
        break;
      }
      case 5: {
        boost::system::error_code error_code;
        // Create directory with random number of files...
        fs::path directory(CreateDirectoryContainingFiles(test_elements.mount_path()));
        EXPECT_FALSE(directory.empty());
        if (!directory.empty()) {
          // Copy directory to disk...
          EXPECT_TRUE(CopyDirectories(directory, *test_dir_));
          EXPECT_TRUE(fs::exists(*test_dir_ / directory.filename(), error_code));
          EXPECT_EQ(error_code.value(), 0);
        }
        break;
      }
      case 6: {
        typedef fs::copy_option copy_option;
        boost::system::error_code error_code;
        // Create file on disk...
        fs::path file(CreateTestFile(*test_dir_, file_size));
        EXPECT_TRUE(fs::exists(file, error_code));
        EXPECT_EQ(error_code.value(), 0);
        // Copy file to virtual drive...
        fs::copy_file(file,
                      test_elements.mount_path() / file.filename(),
                      copy_option::fail_if_exists,
                      error_code);
        EXPECT_EQ(error_code.value(), 0);
        EXPECT_TRUE(fs::exists(test_elements.mount_path() / file.filename(), error_code));
        break;
      }
      case 7: {
        typedef fs::copy_option copy_option;
        boost::system::error_code error_code;
        fs::path file(LocateNthFile(test_elements.mount_path(), RandomUint32() % 21));
        if (file != fs::path()) {
          fs::path found(FindDirectoryOrFile(*test_dir_, file.filename()));
          EXPECT_NE(found, fs::path());
          fs::copy_file(found,
                        test_elements.mount_path() / found.filename(),
                        copy_option::fail_if_exists,
                        error_code);
          EXPECT_TRUE(fs::exists(test_elements.mount_path() / found.filename(),
                                  error_code));
          EXPECT_EQ(error_code.value(), 0);
          fs::copy_file(file,
                        *test_dir_ / file.filename(),
                        copy_option::fail_if_exists,
                        error_code);
          EXPECT_TRUE(fs::exists(*test_dir_ / file.filename(), error_code));
          EXPECT_EQ(error_code.value(), 0);
        }
        break;
      }
      case 8: {
        fs::path file(LocateNthFile(test_elements.mount_path(), RandomUint32() % 30));
        if (file != fs::path()) {
          fs::path found(FindDirectoryOrFile(*test_dir_, file.filename()));
          EXPECT_NE(found, fs::path());
          std::string new_name(maidsafe::RandomAlphaNumericString(5) + ".txt");
          fs::rename(found, found.parent_path() / new_name, error_code);
          EXPECT_TRUE(fs::exists(found.parent_path() / new_name, error_code));
          EXPECT_EQ(error_code.value(), 0);
          fs::rename(file, file.parent_path() / new_name, error_code);
          EXPECT_TRUE(fs::exists(file.parent_path() / new_name, error_code));
          EXPECT_EQ(error_code.value(), 0);
        }
        break;
      }
      case 9: {
        fs::path file(LocateNthFile(test_elements.mount_path(), RandomUint32() % 30));
        if (file != fs::path()) {
          fs::path found(FindDirectoryOrFile(*test_dir_, file.filename()));
          EXPECT_NE(found, fs::path());
          EXPECT_TRUE(CompareFileContents(file, found));
        }
        break;
      }
      default:
        LOG(kInfo) << "Can't reach here!";
    }
  }

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
