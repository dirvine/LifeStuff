/*******************************************************************************
 *  Copyright 2011 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 *******************************************************************************
 */

#include <cstdio>
#include <memory>
#include <random>  // NOLINT

#include "boost/lexical_cast.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_store/remote_chunk_store.h"
#include "maidsafe/private/chunk_store/file_chunk_store.h"

#ifdef WIN32
#  include "maidsafe/drive/win_drive.h"
#else
#  include "maidsafe/drive/unix_drive.h"
#endif
#include "maidsafe/drive/return_codes.h"
#include "maidsafe/lifestuff/tests/test_utils.h"

namespace fs = boost::filesystem;
namespace pcs = maidsafe::priv::chunk_store;

namespace maidsafe {

namespace lifestuff {

namespace test {

namespace {

fs::path g_test_mirror, g_mount_dir;

bool ExcludedFilename(const fs::path &path) {
  std::string file_name(path.filename().stem().string());
  if (file_name.size() == 4 && isdigit(file_name[3])) {
    if (file_name[3] != '0') {
      std::string name(file_name.substr(0, 3));
      std::transform(name.begin(), name.end(), name.begin(), tolower);
      if (name.compare(0, 3, "com", 0, 3) == 0) {
        return true;
      }
      if (name.compare(0, 3, "lpt", 0, 3) == 0) {
        return true;
      }
    }
  } else if (file_name.size() == 3) {
    std::string name(file_name);
    std::transform(name.begin(), name.end(), name.begin(), tolower);
    if (name.compare(0, 3, "con", 0, 3) == 0) {
      return true;
    }
    if (name.compare(0, 3, "prn", 0, 3) == 0) {
      return true;
    }
    if (name.compare(0, 3, "aux", 0, 3) == 0) {
      return true;
    }
    if (name.compare(0, 3, "nul", 0, 3) == 0) {
      return true;
    }
  } else if (file_name.size() == 6) {
    if (file_name[5] == '$') {
      std::string name(file_name);
      std::transform(name.begin(), name.end(), name.begin(), tolower);
      if (name.compare(0, 5, "clock", 0, 5) == 0) {
        return true;
      }
    }
  }
  static const std::string excluded = "\"\\/<>?:*|";
  std::string::const_iterator first(file_name.begin()), last(file_name.end());
  for (; first != last; ++first) {
    if (find(excluded.begin(), excluded.end(), *first) != excluded.end())
      return true;
  }
  return false;
}

}  // unnamed namespace

class ApiTestEnvironment : public testing::Environment {
 public:
  explicit ApiTestEnvironment()
      : asio_service_(5),
        root_test_dir_(new fs::path("LifeStuff_Test_Disk")),
        main_test_dir_() {}

 protected:
  void SetUp() {
    asio_service_.Start();
    main_test_dir_ = maidsafe::test::CreateTestPath((*root_test_dir_).string());
#ifdef WIN32
    g_mount_dir = *main_test_dir_ / "TestMount";
    g_test_mirror = *main_test_dir_ / "TestMirror";
#else
    g_mount_dir = *main_test_dir_ / "MaidSafeDrive";
    g_test_mirror = *main_test_dir_ / "Temp";
#endif

    boost::system::error_code error_code;
    fs::create_directories(g_mount_dir, error_code);
    ASSERT_EQ(0, error_code.value());
    fs::create_directories(g_test_mirror, error_code);
    ASSERT_EQ(0, error_code.value());
  }

  void TearDown() {
    main_test_dir_.reset();
  }

 private:
  ApiTestEnvironment(const ApiTestEnvironment&);
  ApiTestEnvironment& operator=(const ApiTestEnvironment&);

  AsioService asio_service_;
  maidsafe::test::TestPath root_test_dir_;
  maidsafe::test::TestPath main_test_dir_;
};

class LifeStuffRealDriveApiTest : public testing::Test {
 public:
  static const uint32_t kDirectorySize = 4096;

 protected:
  void TearDown() {
     fs::directory_iterator end;
     try {
      fs::directory_iterator begin1(g_test_mirror), end1;
      for (; begin1 != end1; ++begin1)
        fs::remove_all((*begin1).path());
     }
     catch(const std::exception &e) {
      LOG(kError) << e.what();
     }
     try {
      fs::directory_iterator begin2(g_mount_dir), end2;
      for (; begin2 != end2; ++begin2)
        fs::remove_all((*begin2).path());
     }
     catch(const std::exception &e) {
      LOG(kError) << e.what();
     }
  }
};

TEST_F(LifeStuffRealDriveApiTest, BEH_CreateDirectoryOnDrive) {
  // Create empty directory on virtual drive...
  fs::path directory(CreateTestDirectory(g_mount_dir));
  ASSERT_TRUE(fs::exists(directory)) << directory;
}

#ifdef __MSVC__
#  pragma warning(push, 1)
#  pragma warning(disable: 4996)
#endif

TEST_F(LifeStuffRealDriveApiTest, BEH_AppendToFileTest) {
  fs::path file(g_mount_dir / (RandomAlphaNumericString(5) + ".txt"));
  FILE *test_file(NULL);
  int this_char(0);
  int num_of_a_chars = 0;
  int test_runs = 1000;

  for (int i = 0; i < test_runs; ++i) {
    test_file = fopen(file.string().c_str(), "a");
    ASSERT_TRUE(test_file != NULL);
    fputc('a', test_file);
    fclose(test_file);
    test_file = fopen(file.string().c_str(), "r");
    ASSERT_TRUE(test_file != NULL);
    while (this_char != EOF) {
      this_char = getc(test_file);
      if (this_char == 'a')
        ++num_of_a_chars;
    }
    ASSERT_EQ(num_of_a_chars, i + 1);
    fclose(test_file);
    num_of_a_chars = 0;
    this_char = 0;
  }
}

#ifdef __MSVC__
#  pragma warning(pop)
#endif

TEST_F(LifeStuffRealDriveApiTest, BEH_CopyEmptyDirectoryToDrive) {
  // Create empty directory on disk...
  fs::path directory(CreateTestDirectory(g_test_mirror));
  ASSERT_TRUE(fs::exists(directory));
  // Copy disk directory to virtual drive...
  fs::copy_directory(directory, g_mount_dir / directory.filename());
  ASSERT_TRUE(fs::exists(g_mount_dir / directory.filename()));
}

TEST_F(LifeStuffRealDriveApiTest, BEH_CopyNonemptyDirectoryToDriveThenDelete) {
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create empty directory on disk...
  fs::path directory(CreateTestDirectory(g_test_mirror));
  ASSERT_TRUE(fs::exists(directory, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Create a file in newly created directory...
  fs::path file(CreateTestFile(directory, file_size));
  // Copy directory and file to virtual drive...
  ASSERT_TRUE(CopyDirectories(directory, g_mount_dir));
  ASSERT_TRUE(fs::exists(g_mount_dir / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / directory.filename() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Check used space...
  ASSERT_EQ(CalculateUsedSpace(g_test_mirror), CalculateUsedSpace(g_mount_dir));
  // Delete the directory along with its contents...
  ASSERT_EQ(2U, fs::remove_all(g_mount_dir / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(g_mount_dir / directory.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(g_mount_dir / directory.filename() / file.filename()));
}

TEST_F(LifeStuffRealDriveApiTest, BEH_CopyNonemptyDirectoryToDriveDeleteThenRecopy) {
  int64_t file_size(0);
  // Create empty directory on disk...
  fs::path directory(CreateTestDirectory(g_test_mirror));
  ASSERT_TRUE(fs::exists(directory));
  // Create a file in newly created directory...
  fs::path file(CreateTestFile(directory, file_size));
  // Copy directory and file to virtual drive...
  ASSERT_TRUE(CopyDirectories(directory, g_mount_dir));
  ASSERT_TRUE(fs::exists(g_mount_dir / directory.filename()));
  ASSERT_TRUE(fs::exists(g_mount_dir / directory.filename() / file.filename()));
  // Delete the directory along with its contents...
  boost::system::error_code error_code;
  ASSERT_EQ(2U, fs::remove_all(g_mount_dir / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(g_mount_dir / directory.filename()));
  ASSERT_FALSE(fs::exists(g_mount_dir / directory.filename() / file.filename()));
  // Re-copy directory and file to virtual drive...
  ASSERT_TRUE(CopyDirectories(directory, g_mount_dir));
  ASSERT_TRUE(fs::exists(g_mount_dir / directory.filename()));
  ASSERT_TRUE(fs::exists(g_mount_dir / directory.filename() / file.filename()));
  ASSERT_EQ(file_size + kDirectorySize, CalculateUsedSpace(g_mount_dir));
}

TEST_F(LifeStuffRealDriveApiTest, BEH_CopyNonemptyDirectoryThenRename) {
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create empty directory on disk...
  fs::path directory(CreateTestDirectory(g_test_mirror));
  ASSERT_TRUE(fs::exists(directory, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Create a file in newly created directory...
  fs::path file(CreateTestFile(directory, file_size));
  // Copy directory and file to virtual drive...
  ASSERT_TRUE(CopyDirectories(directory, g_mount_dir));
  ASSERT_TRUE(fs::exists(g_mount_dir / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / directory.filename() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Check used space...
  ASSERT_EQ(CalculateUsedSpace(g_test_mirror), CalculateUsedSpace(g_mount_dir));
  // Rename the directory...
  fs::path new_directory_name(g_mount_dir / maidsafe::RandomAlphaNumericString(5));
  fs::rename(g_mount_dir / directory.filename(), new_directory_name, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(g_mount_dir / directory.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(new_directory_name, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Check used space...
  ASSERT_EQ(file_size + kDirectorySize, CalculateUsedSpace(g_test_mirror));
  ASSERT_EQ(file_size + kDirectorySize, CalculateUsedSpace(g_mount_dir));
}

TEST_F(LifeStuffRealDriveApiTest, BEH_CopyNonemptyDirectoryRenameThenRecopy) {
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create empty directory on disk...
  fs::path directory(CreateTestDirectory(g_test_mirror));
  ASSERT_TRUE(fs::exists(directory, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Create a file in newly created directory...
  fs::path file(CreateTestFile(directory, file_size));
  // Copy directory and file to virtual drive...
  ASSERT_TRUE(CopyDirectories(directory, g_mount_dir));
  ASSERT_TRUE(fs::exists(g_mount_dir / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / directory.filename() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Rename the directory...
  fs::path new_directory_name(g_mount_dir / maidsafe::RandomAlphaNumericString(5));
  fs::rename(g_mount_dir / directory.filename(), new_directory_name, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(g_mount_dir / directory.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(new_directory_name));
  // Re-copy disk directory and file to virtual drive...
  ASSERT_TRUE(CopyDirectories(directory, g_mount_dir));
  ASSERT_TRUE(fs::exists(g_mount_dir / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / directory.filename() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Check used space again...
  ASSERT_EQ(2 * file_size + 2 * kDirectorySize, CalculateUsedSpace(g_mount_dir));
}

TEST_F(LifeStuffRealDriveApiTest, FUNC_CopyDirectoryContainingFiles) {
  boost::system::error_code error_code;
  // Create directory with random number of files...
  fs::path directory(CreateDirectoryContainingFiles(g_test_mirror));
  ASSERT_FALSE(directory.empty());
  // Copy directory to virtual drive...
  ASSERT_TRUE(CopyDirectories(directory, g_mount_dir));
  ASSERT_TRUE(fs::exists(g_mount_dir / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Check used space...
  ASSERT_EQ(CalculateUsedSpace(g_test_mirror), CalculateUsedSpace(g_mount_dir));
}

TEST_F(LifeStuffRealDriveApiTest, FUNC_CopyDirectoryContainingFilesAndDirectories) {
  boost::system::error_code error_code;
  // Create directories hierarchy some of which containing files...
  fs::path directories(CreateTestDirectoriesAndFiles(g_test_mirror));
  ASSERT_TRUE(fs::exists(directories));
  // Copy hierarchy to virtual drive...
  ASSERT_TRUE(CopyDirectories(directories, g_mount_dir));
  ASSERT_TRUE(fs::exists(g_mount_dir / directories.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
}

TEST_F(LifeStuffRealDriveApiTest, FUNC_CopyFileThenCopyCopiedFile) {
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file(CreateTestFile(g_test_mirror, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file, g_mount_dir / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive again...
  fs::copy_file(file,
                g_mount_dir / file.filename(),
                fs::copy_option::overwrite_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0) << error_code.message();
  ASSERT_TRUE(fs::exists(g_mount_dir / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Check used space...
  ASSERT_EQ(file_size, CalculateUsedSpace(g_mount_dir));
}

TEST_F(LifeStuffRealDriveApiTest, FUNC_CopyFileDeleteThenRecopy) {
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file(CreateTestFile(g_test_mirror, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file, g_mount_dir / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Delete the file...
  fs::remove(g_mount_dir / file.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(g_mount_dir / file.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  // Copy file to virtual drive again...
  fs::copy_file(file, g_mount_dir / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Check used space...
  ASSERT_EQ(file_size, CalculateUsedSpace(g_mount_dir));
}

TEST_F(LifeStuffRealDriveApiTest, FUNC_CopyFileRenameThenRecopy) {
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file(CreateTestFile(g_test_mirror, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file, g_mount_dir / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Rename the file...
  fs::path new_file_name(g_mount_dir / (RandomAlphaNumericString(5) + ".txt"));
  fs::rename(g_mount_dir / file.filename(), new_file_name, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(g_mount_dir / file.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(new_file_name, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive again...
  fs::copy_file(file, g_mount_dir / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_test_mirror / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Check used space...
  ASSERT_EQ(2 * file_size, CalculateUsedSpace(g_mount_dir));
}

TEST_F(LifeStuffRealDriveApiTest, BEH_CopyFileThenRead) {
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file(CreateTestFile(g_test_mirror, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file, g_mount_dir / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Write virtual drive file back to a disk file...
  fs::path test_file(g_test_mirror / (RandomAlphaNumericString(5) + ".txt"));
  fs::copy_file(g_mount_dir / file.filename(), test_file, fs::copy_option::overwrite_if_exists);
  ASSERT_TRUE(fs::exists(test_file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Compare content in the two files...
  ASSERT_EQ(fs::file_size(test_file), fs::file_size(file));
  ASSERT_TRUE(CompareFileContents(test_file, file));
}

TEST_F(LifeStuffRealDriveApiTest, FUNC_CopyFileRenameThenRead) {
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file(CreateTestFile(g_test_mirror, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file, g_mount_dir / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Rename the file...
  fs::path new_file_name(g_mount_dir / (RandomAlphaNumericString(5) + ".txt"));
  fs::rename(g_mount_dir / file.filename(), new_file_name, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(g_mount_dir / file.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(new_file_name, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Write virtual drive file back to a disk file...
  fs::path test_file(g_test_mirror / new_file_name.filename());
  fs::copy_file(new_file_name, test_file, fs::copy_option::overwrite_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Compare content in the two files...
  ASSERT_TRUE(CompareFileContents(test_file, file));
}

TEST_F(LifeStuffRealDriveApiTest, FUNC_CopyFileDeleteThenTryToRead) {
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file(CreateTestFile(g_test_mirror, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file, g_mount_dir / file.filename(), fs::copy_option::fail_if_exists);
  ASSERT_TRUE(fs::exists(g_mount_dir / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Delete the file...
  fs::remove(g_mount_dir / file.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(g_mount_dir / file.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  // Write virtual drive file back to a disk file...
  fs::path test_file(g_test_mirror / (RandomAlphaNumericString(5) + ".txt"));
  fs::copy_file(g_mount_dir / file.filename(),
                test_file,
                fs::copy_option::overwrite_if_exists,
                error_code);
  ASSERT_NE(error_code.value(), 0);
  // Compare content in the two files...
  ASSERT_FALSE(CompareFileContents(test_file, file));
}

TEST_F(LifeStuffRealDriveApiTest, BEH_CreateFileOnDriveThenRead) {
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on virtual drive...
  fs::path file(CreateTestFile(g_mount_dir, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Write virtual drive file out to disk...
  fs::path test_file(g_test_mirror / file.filename());
  fs::copy_file(file, test_file, fs::copy_option::overwrite_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  // Check used space...
  ASSERT_EQ(file_size, CalculateUsedSpace(g_mount_dir));
}

TEST_F(LifeStuffRealDriveApiTest, BEH_CopyFileModifyThenRead) {
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file(CreateTestFile(g_test_mirror, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file, g_mount_dir / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Check used space...
  ASSERT_EQ(file_size, CalculateUsedSpace(g_mount_dir));
  // Modify the file...
  ASSERT_TRUE(ModifyFile(g_mount_dir / file.filename(), file_size));
  ASSERT_TRUE(fs::exists(g_mount_dir / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Check used space again...
  ASSERT_EQ(file_size, CalculateUsedSpace(g_mount_dir));
  // Write virtual drive file back to a disk file...
  fs::path test_file(g_test_mirror / (RandomAlphaNumericString(5) + ".txt"));
  fs::copy_file(g_mount_dir / file.filename(),
                test_file,
                fs::copy_option::overwrite_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0);
  // Compare content in the two files...
  ASSERT_FALSE(CompareFileContents(test_file, file));
}

TEST_F(LifeStuffRealDriveApiTest, FUNC_CheckFailures) {
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file0(CreateTestFile(g_test_mirror, file_size));
  ASSERT_TRUE(fs::exists(file0, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file0, g_mount_dir / file0.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / file0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy same file to virtual drive again...
  fs::copy_file(file0, g_mount_dir / file0.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / file0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Create a file with the same name on the virtual drive...
  ASSERT_TRUE(CreateFileAt(g_mount_dir / file0.filename()));
  ASSERT_TRUE(fs::exists(file0, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Create another file on disk...
  fs::path file1(CreateTestFile(g_test_mirror, file_size));
  ASSERT_TRUE(fs::exists(file1, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy it to virtual drive...
  fs::copy_file(file1, g_mount_dir / file1.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / file1.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);

  // Rename to first file name...
  fs::rename(g_mount_dir / file1.filename(), g_mount_dir / file0.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / file0.filename(), error_code));
  ASSERT_FALSE(fs::exists(g_mount_dir / file1.filename(), error_code));
  ASSERT_EQ(crypto::HashFile<crypto::Tiger>(file1),
            crypto::HashFile<crypto::Tiger>(g_mount_dir / file0.filename()));
  // Rename mirror likewise...
  fs::rename(g_test_mirror / file1.filename(), g_test_mirror / file0.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_test_mirror / file0.filename(), error_code));
  ASSERT_FALSE(fs::exists(g_test_mirror / file1.filename(), error_code));
  // Delete the first file...
  ASSERT_TRUE(fs::remove(g_mount_dir / file0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(g_mount_dir / file0.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  // Delete the first file again...
  ASSERT_FALSE(fs::remove(g_mount_dir / file0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(g_mount_dir / file0.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);

  // Repeat above for directories
  // Create directory on disk...
  fs::path directory0(CreateTestDirectory(g_test_mirror));
  ASSERT_TRUE(fs::exists(directory0, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy directory to virtual drive...
  fs::copy_directory(directory0, g_mount_dir / directory0.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / directory0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy same directory to virtual drive again...
  fs::copy_directory(directory0, g_mount_dir / directory0.filename(), error_code);
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / directory0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Create a directory with the same name on the virtual drive...
  ASSERT_FALSE(fs::create_directory(g_mount_dir / directory0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(directory0, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Create another directory on disk...
  fs::path directory1(CreateTestDirectory(g_test_mirror));
  ASSERT_TRUE(fs::exists(directory1, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy it to virtual drive...
  fs::copy_directory(directory1, g_mount_dir / directory1.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / directory1.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);

  // Rename to first directory name...
  fs::rename(g_mount_dir / directory1.filename(), g_mount_dir / directory0.filename(), error_code);

  // From boost filesystem docs: if new_p resolves to an existing directory,
  // it is removed if empty on POSIX but is an error on Windows.
#ifdef WIN32
  ASSERT_NE(error_code.value(), 0);
#else
  ASSERT_EQ(error_code.value(), 0);
#endif
  ASSERT_TRUE(fs::exists(g_mount_dir / directory0.filename(), error_code));
  // Delete the first directory...
  ASSERT_TRUE(fs::remove(g_mount_dir / directory0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(g_mount_dir / directory0.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);

  // Delete the first directory again...
  ASSERT_FALSE(fs::remove(g_mount_dir / directory0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(g_mount_dir / directory0.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  // TODO(Fraser#5#): 2011-05-30 - Add similar test for non-empty directory.
}

TEST_F(LifeStuffRealDriveApiTest, FUNC_FunctionalTest) {
  ASSERT_TRUE(DoRandomEvents(g_mount_dir, g_test_mirror));
}

namespace {

fs::path GenerateFile(const fs::path &path,
                      std::uint32_t size = 0,
                      const std::string &content = "") {
  if ((size == 0 && content.empty()) || (size != 0 && !content.empty()))
    return fs::path();

  size_t filename_size(RandomUint32() % 4 + 4);
  fs::path file_name(RandomAlphaNumericString(filename_size) + ".txt");
#ifndef WIN32
  while (ExcludedFilename(file_name))
    file_name = RandomAlphaNumericString(filename_size);
#endif
  file_name = path / file_name;
  fs::ofstream ofs(file_name.c_str(), std::ios::out);
  if (!ofs.is_open())
    return fs::path();

  if (size != 0) {
    std::string random_string(RandomString(size % 1024));
    size_t rounds = size / 1024, count = 0;
    while (count++ < rounds)
      ofs << random_string;
  } else {
    ofs << content;
  }

  ofs.close();
  return file_name;
}

fs::path GenerateDirectory(const fs::path &path) {
  size_t directory_name_size(RandomUint32() % 8 + 1);
  fs::path file_name(RandomAlphaNumericString(directory_name_size));
#ifndef WIN32
  while (ExcludedFilename(file_name))
    file_name = RandomAlphaNumericString(directory_name_size);
#endif
  file_name = path / file_name;
  boost::system::error_code ec;
  fs::create_directory(file_name, ec);
  if (ec)
    return fs::path();
  return file_name;
}

void GenerateFileSizes(std::uint32_t max_size,
                       std::uint32_t min_size,
                       size_t count,
                       std::vector<std::uint32_t> *file_sizes) {
  while (file_sizes->size() < count)
    file_sizes->push_back(RandomUint32() % max_size + min_size);
}

std::uint32_t CreateTestTreeStructure(const fs::path &base_path,
                                      std::vector<fs::path> *directories,
                                      std::set<fs::path> *files,
                                      std::uint32_t directory_node_count,
                                      std::uint32_t file_node_count = 100,
                                      std::uint32_t max_filesize = 5 * 1024 * 1024,
                                      std::uint32_t min_size = 1024) {
  fs::path directory(GenerateDirectory(base_path));
  directories->reserve(directory_node_count);
  directories->push_back(directory);
  while (directories->size() < directory_node_count) {
    size_t random_element(RandomUint32() % directories->size());
    fs::path p = GenerateDirectory(directories->at(random_element));
    if (!p.empty())
      directories->push_back(p);
  }

  std::vector<std::uint32_t> file_sizes;
  GenerateFileSizes(max_filesize, min_size, 20, &file_sizes);
  std::uint32_t total_file_size(0);
  while (files->size() < file_node_count) {
    size_t random_element(RandomUint32() % directory_node_count);
    std::uint32_t file_size = file_sizes.at(files->size() % file_sizes.size());
    fs::path p = GenerateFile(directories->at(random_element), file_size);
    if (!p.empty()) {
      total_file_size += file_size;
      files->insert(p);
    }
  }
  return total_file_size;
}

void CopyRecursiveDirectory(const fs::path &src, const fs::path &dest) {
  boost::system::error_code ec;
  fs::copy_directory(src, dest / src.filename(), ec);
  for (fs::recursive_directory_iterator end, current(src); current != end; ++current) {
    std::string str = current->path().string();
    std::string str2 = src.string();
    boost::algorithm::replace_last(str2, src.filename().string(), "");
    boost::algorithm::replace_first(str, str2, dest.string() + "/");
    EXPECT_TRUE(fs::exists(current->path()));
    if (fs::is_directory(*current)) {
      fs::copy_directory(current->path(), str, ec);
    } else {
      fs::copy_file(current->path(), str, fs::copy_option::overwrite_if_exists, ec);
    }
    EXPECT_TRUE(fs::exists(str));
  }
}

}  // namespace

TEST_F(LifeStuffRealDriveApiTest, FUNC_BENCHMARK_CopyThenReadLargeFile) {
  boost::system::error_code error_code;

  // Create file on disk...
  size_t size = 300 * 1024 * 1024;
  fs::path file(CreateTestFileWithSize(g_test_mirror, size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);

  // Copy file to virtual drive...
  bptime::ptime copy_start_time(bptime::microsec_clock::universal_time());
  fs::copy_file(file, g_mount_dir / file.filename(), fs::copy_option::fail_if_exists, error_code);
  bptime::ptime copy_stop_time(bptime::microsec_clock::universal_time());
  PrintResult(copy_start_time, copy_stop_time, size, kCopy);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(g_mount_dir / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);

  // Read the file back to a disk file...
  // Because of the system caching, the pure read can't reflect the real speed
  fs::path test_file(g_test_mirror / (RandomAlphaNumericString(5) + ".txt"));
  bptime::ptime read_start_time(bptime::microsec_clock::universal_time());
  fs::copy_file(g_mount_dir / file.filename(), test_file, fs::copy_option::overwrite_if_exists);
  bptime::ptime read_stop_time(bptime::microsec_clock::universal_time());
  PrintResult(read_start_time, read_stop_time, size, kRead);
  ASSERT_TRUE(fs::exists(test_file, error_code));
  ASSERT_EQ(error_code.value(), 0);

  // Compare content in the two files...
  ASSERT_EQ(fs::file_size(g_mount_dir / file.filename()), fs::file_size(file));
  bptime::ptime compare_start_time(bptime::microsec_clock::universal_time());
  ASSERT_TRUE(CompareFileContents(g_mount_dir / file.filename(), file));
  bptime::ptime compare_stop_time(bptime::microsec_clock::universal_time());
  PrintResult(compare_start_time, compare_stop_time, size, kCompare);
}

TEST_F(LifeStuffRealDriveApiTest, FUNC_BENCHMARK_CopyThenReadManySmallFiles) {
  std::vector<fs::path> directories;
  std::set<fs::path> files;
  // The changed values that follow don't affect effectiveness or
  // benchmarkability, but do reduce running time significantly...
  std::uint32_t num_of_directories(100);  // 1000);
  std::uint32_t num_of_files(300);  // 3000);
  std::uint32_t max_filesize(256 * 1024);
  std::uint32_t min_filesize(1);
  std::cout << "Creating a test tree with " << num_of_directories
            << " directories holding " << num_of_files
            << " files with file size range from "
            << BytesToBinarySiUnits(min_filesize)
            << " to " << BytesToBinarySiUnits(max_filesize) << std::endl;
  std::uint32_t total_data_size = CreateTestTreeStructure(g_test_mirror, &directories, &files,
                                                          num_of_directories, num_of_files,
                                                          max_filesize, min_filesize);

  // Copy test_tree to virtual drive...
  bptime::ptime copy_start_time(bptime::microsec_clock::universal_time());
  CopyRecursiveDirectory(directories.at(0), g_mount_dir);
  bptime::ptime copy_stop_time(bptime::microsec_clock::universal_time());
  PrintResult(copy_start_time, copy_stop_time, total_data_size, kCopy);

  // Read the test_tree back to a disk file...
  std::string str = directories.at(0).string();
  boost::algorithm::replace_first(str, g_test_mirror.string(), g_mount_dir.string());
  fs::path from_directory(str);
  fs::path read_back_directory(GenerateDirectory(g_test_mirror));
  bptime::ptime read_start_time(bptime::microsec_clock::universal_time());
  CopyRecursiveDirectory(from_directory, read_back_directory);
  bptime::ptime read_stop_time(bptime::microsec_clock::universal_time());
  PrintResult(read_start_time, read_stop_time, total_data_size, kRead);

  // Compare content in the two test_trees...
  bptime::ptime compare_start_time(bptime::microsec_clock::universal_time());
  for (auto it = files.begin(); it != files.end(); ++it) {
    std::string str = (*it).string();
    boost::algorithm::replace_first(str, g_test_mirror.string(), g_mount_dir.string());
    if (!fs::exists(str))
      Sleep(bptime::seconds(1));
    ASSERT_TRUE(fs::exists(str))  << "Missing " << str;
    ASSERT_TRUE(CompareFileContents(*it, str)) << "Comparing " << *it << " with " << str;
  }
  bptime::ptime compare_stop_time(bptime::microsec_clock::universal_time());
  PrintResult(compare_start_time, compare_stop_time, total_data_size, kCompare);

  for (size_t i = 0; i < directories.size(); ++i) {
    std::string str = directories[i].string();
    boost::algorithm::replace_first(str, g_test_mirror.string(), g_mount_dir.string());
    ASSERT_TRUE(fs::exists(str)) << "Missing " << str;
  }
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe

int main(int argc, char **argv) {
  maidsafe::log::Logging::Instance().Initialise(argc, argv);
  testing::FLAGS_gtest_catch_exceptions = false;
  testing::InitGoogleTest(&argc, argv);
  testing::AddGlobalTestEnvironment(
      new maidsafe::lifestuff::test::ApiTestEnvironment());
  int result(RUN_ALL_TESTS());
  int test_count = testing::UnitTest::GetInstance()->test_to_run_count();
  return (test_count == 0) ? -1 : result;
}
