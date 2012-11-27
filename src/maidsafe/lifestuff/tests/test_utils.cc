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

#include <random>

#include "maidsafe/lifestuff/tests/test_utils.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/log.h"

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
  size_t size = RandomUint32() % 1048576;  // 2^20

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

fs::path CreateTestDirectoriesAndFiles(fs::path const& parent) {
  const size_t kMaxPathLength(200);
  fs::path directory(CreateTestDirectory(parent)), check;
  int64_t file_size(0);
  std::mt19937 generator(RandomUint32());
  std::uniform_int_distribution<> distribution(2,4);
  size_t r1 = distribution(generator), r2, r3, r4;

  boost::system::error_code error_code;
  for (size_t i = 0; i != r1; ++i) {
    r2 = distribution(generator);
    r3 = distribution(generator);
    if (parent.string().size() > kMaxPathLength)
      break;
    if (r2 < r3) {
      check = CreateTestDirectoriesAndFiles(directory);
      EXPECT_TRUE(fs::exists(check, error_code)) << check << ": "
                                                  << error_code.message();
      EXPECT_EQ(0, error_code.value()) << check << ": "
                                        << error_code.message();
    } else if (r2 > r3) {
      r4 = distribution(generator);
      for (size_t j = 0; j != r4; ++j) {
        check = CreateTestFile(directory, file_size);
        EXPECT_TRUE(fs::exists(check, error_code)) << check << ": "
                                                    << error_code.message();
        EXPECT_EQ(0, error_code.value()) << check << ": "
                                          << error_code.message();
      }
    } else {
      r4 = distribution(generator);
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

fs::path CreateEmptyFile(fs::path const& path) {
  fs::path file(path / (RandomAlphaNumericString(5) + ".txt"));
  std::ofstream ofs;
  ofs.open(file.native().c_str(), std::ios_base::out | std::ios_base::binary);
  if (ofs.bad()) {
    LOG(kError) << "Can't open " << file;
  } else {
    ofs.close();
  }
  boost::system::error_code ec;
  EXPECT_TRUE(fs::exists(file, ec)) << file;
  EXPECT_EQ(0, ec.value());
  return file;
}

fs::path CreateDirectoryContainingFiles(fs::path const& path) {
  int64_t file_size(0);
  LOG(kInfo) << "CreateDirectoryContainingFiles: directory = " << path;
  try {
    size_t r1 = 0;
    do {
      r1 = RandomUint32() % 5;
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
};

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
          // try again...
          EXPECT_TRUE(fs::remove((*begin).path(), error_code));
          if (error_code.value() != 0) {
            LOG(kError) << "Failed to remove " << (*begin).path();
            return false;
          }
        }
      } else if (fs::is_regular_file(*begin)) {
        EXPECT_TRUE(fs::remove((*begin).path(), error_code));
        if (error_code.value() != 0) {
          // may as well...
          EXPECT_TRUE(fs::remove((*begin).path(), error_code));
          if (error_code.value() != 0) {
            LOG(kError) << "Failed to remove " << (*begin).path();
            return false;
          }
        }
      } else {
        // try removing it anyway...
        EXPECT_TRUE(fs::remove((*begin).path(), error_code));
        if (error_code.value() != 0) {
          // and again...
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
};

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
};

bool CompareDirectoryEntries(fs::path const& drive_path, fs::path const& disk_path) {
  typedef std::set<fs::path>::iterator iterator;

  std::set<fs::path> drive_files, disk_files;
  try {
    fs::recursive_directory_iterator actual(drive_path), compare(disk_path), end;
    for (; actual != end; ++actual)
      drive_files.insert((*actual).path().filename());
    for (; compare != end; ++compare)
      disk_files.insert((*compare).path().filename());
  }
  catch(...) {
    LOG(kError) << "CompareDirectoryEntries: Failed";
    return false;
  }
  std::size_t drive_files_total(drive_files.size()), disk_files_total(disk_files.size());
  if (drive_files_total == disk_files_total) {
    iterator first1 = drive_files.begin(), last1 = drive_files.end(),
              first2 = disk_files.begin();
    for (; first1 != last1; ++first1, ++first2)
      EXPECT_EQ(*first1, *first2);
  } else if (drive_files_total > disk_files_total) {
    iterator first = disk_files.begin(), last = disk_files.end(), found;
    for (; first != last; ++first) {
      found = drive_files.find(*first);
      if (found != drive_files.end())
        EXPECT_EQ(*found, *first);
      else
        return false;
    }
  } else {
    iterator first = drive_files.begin(), last = drive_files.end(), found;
    for (; first != last; ++first) {
      found = disk_files.find(*first);
      if (found == drive_files.end())
        return false;
    }
  }
  return true;
};

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

int64_t CalculateUsedSpace(fs::path const& path) {
  LOG(kInfo) << "CalculatUsedSpace: " << path;
  boost::system::error_code error_code;
  int64_t space_used(0);
  fs::recursive_directory_iterator begin(path), end;
  try {
    for (; begin != end; ++begin) {
      if (fs::is_directory(*begin)) {
        space_used += 4096;  // kDirectorySize;
      } else if (fs::is_regular_file(*begin)) {
        space_used += fs::file_size((*begin).path(), error_code);
        EXPECT_EQ(0, error_code.value());
      }
    }
  }
  catch(...) {
    LOG(kError) << "CalculatUsedSpace: Failed";
    return 0;
  }
  return space_used;
}

bool DoRandomEvents(fs::path mount_dir, fs::path mirror_dir) {
  LOG(kInfo) << "DoRandomEvents";
  // Values assigned to events, randomly chosen of course, are given by,
  //  1. Create directories hierarchy on disk containing arbitrary number of
  //     files then copy to virtual drive.
  //  2. Create a file on virtual drive then copy to mirror.
  //  3. Create a directory containing some files in mirror then copy to
  //     virtual drive.
  //  4. Delete a file on virtual drive and its corresponding mirror.
  //  5. Delete a directory on virtual drive and its corresponding mirror.
  //  6. Create a directory containing some files on virtual drive then copy
  //     to mirror.
  //  7. Create a file in mirror then copy do virtual drive.
  //  8. Unmount then remount virtual drive and compare contents of
  //     directories and files with those in mirror.
  //  9. Copy an existing file to new location on the virtual drive repeat for
  //     mirror.
  // 10. Find any file on the virtual drive then rename it and its mirror
  //     equivalently.
  // 11. Search for a file and compare contents with mirror.

  boost::system::error_code error_code;
  size_t count(15 + RandomUint32() % 5);
  int64_t file_size(0);

  for (size_t i = 0; i != count; ++i) {
    switch (RandomUint32() % 10) {
      case 0: {
        fs::path directories(CreateTestDirectoriesAndFiles(mirror_dir));
        EXPECT_TRUE(fs::exists(directories, error_code));
        EXPECT_TRUE(CopyDirectories(directories, mount_dir));
        EXPECT_TRUE(fs::exists(mount_dir / directories.filename(), error_code));
        EXPECT_EQ(error_code.value(), 0);
        break;
      }
      case 1: {
        fs::path file(CreateTestFile(mount_dir, file_size));
        EXPECT_TRUE(fs::exists(file, error_code));
        fs::copy_file(file, mirror_dir / file.filename());
        EXPECT_TRUE(fs::exists(mirror_dir / file.filename(), error_code));
        EXPECT_EQ(error_code.value(), 0);
        break;
      }
      case 2: {
        fs::path directory(CreateDirectoryContainingFiles(mirror_dir));
        EXPECT_FALSE(directory.empty());
        if (!directory.empty()) {
          EXPECT_TRUE(CopyDirectories(directory, mount_dir));
          EXPECT_TRUE(fs::exists(mount_dir / directory.filename(), error_code));
          EXPECT_EQ(error_code.value(), 0);
        }
        break;
      }
      case 3: {
        fs::path file(LocateNthFile(mount_dir, RandomUint32() % 30));
        if (file != fs::path()) {
          fs::path found(FindDirectoryOrFile(mirror_dir, file.filename()));
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
        fs::path directory(LocateNthDirectory(mount_dir, RandomUint32() % 30));
        if (directory != fs::path()) {
          fs::path found(FindDirectoryOrFile(mirror_dir, directory.filename()));
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
        fs::path directory(CreateDirectoryContainingFiles(mount_dir));
        EXPECT_FALSE(directory.empty());
        if (!directory.empty()) {
          // Copy directory to disk...
          EXPECT_TRUE(CopyDirectories(directory, mirror_dir));
          EXPECT_TRUE(fs::exists(mirror_dir / directory.filename(), error_code));
          EXPECT_EQ(error_code.value(), 0);
        }
        break;
      }
      case 6: {
        typedef fs::copy_option copy_option;
        boost::system::error_code error_code;
        // Create file on disk...
        fs::path file(CreateTestFile(mirror_dir, file_size));
        EXPECT_TRUE(fs::exists(file, error_code));
        EXPECT_EQ(error_code.value(), 0);
        // Copy file to virtual drive...
        fs::copy_file(file,
                      mount_dir / file.filename(),
                      copy_option::fail_if_exists,
                      error_code);
        EXPECT_EQ(error_code.value(), 0);
        EXPECT_TRUE(fs::exists(mount_dir / file.filename(), error_code));
        break;
      }
      case 7: {
        typedef fs::copy_option copy_option;
        boost::system::error_code error_code;
        fs::path file(LocateNthFile(mount_dir, RandomUint32() % 21));
        if (file != fs::path()) {
          fs::path found(FindDirectoryOrFile(mirror_dir, file.filename()));
          EXPECT_NE(found, fs::path());
          fs::copy_file(found,
                        mount_dir / found.filename(),
                        copy_option::fail_if_exists,
                        error_code);
          EXPECT_TRUE(fs::exists(mount_dir / found.filename(),
                                  error_code));
          EXPECT_EQ(error_code.value(), 0);
          fs::copy_file(file,
                        mirror_dir / file.filename(),
                        copy_option::fail_if_exists,
                        error_code);
          EXPECT_TRUE(fs::exists(mirror_dir / file.filename(), error_code));
          EXPECT_EQ(error_code.value(), 0);
        }
        break;
      }
      case 8: {
        fs::path file(LocateNthFile(mount_dir, RandomUint32() % 30));
        if (file != fs::path()) {
          fs::path found(FindDirectoryOrFile(mirror_dir, file.filename()));
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
        fs::path file(LocateNthFile(mount_dir, RandomUint32() % 30));
        if (file != fs::path()) {
          fs::path found(FindDirectoryOrFile(mirror_dir, file.filename()));
          EXPECT_NE(found, fs::path());
          EXPECT_TRUE(CompareFileContents(file, found));
        }
        break;
      }
      default:
        LOG(kInfo) << "Can't reach here!";
    }
  }
  return true;
}

void PrintResult(const bptime::ptime &start_time,
                  const bptime::ptime &stop_time,
                  size_t size, TestOperationCode operation_code) {
  uint64_t duration = (stop_time - start_time).total_microseconds();
  if (duration == 0)
    duration = 1;
  uint64_t rate((static_cast<uint64_t>(size) * 1000000) / duration);
  switch (operation_code) {
    case(kCopy) : {
      std::cout << "Copy " << BytesToBinarySiUnits(size)
                << " of data to drive in " << (duration / 1000000.0)
                << " seconds at a speed of " << BytesToBinarySiUnits(rate)
                << "/s" << std::endl;
      break;
    }
    case(kRead) : {
      std::cout << "Read " << BytesToBinarySiUnits(size)
                << " Bytes of data from drive in " << (duration / 1000000.0)
                << " seconds at a speed of " << BytesToBinarySiUnits(rate)
                << "/s" << std::endl;
      break;
    }
    case(kCompare) : {
      std::cout << "Compare " << BytesToBinarySiUnits(size)
                << " Bytes of data from drive in " << (duration / 1000000.0)
                << " seconds at a speed of " << BytesToBinarySiUnits(rate)
                << "/s" << std::endl;
    }
  }
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe