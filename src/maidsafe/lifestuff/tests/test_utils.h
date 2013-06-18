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

#ifndef MAIDSAFE_LIFESTUFF_TESTS_TEST_UTILS_H_
#define MAIDSAFE_LIFESTUFF_TESTS_TEST_UTILS_H_

#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"

namespace fs = boost::filesystem;
namespace bptime = boost::posix_time;

namespace maidsafe {
namespace lifestuff {
namespace test {

enum TestOperationCode { kCopy, kRead, kCompare };

fs::path CreateTestFileWithContent(fs::path const& parent, const std::string &content);
fs::path CreateTestFileWithSize(fs::path const& parent, size_t size);
fs::path CreateTestFile(fs::path const& parent, int64_t &file_size);
bool CreateFileAt(fs::path const& path);
bool ModifyFile(fs::path const& path, int64_t &file_size);
fs::path CreateTestDirectory(fs::path const& parent);
fs::path CreateTestDirectoriesAndFiles(fs::path const& parent);
fs::path CreateEmptyFile(fs::path const& path);
fs::path CreateDirectoryContainingFiles(fs::path const& path);
bool RemoveDirectories(fs::path const& path);
bool CopyDirectories(fs::path const& from, fs::path const& to);
bool CompareDirectoryEntries(fs::path const& drive_path, fs::path const& disk_path);
bool CompareFileContents(fs::path const& path1, fs::path const& path2);
fs::path LocateNthFile(fs::path const& path, size_t n);
fs::path LocateNthDirectory(fs::path const& path, size_t n);
fs::path FindDirectoryOrFile(fs::path const& path, fs::path const& find);
int64_t CalculateUsedSpace(fs::path const& path);
bool DoRandomEvents(fs::path mount_dir, fs::path mirror_dir);

void PrintResult(const bptime::ptime &start_time,
                 const bptime::ptime &stop_time,
                 size_t size,
                 TestOperationCode operation_code);
bool ExcludedFilename(const fs::path &path);
fs::path GenerateFile(const fs::path &path, uint32_t size = 0, const std::string &content = "");
fs::path GenerateDirectory(const fs::path &path);
void GenerateFileSizes(uint32_t max_size,
                       uint32_t min_size,
                       size_t count,
                       std::vector<uint32_t> *file_sizes);
uint32_t CreateTestTreeStructure(const fs::path &base_path,
                                 std::vector<fs::path> *directories,
                                 std::set<fs::path> *files,
                                 uint32_t directory_node_count,
                                 uint32_t file_node_count = 100,
                                 uint32_t max_filesize = 5 * 1024 * 1024,
                                 uint32_t min_size = 1024);
void CopyRecursiveDirectory(const fs::path &src, const fs::path &dest);

}  // namespace test
}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_TESTS_TEST_UTILS_H_
