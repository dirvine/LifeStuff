/* Copyright 2011 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
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
