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

#include "maidsafe/lifestuff/detail/utils.h"

#include <fstream>  // NOLINT (Fraser)
#include <iostream>  // NOLINT (Fraser)
#include <istream>  // NOLINT (Fraser)
#include <limits>
#include <ostream>  // NOLINT (Fraser)
#include <vector>

#include "boost/archive/text_iarchive.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/regex.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#include "maidsafe/encrypt/data_map.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/return_codes.h"

namespace pca = maidsafe::priv::chunk_actions;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace lifestuff {

InboxItem::InboxItem(InboxItemType inbox_item_type)
    : item_type(inbox_item_type),
      sender_public_id(),
      receiver_public_id(),
      content(),
      timestamp(IsoTimeWithMicroSeconds()) {}

std::string CreatePin() {
  std::stringstream pin_stream;
  uint32_t pin(0);
  while (pin < 1000)
    pin = RandomUint32() % 10000;
  pin_stream << pin;
  return pin_stream.str();
}

bool AcceptableWordSize(const std::string &word) {
  return word.size() >= kMinWordSize && word.size() <= kMaxWordSize;
}

bool AcceptableWordPattern(const std::string &word) {
  boost::regex space(" ");
  return !boost::regex_search(word.begin(), word.end(), space);
}

bool CheckWordValidity(const std::string &word) {
  if (!AcceptableWordSize(word)) {
    LOG(kError) << "Unacceptable size: " << word.size();
    return false;
  }

  if (!AcceptableWordPattern(word)) {
    LOG(kError) << "Unacceptable pattern: '" << word << "'";
    return false;
  }

  return true;
}

bool CheckKeywordValidity(const std::string &keyword) {
  return CheckWordValidity(keyword);
}

bool CheckPasswordValidity(const std::string &password) {
  return CheckWordValidity(password);
}

bool CheckPinValidity(const std::string &pin) {
  try {
    int peen(boost::lexical_cast<int>(pin));
    if (peen < 1) {
      LOG(kError) << "PIN out of range: " << peen;
      return false;
    }
    std::string pattern("[0-9]{" +
                        boost::lexical_cast<std::string>(kPinSize) +
                        "}");
    boost::regex rx(pattern);
    return boost::regex_match(pin.begin(), pin.end(), rx);
  }
  catch(const std::exception &e) {
    LOG(kError) << e.what();
    return false;
  }
}

fs::path CreateTestDirectory(fs::path const& parent, std::string *tail) {
  *tail = RandomAlphaNumericString(5);
  fs::path directory(parent / (*tail));
  boost::system::error_code error_code;
  fs::create_directories(directory, error_code);
  if (error_code)
    return fs::path();
  return directory;
}

int CreateTestFile(fs::path const& parent,
                   int size_in_mb,
                   std::string *file_name) {
  if (size_in_mb > 1024) {
    LOG(kError) << "This function doesn't create files larger than 1024MB.";
    return -1;
  }

  std::string random_string(RandomString(256 * 1024));
  *file_name = RandomAlphaNumericString(8);
  fs::path file_path(parent / *file_name);
  int total(size_in_mb * 4);

  try {
    std::ofstream file_out(file_path.c_str(),
                           std::ios::trunc | std::ios::binary);
    if (!file_out.good()) {
      LOG(kError) << "Can't get ofstream created for " << file_path;
      return -1;
    }
    for (int rounds(0); rounds < total; ++rounds)
      file_out.write(random_string.data(), random_string.size());
    file_out.close();
  }
  catch(const std::exception &e) {
    LOG(kError) << "Failed to write file " << file_path << ": " << e.what();
    return -1;
  }

  return kSuccess;
}

int CreateSmallTestFile(fs::path const& parent,
                        int size_in_kb,
                        std::string *file_name) {
  if (size_in_kb > 1024) {
    LOG(kError) << "This function doesn't create files larger than 1024MB.";
    return -1;
  }

  std::string random_string(RandomString(256));
  *file_name = RandomAlphaNumericString(8);
  fs::path file_path(parent / *file_name);
  int total(size_in_kb * 4);

  try {
    std::ofstream file_out(file_path.c_str(),
                           std::ios::trunc | std::ios::binary);
    if (!file_out.good()) {
      LOG(kError) << "Can't get ofstream created for " << file_path;
      return -1;
    }
    for (int rounds(0); rounds < total; ++rounds)
      file_out.write(random_string.data(), random_string.size());
    file_out.close();
  }
  catch(const std::exception &e) {
    LOG(kError) << "Failed to write file " << file_path << ": " << e.what();
    return -1;
  }

  return kSuccess;
}

void ChunkStoreOperationCallback(const bool &response,
                                 boost::mutex *mutex,
                                 boost::condition_variable *cond_var,
                                 int *result) {
  if (!mutex || !cond_var || !result)
    return;
  boost::mutex::scoped_lock lock(*mutex);
  if (response)
    *result = kSuccess;
  else
    *result = kRemoteChunkStoreFailure;
  cond_var->notify_one();
}

int WaitForResultsPtr(boost::mutex *mutex,
                      boost::condition_variable *cond_var,
                      std::vector<int> *results) {
  assert(results->size() < 50U);
  size_t size(results->size());
  try {
    boost::mutex::scoped_lock lock(*mutex);
    if (!cond_var->timed_wait(lock,
                              bptime::seconds(static_cast<int>(kSecondsInterval * size)),
                              [&]()->bool {
                                for (size_t i(0); i < size; ++i) {
                                  if (results->at(i) == kPendingResult)
                                    return false;
                                }
                                return true;
                              })) {
      LOG(kError) << "Timed out during waiting response.";
      return kOperationTimeOut;
    }
  }
  catch(const std::exception &e) {
    LOG(kError) << "Exception Failure during waiting response : " << e.what();
    return kOperationTimeOut;
  }
  return kSuccess;
}

int WaitForResults(boost::mutex &mutex,  // NOLINT (Dan)
                   boost::condition_variable &cond_var,  // NOLINT (Dan)
                   std::vector<int> &results) {  // NOLINT (Dan)
  assert(results.size() < 50U);
  size_t size(results.size());
  try {
    boost::mutex::scoped_lock lock(mutex);
    if (!cond_var.timed_wait(lock,
                             bptime::seconds(static_cast<int>(kSecondsInterval * size)),
                             [&]()->bool {
                               for (size_t i(0); i < size; ++i) {
                                 if (results.at(i) == kPendingResult)
                                   return false;
                               }
                               return true;
                             })) {
      LOG(kError) << "Timed out during waiting response.";
      return kOperationTimeOut;
    }
  }
  catch(const std::exception &e) {
    LOG(kError) << "Exception Failure during waiting response : " << e.what();
    return kOperationTimeOut;
  }
  return kSuccess;
}

std::string ComposeSignaturePacketName(const std::string &name) {
  return name + std::string (1, pca::kSignaturePacket);
}

std::string ComposeSignaturePacketValue(
    const pki::SignaturePacket &packet) {
  std::string public_key;
  asymm::EncodePublicKey(packet.value(), &public_key);
  pca::SignedData signed_data;
  signed_data.set_data(public_key);
  signed_data.set_signature(packet.signature());
  return signed_data.SerializeAsString();
}

std::string PutFilenameData(const std::string &file_name) {
  if (file_name.size() > 255U)
    return "";
  try {
    std::string data(boost::lexical_cast<std::string>(file_name.size()));
    while (data.size() < 3U)
      data.insert(0, "0");
    BOOST_ASSERT(data.size() == 3U);
    data += file_name;
    return data;
  }
  catch(const std::exception &e) {
    LOG(kError) << e.what();
    return "";
  }
}

void GetFilenameData(const std::string &content,
                     std::string *file_name,
                     std::string *serialised_data_map) {
  if (content.size() < 5U)
    return;

  try {
    int chars_to_read(boost::lexical_cast<int>(content.substr(0, 3)));
    *file_name = content.substr(3, chars_to_read);
    chars_to_read += 3;
    *serialised_data_map = content.substr(chars_to_read);
  }
  catch(const std::exception &e) {
    LOG(kError) << e.what();
  }
}

std::string GetNameInPath(const fs::path &save_path,
                          const std::string &file_name) {
  int index(0), limit(2000);
  fs::path path_file_name(file_name);
  std::string stem(path_file_name.stem().string()),
              extension(path_file_name.extension().string());

  boost::system::error_code ec;
  while (fs::exists(save_path / path_file_name, ec) && index++ < limit) {
    if (ec)
      continue;
    path_file_name = (stem + " (" + IntToString(index) + ")" + extension);
  }
  if (index == limit)
    path_file_name.clear();
  return path_file_name.string();
}

encrypt::DataMapPtr ParseSerialisedDataMap(
    const std::string &serialised_data_map) {
  encrypt::DataMapPtr data_map(new encrypt::DataMap);
  std::istringstream input_stream(serialised_data_map, std::ios_base::binary);
  try {
    boost::archive::text_iarchive input_archive(input_stream);
    input_archive >> *data_map;
  } catch(const boost::archive::archive_exception &e) {
    LOG(kError) << e.what();
    return encrypt::DataMapPtr();
  }
  return data_map;
}

int CopyDir(const fs::path& source, const fs::path& dest) {
  try {
    // Check whether the function call is valid
    if (!fs::exists(source) || !fs::is_directory(source)) {
      LOG(kError) << "Source directory " << source.string()
                  << " does not exist or is not a directory.";
      return kGeneralError;
    }
    if (!fs::exists(dest))
      fs::create_directory(dest);
  }
  catch(const fs::filesystem_error &e) {
    LOG(kError) << e.what();
    return kGeneralError;
  }
  // Iterate through the source directory
  for (fs::directory_iterator it(source);
      it != fs::directory_iterator(); it++) {
    try {
      fs::path current(it->path());
      if (fs::is_directory(current)) {
        // Found directory: Create directory and Recursion
        fs::create_directory(dest / current.filename());
        CopyDir(current, dest / current.filename());
      } else {
        // Found file: Copy
        fs::copy_file(current, fs::path(dest / current.filename()));
      }
    }
    catch(const fs::filesystem_error &e) {
      LOG(kError) << e.what();
    }
  }
  return kSuccess;
}

int CopyDirectoryContent(const fs::path& from, const fs::path& to) {
  boost::system::error_code error_code;
  int result;
  fs::directory_iterator it(from), end;
  try {
    for (; it != end; ++it) {
      fs::path current(it->path());
      if (fs::is_directory(*it)) {
        fs::create_directory(to / current.filename(), error_code);
        if (error_code) {
          LOG(kError) << "Failed to create directory: "
                      << to / current.filename()
                      << " " << error_code.message();
          return kGeneralError;
        }
        result = CopyDirectoryContent(current, to / current.filename());
        if (result != kSuccess) {
          LOG(kError) << "Failed to create directory "
                      << to / current.filename() << error_code.value();
          return kGeneralError;
        }
      } else if (fs::is_regular_file(*it)) {
        fs::copy_file(current, to / current.filename(), error_code);
        if (error_code) {
          LOG(kError) << "Failed to create file " << to / current.filename()
                      << error_code.value();
          return kGeneralError;
        }
      } else {
        if (fs::exists(*it))
          LOG(kError) << "Unknown file type found.";
        else
          LOG(kError) << "Nonexistant file type found.";
        return kGeneralError;
      }
    }
  }
  catch(...) {
    LOG(kError) << "Failed copying directory " << from << " to " << to;
    return kGeneralError;
  }
  return kSuccess;
}

bool VerifyOrCreatePath(const fs::path& path) {
  boost::system::error_code error_code;
  if (fs::exists(path, error_code) && !error_code) {
    LOG(kInfo) << path << " does exist.";
    return true;
  }

  if (!fs::create_directories(path, error_code) || error_code) {
    LOG(kError) << path << " doesn't exist and couldn't be created.";
    return false;
  }

  return true;
}

std::string IsoTimeWithMicroSeconds() {
  return bptime::to_iso_string(bptime::microsec_clock::universal_time());
}

}  // namespace lifestuff

}  // namespace maidsafe
