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

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
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

bool AcceptableWordSize(const std::string& word) {
  return word.size() >= kMinWordSize && word.size() <= kMaxWordSize;
}

bool AcceptableWordPattern(const std::string& word) {
  boost::regex space(" ");
  return !boost::regex_search(word.begin(), word.end(), space);
}

int CheckWordValidity(const std::string& word) {
  if (!AcceptableWordSize(word)) {
    LOG(kError) << "Unacceptable size: " << word.size();
    return kWordSizeInvalid;
  }

  if (!AcceptableWordPattern(word)) {
    LOG(kError) << "Unacceptable pattern: '" << word << "'";
    return kWordPatternInvalid;
  }

  return kSuccess;
}

int CheckKeywordValidity(const std::string& keyword) {
  return CheckWordValidity(keyword);
}

int CheckPasswordValidity(const std::string& password) {
  return CheckWordValidity(password);
}

int CheckPinValidity(const std::string& pin) {
  if (pin.size() != kPinSize) {
    LOG(kError) << "PIN wrong size: " << pin;
    return kPinSizeInvalid;
  }

  try {
    int peen(boost::lexical_cast<int>(pin));
    if (peen < 1) {
      LOG(kError) << "PIN out of range: " << peen;
      return kPinPatternInvalid;
    }
    return kSuccess;
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what();
    return kPinPatternInvalid;
  }
}

int CheckPublicIdValidity(const std::string& public_id) {
  if (public_id.empty()) {
    LOG(kError) << "Public ID empty.";
    return kPublicIdEmpty;
  }
  if (public_id.length() > kMaxPublicIdSize) {
    LOG(kError) << "Public ID too long: '" << public_id << "'";
    return kPublicIdLengthInvalid;
  }
  if (public_id.at(0) == ' ') {
    LOG(kError) << "Public ID starts with space: '" << public_id << "'";
    return kPublicIdEndSpaceInvalid;
  }
  if (public_id.at(public_id.length() - 1) == ' ') {
    LOG(kError) << "Public ID ends with space: '" << public_id << "'";
    return kPublicIdEndSpaceInvalid;
  }
  boost::regex double_space("  ");
  if (boost::regex_search(public_id.begin(), public_id.end(), double_space)) {
    LOG(kError) << "Public ID contains double space: '" << public_id << "'";
    return kPublicIdDoubleSpaceInvalid;
  }
  return kSuccess;
}

fs::path CreateTestDirectory(fs::path const& parent, std::string* tail) {
  *tail = RandomAlphaNumericString(5);
  fs::path directory(parent / (*tail));
  boost::system::error_code error_code;
  fs::create_directories(directory, error_code);
  if (error_code)
    return fs::path();
  return directory;
}

int CreateTestFile(fs::path const& parent, int size_in_mb, std::string* file_name) {
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
  catch(const std::exception& e) {
    LOG(kError) << "Failed to write file " << file_path << ": " << e.what();
    return -1;
  }

  return kSuccess;
}

int CreateSmallTestFile(fs::path const& parent, int size_in_kb, std::string* file_name) {
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
  catch(const std::exception& e) {
    LOG(kError) << "Failed to write file " << file_path << ": " << e.what();
    return -1;
  }

  return kSuccess;
}

std::string ComposeSignaturePacketName(const std::string& name) {
  return name + std::string (1, pca::kSignaturePacket);
}

std::string ComposeModifyAppendableByAll(const asymm::PrivateKey& signing_key,
                                         const char appendability) {
  std::string appendability_string(1, appendability);
  pca::SignedData signed_data;
  std::string signature;

  asymm::Sign(appendability_string, signing_key, &signature);
  signed_data.set_data(appendability_string);
  signed_data.set_signature(signature);
  pca::ModifyAppendableByAll modify;
  modify.mutable_allow_others_to_append()->CopyFrom(signed_data);
  return modify.SerializeAsString();
}

std::string AppendableIdValue(const asymm::Keys& data, bool accepts_new_contacts) {
  pca::AppendableByAll contact_id;
  pca::SignedData* identity_key = contact_id.mutable_identity_key();
  pca::SignedData* allow_others_to_append = contact_id.mutable_allow_others_to_append();

  std::string public_key;
  asymm::EncodePublicKey(data.public_key, &public_key);
  identity_key->set_data(public_key);
  identity_key->set_signature(data.validation_token);
  allow_others_to_append->set_data(accepts_new_contacts ? std::string(1, pca::kAppendableByAll) :
                                                          std::string(1, pca::kModifiableByOwner));

  asymm::Signature packet_signature;
  int result(asymm::Sign(allow_others_to_append->data(), data.private_key, &packet_signature));
  if (result != kSuccess) {
    LOG(kError) << "AppendableIdValue - Failed to sign";
    return "";
  }

  allow_others_to_append->set_signature(packet_signature);

  return contact_id.SerializeAsString();
}

std::string MaidsafeContactIdName(const std::string& public_id) {
  return crypto::Hash<crypto::SHA512>(public_id) + std::string(1, pca::kAppendableByAll);
}

std::string SignaturePacketName(const std::string& name) {
  return name + std::string (1, pca::kSignaturePacket);
}

std::string AppendableByAllName(const std::string& name) {
  return name + std::string (1, pca::kAppendableByAll);
}

std::string SignaturePacketValue(const asymm::Keys& keys) {
  pca::SignedData signed_data;
  std::string serialised_public_key;
  asymm::EncodePublicKey(keys.public_key, &serialised_public_key);
  if (serialised_public_key.empty())
    return "";

  signed_data.set_data(serialised_public_key);
  signed_data.set_signature(keys.validation_token);
  return signed_data.SerializeAsString();
}

std::string PutFilenameData(const std::string& file_name) {
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
  catch(const std::exception& e) {
    LOG(kError) << e.what();
    return "";
  }
}

void GetFilenameData(const std::string& content,
                     std::string* file_name,
                     std::string* serialised_data_map) {
  if (content.size() < 5U)
    return;

  try {
    int chars_to_read(boost::lexical_cast<int>(content.substr(0, 3)));
    *file_name = content.substr(3, chars_to_read);
    chars_to_read += 3;
    *serialised_data_map = content.substr(chars_to_read);
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what();
  }
}

std::string GetNameInPath(const fs::path& save_path, const std::string& file_name) {
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

encrypt::DataMapPtr ParseSerialisedDataMap(const std::string& serialised_data_map) {
//  LOG(kError) << "ParseSerialisedDataMap - input size: " << serialised_data_map.size();
  encrypt::DataMapPtr data_map(new encrypt::DataMap);
  std::istringstream input_stream(serialised_data_map, std::ios_base::binary);
  try {
    boost::archive::text_iarchive input_archive(input_stream);
    input_archive >> *data_map;
  } catch(const boost::archive::archive_exception& e) {
    LOG(kError) << e.what();
    return encrypt::DataMapPtr();
  }
  return data_map;
}

bool CheckCorrectKeys(const std::vector<std::string>& content, asymm::Keys* keys) {
  if (content.at(kKeysIdentity).empty())
    return true;
  asymm::DecodePrivateKey(content.at(kKeysPrivateKey), &(keys->private_key));
  asymm::DecodePublicKey(content.at(kKeysPublicKey), &(keys->public_key));
  if (!asymm::ValidateKey(keys->private_key) || !asymm::ValidateKey(keys->public_key)) {
    LOG(kError) << "Keys in message are invalid.";
    keys->private_key = asymm::PrivateKey();
    keys->public_key = asymm::PublicKey();
    return false;
  }
  keys->identity = content.at(kKeysIdentity);
  keys->validation_token = content.at(kKeysValidationToken);
  return true;
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
  catch(const fs::filesystem_error& e) {
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
    catch(const fs::filesystem_error& e) {
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

void OperationCallback(bool result, OperationResults& results, int index) {
  boost::mutex::scoped_lock barra_loch_an_duin(results.mutex);
  results.individual_results.at(index) = result ? kSuccess : kRemoteChunkStoreFailure;
  results.conditional_variable.notify_one();
}

int AssessJointResult(const std::vector<int>& results) {
  auto it(std::find_if(results.begin(),
                       results.end(),
                       [&](const int& element)->bool {
                         return element != kSuccess;
                       }));
  if (it != results.end())
    return kAtLeastOneFailure;

  return kSuccess;
}

bool MessagePointToPoint(const std::string& unwrapped_message,
                         const asymm::PublicKey& recipient_public_key,
                         const asymm::PrivateKey& sender_private_key,
                         std::string& final_message) {
  std::string encrypted_message;
  int result(asymm::Encrypt(unwrapped_message, recipient_public_key, &encrypted_message));
  if (result != kSuccess) {
    LOG(kError) << "Failed to encrypt message: " << result;
    return false;
  }

  pca::SignedData signed_data;
  signed_data.set_data(encrypted_message);

  std::string message_signature;
  result = asymm::Sign(signed_data.data(), sender_private_key, &message_signature);
  if (result != kSuccess) {
    LOG(kError) << "Failed to sign message: " << result;
    return false;
  }
  signed_data.set_signature(message_signature);

  if (!signed_data.SerializeToString(&final_message)) {
    LOG(kError) << "Failed to sign message: " << result;
    return false;
  }

  return true;
}

bool PointToPointMessageValid(const std::string& wrapped_message,
                              const asymm::PublicKey& sender_public_key,
                              const asymm::PrivateKey& receiver_private_key,
                              std::string& final_message) {
  pca::SignedData signed_data;
  if (!signed_data.ParseFromString(wrapped_message)) {
    LOG(kError) << "Message doesn't parse to SignedData.";
    return false;
  }

  int result(asymm::CheckSignature(signed_data.data(), signed_data.signature(), sender_public_key));
  if (result != kSuccess) {
    LOG(kError) << "Failed to validate signature of message: " << result;
    return false;
  }

  result = asymm::Decrypt(signed_data.data(), receiver_private_key, &final_message);
  if (result != kSuccess) {
    LOG(kError) << "Failed to decrypt message: " << result;
    return false;
  }

  return true;
}

}  // namespace lifestuff

}  // namespace maidsafe
