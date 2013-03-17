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

#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/regex.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/appendable_by_all.pb.h"
#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk.pb.h"
#include "maidsafe/private/chunk_actions/chunk_id.h"

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

NonEmptyString CreatePin() {
  std::stringstream pin_stream;
  uint32_t pin(0);
  while (pin < 1000)
    pin = RandomUint32() % 10000;
  pin_stream << pin;
  return NonEmptyString(pin_stream.str());
}

bool AcceptableWordSize(const std::string& word) {
  return word.size() >= kMinWordSize && word.size() <= kMaxWordSize;
}

bool AcceptableWordPattern(const std::string& word) {
  boost::regex space(" ");
  return !boost::regex_search(word.begin(), word.end(), space);
}

int CheckWordValidity(const NonEmptyString& word) {
  if (!AcceptableWordSize(word.string())) {
    LOG(kError) << "Unacceptable size: " << word.string().size();
    return kWordSizeInvalid;
  }

  if (!AcceptableWordPattern(word.string())) {
    LOG(kError) << "Unacceptable pattern: '" << word.string() << "'";
    return kWordPatternInvalid;
  }

  return kSuccess;
}

int CheckKeywordValidity(const NonEmptyString& keyword) {
  int result(CheckWordValidity(keyword));
  if (result == kWordSizeInvalid)
    return kKeywordSizeInvalid;
  else if (result == kWordPatternInvalid)
    return kKeywordPatternInvalid;
  return kSuccess;
}

int CheckPasswordValidity(const NonEmptyString& password) {
  int result(CheckWordValidity(password));
  if (result == kWordSizeInvalid)
    return kPasswordSizeInvalid;
  else if (result == kWordPatternInvalid)
    return kPasswordPatternInvalid;
  return kSuccess;
}

int CheckPinValidity(const NonEmptyString& pin) {
  if (pin.string().size() != kPinSize) {
    LOG(kError) << "PIN wrong size: " << pin.string();
    return kPinSizeInvalid;
  }

  try {
    int peen(boost::lexical_cast<int>(pin.string()));
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

int CheckPublicIdValidity(const NonEmptyString& public_id) {
  std::string str_public_id(public_id.string());
  if (str_public_id.length() > kMaxPublicIdSize) {
    LOG(kError) << "Public ID too long: '" << str_public_id << "'";
    return kPublicIdLengthInvalid;
  }
  if (str_public_id.at(0) == ' ') {
    LOG(kError) << "Public ID starts with space: '" << str_public_id << "'";
    return kPublicIdEndSpaceInvalid;
  }
  if (str_public_id.at(str_public_id.length() - 1) == ' ') {
    LOG(kError) << "Public ID ends with space: '" << str_public_id << "'";
    return kPublicIdEndSpaceInvalid;
  }
  boost::regex double_space("  ");
  if (boost::regex_search(str_public_id.begin(), str_public_id.end(), double_space)) {
    LOG(kError) << "Public ID contains double space: '" << str_public_id << "'";
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
    LOG(kError) << "This function doesn't create files larger than 1024KB.";
    return -1;
  }

  std::string random_string(RandomString(256)), content;
  *file_name = RandomAlphaNumericString(8);
  fs::path file_path(parent / *file_name);
  int total(size_in_kb * 4);
  for (int rounds(0); rounds < total; ++rounds)
    content += random_string;

  return WriteFile(file_path, content) ? kSuccess : -1;
}

priv::ChunkId ComposeSignaturePacketName(const Identity& name) {
  return priv::ApplyTypeToName(name, priv::ChunkType::kSignaturePacket);
}

NonEmptyString ComposeModifyAppendableByAll(const asymm::PrivateKey& signing_key,
                                            const bool appendability) {
  asymm::PlainText appendability_string(
      std::string(1, static_cast<char>(appendability ? priv::ChunkType::kAppendableByAll :
                                                       priv::ChunkType::kModifiableByOwner)));
  pca::SignedData signed_data;
  asymm::Signature signature(asymm::Sign(appendability_string, signing_key));
  signed_data.set_data(appendability_string.string());
  signed_data.set_signature(signature.string());
  pca::ModifyAppendableByAll modify;
  modify.mutable_allow_others_to_append()->CopyFrom(signed_data);
  return NonEmptyString(modify.SerializeAsString());
}

NonEmptyString AppendableIdValue(const Fob& fob, bool accepts_new_contacts) {
  pca::AppendableByAll contact_id;
  pca::SignedData* identity_key = contact_id.mutable_identity_key();
  pca::SignedData* allow_others_to_append = contact_id.mutable_allow_others_to_append();

  asymm::EncodedPublicKey public_key(asymm::EncodeKey(fob.keys.public_key));
  identity_key->set_data(public_key.string());
  identity_key->set_signature(fob.validation_token.string());
  allow_others_to_append->set_data(
      accepts_new_contacts ?
          std::string(1, static_cast<char>(priv::ChunkType::kAppendableByAll)) :
          std::string(1, static_cast<char>(priv::ChunkType::kModifiableByOwner)));

  asymm::Signature packet_signature(asymm::Sign(asymm::PlainText(allow_others_to_append->data()),
                                                fob.keys.private_key));
  allow_others_to_append->set_signature(packet_signature.string());

  return NonEmptyString(contact_id.SerializeAsString());
}

priv::ChunkId MaidsafeContactIdName(const NonEmptyString& public_id) {
  return priv::ChunkId(crypto::Hash<crypto::SHA512>(public_id).string() +
                       std::string(1, static_cast<char>(priv::ChunkType::kAppendableByAll)));
}

priv::ChunkId SignaturePacketName(const Identity& name) {
  return priv::ApplyTypeToName(name, priv::ChunkType::kSignaturePacket);
}

priv::ChunkId AppendableByAllName(const Identity& name) {
  return priv::ApplyTypeToName(name, priv::ChunkType::kAppendableByAll);
}

priv::ChunkId ModifiableName(const Identity& name) {
  return priv::ApplyTypeToName(name, priv::ChunkType::kModifiableByOwner);
}

NonEmptyString SignaturePacketValue(const Fob& fob) {
  pca::SignedData signed_data;
  asymm::EncodedPublicKey serialised_public_key(asymm::EncodeKey(fob.keys.public_key));
  signed_data.set_data(serialised_public_key.string());
  signed_data.set_signature(fob.validation_token.string());
  return NonEmptyString(signed_data.SerializeAsString());
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
                     std::string& file_name,
                     std::string& serialised_data_map) {
  if (content.size() < 5U)
    return;

  try {
    int chars_to_read(boost::lexical_cast<int>(content.substr(0, 3)));
    file_name = content.substr(3, chars_to_read);
    chars_to_read += 3;
    serialised_data_map = content.substr(chars_to_read);
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
    path_file_name = (stem + " (" + std::to_string(index) + ")" + extension);
  }
  if (index == limit)
    path_file_name.clear();
  return path_file_name.string();
}

encrypt::DataMap ParseSerialisedDataMap(const NonEmptyString& serialised_data_map) {
  encrypt::DataMap data_map;
  encrypt::ParseDataMap(serialised_data_map.string(), data_map);
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
        if (fs::exists(*it)) {
          LOG(kError) << "Unknown file type found.";
        } else {
          LOG(kError) << "Nonexistant file type found.";
        }
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
  {
    std::lock_guard<std::mutex> lock(results.mutex);
    results.individual_results.at(index) = result ? kSuccess : kRemoteChunkStoreFailure;
    results.conditional_variable.notify_one();
  }
}

int AssessJointResult(const std::vector<int>& results) {
  auto it(std::find_if(results.begin(),
                       results.end(),
                       [&] (const int& element)->bool { return element != kSuccess; }));  // NOLINT (Alison)
  if (it != results.end())
    return kAtLeastOneFailure;

  return kSuccess;
}

NonEmptyString MessagePointToPoint(const NonEmptyString& unwrapped_message,
                                   const asymm::PublicKey& recipient_public_key,
                                   const asymm::PrivateKey& sender_private_key) {
  asymm::CipherText encrypted_message(asymm::Encrypt(unwrapped_message, recipient_public_key));
  pca::SignedData signed_data;
  signed_data.set_data(encrypted_message.string());

  asymm::Signature message_signature(asymm::Sign(asymm::PlainText(signed_data.data()),
                                                 sender_private_key));
  signed_data.set_signature(message_signature.string());

  return NonEmptyString(signed_data.SerializeAsString());
}

bool PointToPointMessageValid(const NonEmptyString& wrapped_message,
                              const asymm::PublicKey& sender_public_key,
                              const asymm::PrivateKey& receiver_private_key,
                              std::string& final_message) {
  pca::SignedData signed_data;
  if (!signed_data.ParseFromString(wrapped_message.string())) {
    LOG(kError) << "Message doesn't parse to SignedData.";
    return false;
  }

  if (!asymm::CheckSignature(asymm::PlainText(signed_data.data()),
                             asymm::Signature(signed_data.signature()),
                             sender_public_key)) {
    LOG(kError) << "Failed to validate signature of message";
    return false;
  }

  asymm::PlainText decrypted_message(asymm::Decrypt(asymm::CipherText(signed_data.data()),
                                                    receiver_private_key));
  final_message = decrypted_message.string();

  return true;
}

}  // namespace lifestuff

}  // namespace maidsafe
