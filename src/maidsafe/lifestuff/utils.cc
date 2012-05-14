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

#include "maidsafe/lifestuff/utils.h"

#include <fstream>  // NOLINT (Fraser)
#include <iostream>  // NOLINT (Fraser)
#include <istream>  // NOLINT (Fraser)
#include <ostream>  // NOLINT (Fraser)
#include <vector>

#include "boost/asio.hpp"
#include "boost/archive/text_iarchive.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/regex.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#include "maidsafe/encrypt/data_map.h"

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/dht/contact.h"
#include "maidsafe/pd/client/client_container.h"
#include "maidsafe/pd/client/utils.h"
#endif

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/return_codes.h"

namespace pca = maidsafe::priv::chunk_actions;
namespace bai = boost::asio::ip;

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
    DLOG(ERROR) << "Unacceptable size: " << word.size();
    return false;
  }

  if (!AcceptableWordPattern(word)) {
    DLOG(ERROR) << "Unacceptable pattern: '" << word << "'";
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
      DLOG(ERROR) << "PIN out of range: " << peen;
      return false;
    }
    std::string pattern("[0-9]{" +
                        boost::lexical_cast<std::string>(kPinSize) +
                        "}");
    boost::regex rx(pattern);
    return boost::regex_match(pin.begin(), pin.end(), rx);
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << e.what();
    return false;
  }
}

fs::path CreateTestDirectory(fs::path const& parent, std::string *tail) {
  *tail = RandomAlphaNumericString(5);
  fs::path directory(parent / (*tail));
  boost::system::error_code error_code;
  fs::create_directories(directory, error_code);
  return directory;
}

int CreateTestFile(fs::path const& parent,
                   int size_in_mb,
                   std::string *file_name) {
  if (size_in_mb > 1024) {
    DLOG(ERROR) << "This function doesn't create files larger than 1024MB.";
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
      DLOG(ERROR) << "Can't get ofstream created for " << file_path;
      return -1;
    }
    for (int rounds(0); rounds < total; ++rounds)
      file_out.write(random_string.data(), random_string.size());
    file_out.close();
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Failed to write file " << file_path << ": " << e.what();
    return -1;
  }

  return kSuccess;
}

int GetValidatedMpidPublicKey(
    const std::string &public_username,
    const pcs::RemoteChunkStore::ValidationData &validation_data,
    std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
    asymm::PublicKey *public_key) {
  // Get public key packet from network
  std::string packet_name(crypto::Hash<crypto::SHA512>(public_username) +
                          std::string(1, pca::kAppendableByAll));
  std::string packet_value(remote_chunk_store->Get(packet_name,
                                                   validation_data));
  if (packet_value.empty()) {
    DLOG(ERROR) << "Failed to get public key for " << public_username;
    *public_key = asymm::PublicKey();
    return kGetPublicKeyFailure;
  }

  pca::SignedData packet;
  if (!packet.ParseFromString(packet_value)) {
    DLOG(ERROR) << "Failed to parse public key packet for " << public_username;
    *public_key = asymm::PublicKey();
    return kGetPublicKeyFailure;
  }
  BOOST_ASSERT(!packet.data().empty());
  BOOST_ASSERT(!packet.signature().empty());

  // Decode and validate public key
  std::string serialised_public_key(packet.data());
  std::string public_key_signature(packet.signature());
  asymm::DecodePublicKey(serialised_public_key, public_key);
  if (!asymm::ValidateKey(*public_key)) {
    DLOG(ERROR) << "Failed to validate public key for " << public_username;
    *public_key = asymm::PublicKey();
    return kGetPublicKeyFailure;
  }

  // Get corresponding MPID packet from network
  std::string mpid_value(serialised_public_key + public_key_signature);
  std::string mpid_name(crypto::Hash<crypto::SHA512>(mpid_value) +
                        std::string(1, pca::kSignaturePacket));
  packet_value = remote_chunk_store->Get(packet_name, validation_data);
  if (packet_value.empty()) {
    DLOG(ERROR) << "Failed to get MPID for " << public_username;
    *public_key = asymm::PublicKey();
    return kGetMpidFailure;
  }

  packet.Clear();
  if (!packet.ParseFromString(packet_value)) {
    DLOG(ERROR) << "Failed to parse MPID packet for " << public_username;
    *public_key = asymm::PublicKey();
    return kGetMpidFailure;
  }
  BOOST_ASSERT(!packet.data().empty());
  BOOST_ASSERT(!packet.signature().empty());

  // Check that public key packet matches MPID packet, and validate the
  // signature
  if (serialised_public_key != packet.data() ||
      public_key_signature != packet.signature()) {
    DLOG(ERROR) << "Public key doesn't match MPID for " << public_username;
    *public_key = asymm::PublicKey();
    return kInvalidPublicKey;
  }

  return kSuccess;
}

int GetValidatedMmidPublicKey(
    const std::string &mmid_name,
    const pcs::RemoteChunkStore::ValidationData &validation_data,
    std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
    asymm::PublicKey *public_key) {
  std::string packet_value(
      remote_chunk_store->Get(mmid_name + std::string(1, pca::kAppendableByAll),
                              validation_data));
  if (packet_value.empty()) {
    DLOG(ERROR) << "Failed to get public key for " << Base32Substr(mmid_name);
    *public_key = asymm::PublicKey();
    return kGetPublicKeyFailure;
  }

  pca::SignedData packet;
  if (!packet.ParseFromString(packet_value)) {
    DLOG(ERROR) << "Failed to parse public key packet for "
                << Base32Substr(mmid_name);
    *public_key = asymm::PublicKey();
    return kGetPublicKeyFailure;
  }
  BOOST_ASSERT(!packet.data().empty());
  BOOST_ASSERT(!packet.signature().empty());

  // Validate self-signing
  if (crypto::Hash<crypto::SHA512>(packet.data() + packet.signature()) !=
      mmid_name) {
    DLOG(ERROR) << "Failed to validate MMID " << Base32Substr(mmid_name);
    *public_key = asymm::PublicKey();
    return kGetPublicKeyFailure;
  }

  // Decode and validate public key
  std::string serialised_public_key(packet.data());
  std::string public_key_signature(packet.signature());
  asymm::DecodePublicKey(serialised_public_key, public_key);
  if (!asymm::ValidateKey(*public_key)) {
    DLOG(ERROR) << "Failed to validate public key for "
                << Base32Substr(mmid_name);
    *public_key = asymm::PublicKey();
    return kGetPublicKeyFailure;
  }

  return kSuccess;
}

void SendContactInfoCallback(const bool &response,
                             boost::mutex *mutex,
                             boost::condition_variable *cond_var,
                             int *result) {
  if (!mutex || !cond_var || !result)
    return;
  boost::mutex::scoped_lock lock(*mutex);
  if (response)
    *result = kSuccess;
  else
    *result = kSendContactInfoFailure;
  cond_var->notify_one();
}

int AwaitingResponse(boost::mutex *mutex,
                     boost::condition_variable *cond_var,
                     std::vector<int> *results) {
  size_t size(results->size());
  try {
    boost::mutex::scoped_lock lock(*mutex);
    if (!cond_var->timed_wait(lock,
                              boost::posix_time::seconds(30),
                              [&]()->bool {
                                for (size_t i(0); i < size; ++i) {
                                  if (results->at(i) == kPendingResult)
                                    return false;
                                }
                                return true;
                              })) {
      DLOG(ERROR) << "Timed out during waiting response.";
      return kPublicIdTimeout;
    }
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Exception Failure during waiting response : " << e.what();
    return kPublicIdException;
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
    DLOG(ERROR) << e.what();
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
    DLOG(ERROR) << e.what();
  }
}

std::string GetNameInPath(const fs::path &save_path,
                          const std::string &file_name) {
  int index(0), limit(10);
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
    DLOG(ERROR) << e.what();
    return encrypt::DataMapPtr();
  }
  return data_map;
}

int CopyDir(const fs::path& source, const fs::path& dest) {
  try {
    // Check whether the function call is valid
    if (!fs::exists(source) || !fs::is_directory(source)) {
      DLOG(ERROR) << "Source directory " << source.string()
                  << " does not exist or is not a directory.";
      return kGeneralError;
    }
    if (!fs::exists(dest))
      fs::create_directory(dest);
  }
  catch(const fs::filesystem_error &e) {
    DLOG(ERROR) << e.what();
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
      DLOG(ERROR) << e.what();
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
          DLOG(ERROR) << "Failed to create directory: "
                      << to / current.filename()
                      << " " << error_code.message();
          return kGeneralError;
        }
        result = CopyDirectoryContent(current, to / current.filename());
        if (result != kSuccess) {
          DLOG(ERROR) << "Failed to create directory "
                      << to / current.filename() << error_code.value();
          return kGeneralError;
        }
      } else if (fs::is_regular_file(*it)) {
        fs::copy_file(current, to / current.filename(), error_code);
        if (error_code) {
          DLOG(ERROR) << "Failed to create file " << to / current.filename()
                      << error_code.value();
          return kGeneralError;
        }
      } else {
        if (fs::exists(*it))
          DLOG(ERROR) << "Unknown file type found.";
        else
          DLOG(ERROR) << "Nonexistant file type found.";
        return kGeneralError;
      }
    }
  }
  catch(...) {
    DLOG(ERROR) << "Failed copying directory " << from << " to " << to;
    return kGeneralError;
  }
  return kSuccess;
}

bool VerifyAndCreatePath(const fs::path& path) {
  boost::system::error_code error_code;
  if (fs::exists(path, error_code) && !error_code) {
    DLOG(INFO) << path << " does exist.";
    return true;
  }

  if (fs::create_directories(path, error_code) && !error_code) {
    DLOG(INFO) << path << " created successfully.";
    return true;
  }

  DLOG(ERROR) << path << " doesn't exist and couldn't be created.";
  return false;
}

std::string IsoTimeWithMicroSeconds() {
  return bptime::to_iso_string(bptime::microsec_clock::universal_time());
}

#ifdef LOCAL_TARGETS_ONLY
std::shared_ptr<pcs::RemoteChunkStore> BuildChunkStore(
    const fs::path &buffered_chunk_store_path,
    const fs::path &local_chunk_manager_path,
    boost::asio::io_service &asio_service) {  // NOLINT (Dan)
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store(
      pcs::CreateLocalChunkStore(buffered_chunk_store_path,
                                 local_chunk_manager_path,
                                 asio_service));
  return remote_chunk_store;
}
#else
std::shared_ptr<priv::chunk_store::RemoteChunkStore> BuildChunkStore(
    const fs::path &base_dir,
    std::shared_ptr<pd::ClientContainer> *client_container) {
  BOOST_ASSERT(client_container);
  *client_container = SetUpClientContainer(base_dir);
  if (*client_container) {
    std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store(
        new pcs::RemoteChunkStore((*client_container)->chunk_store(),
            (*client_container)->chunk_manager(),
            (*client_container)->chunk_action_authority()));
    remote_chunk_store->SetMaxActiveOps(32);
    return remote_chunk_store;
  } else {
    DLOG(ERROR) << "Failed to initialise client container.";
    return nullptr;
  }
}

int RetrieveBootstrapContacts(const fs::path &download_dir,
                              std::vector<dht::Contact> *bootstrap_contacts) {
  std::ostringstream bootstrap_stream(std::ios::binary);
  try {
    boost::asio::io_service io_service;

    // Get a list of endpoints corresponding to the server name.
    bai::tcp::resolver resolver(io_service);
//     bai::tcp::resolver::query query("96.126.103.209", "http");
     bai::tcp::resolver::query query("127.0.0.1", "http");
//    bai::tcp::resolver::query query("192.168.1.119", "http");
    bai::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

    // Try each endpoint until we successfully establish a connection.
    bai::tcp::socket socket(io_service);
    boost::asio::connect(socket, endpoint_iterator);

    // Form the request. We specify the "Connection: close" header so that the
    // server will close the socket after transmitting the response. This will
    // allow us to treat all data up until the EOF as the content.
    boost::asio::streambuf request;
    std::ostream request_stream(&request);
    request_stream << "GET /bootstrap HTTP/1.0\r\n";
    request_stream << "Host: LifeStuffTest\r\n";
    request_stream << "Accept: */*\r\n";
    request_stream << "Connection: close\r\n\r\n";

    // Send the request.
    boost::asio::write(socket, request);

    // Read the response status line. The response streambuf will automatically
    // grow to accommodate the entire line. The growth may be limited by passing
    // a maximum size to the streambuf constructor.
    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\r\n");

    // Check that response is OK.
    std::istream response_stream(&response);
    std::string http_version;
    response_stream >> http_version;
    unsigned int status_code;
    response_stream >> status_code;
    std::string status_message;
    std::getline(response_stream, status_message);
    if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
      DLOG(ERROR) << "Error downloading bootstrap file: Invalid response";
      return kGeneralError;
    }
    if (status_code != 200) {
      DLOG(ERROR) << "Error downloading bootstrap file: Response returned "
                  << "with status code " << status_code;
      return kGeneralError;
    }

    // Read the response headers, which are terminated by a blank line.
    boost::asio::read_until(socket, response, "\r\n\r\n");

    // Process the response headers.
    std::string header;
    while (std::getline(response_stream, header)) {
      if (header == "\r")
        break;
    }

    // Write whatever content we already have to output.
    if (response.size() > 0)
      bootstrap_stream << &response;

    // Read until EOF, writing data to output as we go.
    boost::system::error_code error;
    while (boost::asio::read(socket,
                             response,
                             boost::asio::transfer_at_least(1),
                             error))
      bootstrap_stream << &response;

    if (error != boost::asio::error::eof) {
      DLOG(ERROR) << "Error downloading bootstrap file: " << error.message();
      return error.value();
    }
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Exception: " << e.what();
    return kGeneralException;
  }

  fs::path bootstrap_file(download_dir / "bootstrap");
  WriteFile(bootstrap_file, bootstrap_stream.str());
  if (!maidsafe::dht::ReadContactsFromFile(bootstrap_file,
                                           bootstrap_contacts)) {
    DLOG(ERROR) << "Failed to read " << bootstrap_file;
    return kGeneralError;
  }

  return kSuccess;
}

ClientContainerPtr SetUpClientContainer(
    const fs::path &base_dir) {
  ClientContainerPtr client_container(new pd::ClientContainer);
  if (!client_container->Init(base_dir / "buffered_chunk_store", 10, 4)) {
    DLOG(ERROR) << "Failed to initialise client container.";
    return nullptr;
  }

  std::vector<dht::Contact> bootstrap_contacts;
  int result = RetrieveBootstrapContacts(base_dir, &bootstrap_contacts);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to retrieve bootstrap contacts.  Result: " << result;
    return nullptr;
  }

  result = client_container->Start(bootstrap_contacts);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to start client container.  Result: " << result;
    return nullptr;
  }

  DLOG(INFO) << "Started client_container.";
  return client_container;
}
#endif

}  // namespace lifestuff

}  // namespace maidsafe
