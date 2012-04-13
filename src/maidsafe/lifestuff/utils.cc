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

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/return_codes.h"

namespace pca = maidsafe::priv::chunk_actions;
namespace bai = boost::asio::ip;

namespace maidsafe {

namespace lifestuff {

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
    const maidsafe::pki::SignaturePacket &packet) {
  std::string public_key;
  asymm::EncodePublicKey(packet.value(), &public_key);
  pca::SignedData signed_data;
  signed_data.set_data(public_key);
  signed_data.set_signature(packet.signature());
  return signed_data.SerializeAsString();
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

#ifndef LOCAL_TARGETS_ONLY

int RetrieveBootstrapContacts(const fs::path &download_dir,
                              std::vector<dht::Contact> *bootstrap_contacts) {
  std::ostringstream bootstrap_stream(std::ios::binary);
  try {
    boost::asio::io_service io_service;

    // Get a list of endpoints corresponding to the server name.
    bai::tcp::resolver resolver(io_service);
//    bai::tcp::resolver::query query("96.126.103.209", "http");
    bai::tcp::resolver::query query("192.168.1.113", "http");
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

ClientContainerPtr SetUpClientContainer(const fs::path &test_dir) {
  std::shared_ptr<asymm::Keys> key_pair(new asymm::Keys);
  int result(asymm::GenerateKeyPair(key_pair.get()));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to generate key pair.  Result: " << result;
    return ClientContainerPtr();
  }

  std::string pub_key;
  asymm::EncodePublicKey(key_pair->public_key, &pub_key);
  result = asymm::Sign(pub_key, key_pair->private_key,
                       &key_pair->validation_token);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to sign public key.  Result: " << result;
    return ClientContainerPtr();
  }

  key_pair->identity =
      crypto::Hash<crypto::SHA512>(pub_key + key_pair->validation_token);

  ClientContainerPtr client_container(new pd::ClientContainer);
  client_container->set_key_pair(key_pair);
  if (!client_container->Init(test_dir / "buffered_chunk_store", 10, 4)) {
    DLOG(ERROR) << "Failed to Init client_container.";
    return ClientContainerPtr();
  }

  std::vector<dht::Contact> bootstrap_contacts;
  result = RetrieveBootstrapContacts(test_dir, &bootstrap_contacts);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to retrieve bootstrap contacts.  Result: " << result;
    return ClientContainerPtr();
  }

  result = client_container->Start(&bootstrap_contacts);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to start client_container.  Result: " << result;
    return ClientContainerPtr();
  }

  DLOG(INFO) << "Started client_container.";
  return client_container;
}

#endif

}  // namespace lifestuff

}  // namespace maidsafe
