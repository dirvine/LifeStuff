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

#include "maidsafe/lifestuff/rcs_helper.h"

#include <fstream>  // NOLINT (Fraser)
#include <iostream>  // NOLINT (Fraser)
#include <istream>  // NOLINT (Fraser)
#include <ostream>  // NOLINT (Fraser)
#include <string>
#include <vector>

#include "boost/archive/text_iarchive.hpp"

#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

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

int GetValidatedMpidPublicKey(
    const std::string &public_username,
    std::shared_ptr<asymm::Keys> validation_key,
    std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
    asymm::PublicKey *public_key) {
  // Get public key packet from network
  std::string packet_name(crypto::Hash<crypto::SHA512>(public_username) +
                          std::string(1, pca::kAppendableByAll));
  std::string packet_value(remote_chunk_store->Get(packet_name,
                                                   validation_key));
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
  packet_value = remote_chunk_store->Get(packet_name, validation_key);
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
    std::shared_ptr<asymm::Keys> validation_key,
    std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
    asymm::PublicKey *public_key) {
  std::string packet_value(
      remote_chunk_store->Get(mmid_name + std::string(1, pca::kAppendableByAll),
                              validation_key));
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

#ifdef LOCAL_TARGETS_ONLY
std::shared_ptr<pcs::RemoteChunkStore> BuildChunkStore(
    const fs::path &buffered_chunk_store_path,
    const fs::path &local_chunk_manager_path,
    boost::asio::io_service &asio_service) {  // NOLINT (Dan)
  fs::path chunk_lock_path(local_chunk_manager_path / "ChunkLock");
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store(
      pcs::CreateLocalChunkStore(buffered_chunk_store_path,
                                 local_chunk_manager_path,
                                 chunk_lock_path,
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
//     bai::tcp::resolver::query query("127.0.0.1", "http");
    bai::tcp::resolver::query query("192.168.1.119", "http");
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
  if (!client_container->InitClientContainer(base_dir / "buffered_chunk_store", 10, 4)) {
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
