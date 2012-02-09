/* ============================================================================
*
* Copyright [2012] maidsafe.net limited
*
* Version:      1.0
* Created:      2011-04-18
* Author:       Team
* Company:      maidsafe.net limited
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


#include "maidsafe/lifestuff/tests/test_utils.h"

#include <fstream>  // NOLINT (Fraser)
#include <iostream>  // NOLINT (Fraser)
#include <istream>  // NOLINT (Fraser)
#include <ostream>  // NOLINT (Fraser)
#include <string>

#include "boost/asio.hpp"

#include "maidsafe/dht/contact.h"

#include "maidsafe/pd/client/utils.h"
#include "maidsafe/pd/client/client_container.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/return_codes.h"


using boost::asio::ip::tcp;

namespace maidsafe {

namespace lifestuff {

namespace test {

int RetrieveBootstrapContacts(const fs::path &download_dir,
                              std::vector<dht::Contact> *bootstrap_contacts) {
  fs::path bootstrap_file(download_dir / "bootstrap.xml");
  std::ofstream bootstrap_stream(bootstrap_file.c_str(), std::ofstream::trunc);
  if (!bootstrap_stream.good()) {
    DLOG(ERROR) << "Can't open " << bootstrap_file << " for writing.";
    return kGeneralError;
  }

  try {
    boost::asio::io_service io_service;

    // Get a list of endpoints corresponding to the server name.
    tcp::resolver resolver(io_service);
    tcp::resolver::query query("192.168.1.53", "http");
    tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

    // Try each endpoint until we successfully establish a connection.
    tcp::socket socket(io_service);
    boost::asio::connect(socket, endpoint_iterator);

    // Form the request. We specify the "Connection: close" header so that the
    // server will close the socket after transmitting the response. This will
    // allow us to treat all data up until the EOF as the content.
    boost::asio::streambuf request;
    std::ostream request_stream(&request);
    request_stream << "GET /bootstrap.xml HTTP/1.0\r\n";
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
      DLOG(ERROR) << "Error downloading bootstrap.xml: Invalid response";
      bootstrap_stream.close();
      return kGeneralError;
    }
    if (status_code != 200) {
      DLOG(ERROR) << "Error downloading bootstrap.xml: Response returned "
                  << "with status code " << status_code;
      bootstrap_stream.close();
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
    while (boost::asio::read(socket, response,
                             boost::asio::transfer_at_least(1), error))
      bootstrap_stream << &response;

    if (error != boost::asio::error::eof) {
      DLOG(ERROR) << "Error downloading bootstrap.xml: " << error.message();
      bootstrap_stream.close();
      return error.value();
    }
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Exception: " << e.what();
    bootstrap_stream.close();
    return kGeneralException;
  }

  bootstrap_stream.close();
  if (!pd::ReadBootstrapFile(bootstrap_file, bootstrap_contacts)) {
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

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
