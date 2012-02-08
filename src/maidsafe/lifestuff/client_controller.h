/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Singleton class which controls all maidsafe client operations
* Version:      1.0
* Created:      2009-01-28-11.09.12
* Revision:     none
* Compiler:     gcc
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

#ifndef MAIDSAFE_LIFESTUFF_CLIENT_CONTROLLER_H_
#define MAIDSAFE_LIFESTUFF_CLIENT_CONTROLLER_H_

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "boost/function.hpp"
#include "boost/signals2.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/filesystem/path.hpp"
#include "boost/thread/thread.hpp"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/return_codes.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 200
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif

namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace dht { class Contact; }
namespace pd { class RemoteChunkStore; }
class ChunkStore;

namespace lifestuff {

namespace test { class ClientControllerTest; }
class Authentication;
class Session;
class YeOldeSignalToCallbackConverter;

class ClientController {
 public:
  explicit ClientController(boost::asio::io_service &service,  // NOLINT (Dan)
                            std::shared_ptr<Session> session);

  ~ClientController();
  void Init(bool local, const fs::path &chunk_store_dir);
  bool initialised() const { return initialised_; }

  // User credential operations
  int CheckUserExists(const std::string &username,
                      const std::string &pin);
  bool ValidateUser(const std::string &password);
  bool CreateUser(const std::string &username,
                  const std::string &pin,
                  const std::string &password);
  bool Logout();
  int SaveSession();
  bool ChangeUsername(const std::string &new_username);
  bool ChangePin(const std::string &new_pin);
  bool ChangePassword(const std::string &new_password);
  bool LeaveMaidsafeNetwork();

  std::string SessionName();
  std::string Username();
  std::string Pin();
  std::string Password();

  std::shared_ptr<pd::RemoteChunkStore> remote_chunk_store();
  std::shared_ptr<YeOldeSignalToCallbackConverter> converter();

  friend class test::ClientControllerTest;

 private:
  ClientController &operator=(const ClientController&);
  ClientController(const ClientController&);

  int ParseDa();
  int SerialiseDa();

  std::shared_ptr<Session> session_;
  std::shared_ptr<pd::RemoteChunkStore> remote_chunk_store_;
  std::shared_ptr<Authentication> auth_;
  std::string ser_da_, surrogate_ser_da_;
  bool initialised_;
  bool logging_out_;
  bool logged_in_;

  boost::asio::io_service &service_;
  std::shared_ptr<YeOldeSignalToCallbackConverter> converter_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_CLIENT_CONTROLLER_H_
