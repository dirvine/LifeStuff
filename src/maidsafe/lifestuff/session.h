/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  setting/getting session info
* Version:      1.0
* Created:      2009-01-28-16.56.20
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#ifndef MAIDSAFE_LIFESTUFF_SESSION_H_
#define MAIDSAFE_LIFESTUFF_SESSION_H_

#include <map>
#include <string>

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif

#include "boost/scoped_ptr.hpp"
#include "boost/utility.hpp"

#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/lifestuff.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 300
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif

namespace maidsafe {

namespace lifestuff {

namespace test {
class AuthenticationTest;
class ClientControllerTest;
class LocalStoreManagerTest;
class MessageHandlerTest;
class PublicIdTest;
class SessionTest;
}  // namespace test

class Authentication;
class ContactsHandler;
class ClientController;
class MessageHandler;
class PublicId;
class UserStorage;
struct UserDetails;

typedef std::shared_ptr<ContactsHandler> ContactsHandlerPtr;
typedef std::map<std::string, ContactsHandlerPtr> ContactHandlerMap;

class Session {
 public:
  Session();
  ~Session();
  bool ResetSession();

  ContactHandlerMap& contact_handler_map();

  DefConLevels def_con_level() const;
  std::string username() const;
  std::string pin() const;
  std::string password() const;
  std::string session_name() const;
  std::string unique_user_id() const;
  std::string root_parent_id() const;
  int mounted() const;
  char win_drive() const;

  void set_def_con_level(DefConLevels defconlevel);
  bool set_session_name(bool clear);
  void set_unique_user_id(const std::string &unique_user_id);
  void set_root_parent_id(const std::string &root_parent_id);
  void set_mounted(int mounted);
  void set_win_drive(char win_drive);
  int ParseKeyChain(const std::string &serialised_keyring,
                    const std::string &serialised_selectables);
  void SerialiseKeyChain(std::string *serialised_keyring,
                         std::string *serialised_selectables);

  friend void GetKeyring(const std::string&,
                         std::shared_ptr<Session>,
                         asymm::Keys*);
  friend void GetPublicKey(const std::string&,
                           std::shared_ptr<Session>,
                           asymm::PublicKey*);
  friend void GetPrivateKey(const std::string&,
                            std::shared_ptr<Session>,
                            asymm::PrivateKey*);
  friend class Authentication;
  friend class ClientController;
  friend class MessageHandler;
  friend class PublicId;
  friend class UserStorage;
  friend class test::AuthenticationTest;
  friend class test::ClientControllerTest;
  friend class test::LocalStoreManagerTest;
  friend class test::MessageHandlerTest;
  friend class test::PublicIdTest;
  friend class test::SessionTest;

 private:
  Session &operator=(const Session&);
  Session(const Session&);
  void set_username(const std::string &username);
  void set_pin(const std::string &pin);
  void set_password(const std::string &password);
  bool CreateTestPackets();

  std::shared_ptr<UserDetails> user_details_;
  std::shared_ptr<passport::Passport> passport_;
  ContactHandlerMap contact_handler_map_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_SESSION_H_
