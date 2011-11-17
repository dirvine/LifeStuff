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

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif

#include "boost/utility.hpp"
#include "boost/thread/once.hpp"
#include "boost/scoped_ptr.hpp"
#include "boost/asio/io_service.hpp"

#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/private_shares.h"
#include "maidsafe/lifestuff/maidsafe.h"

namespace maidsafe {

namespace lifestuff {

namespace test {
class SessionTest;
class ClientControllerTest;
class LocalStoreManagerTest;
class SessionTest_BEH_SetsGetsAndResetSession_Test;
class SessionTest_BEH_SessionName_Test;
class AuthenticationTest_FUNC_RepeatedSaveSessionBlocking_Test;
class AuthenticationTest_FUNC_RepeatedSaveSessionCallbacks_Test;
class AuthenticationTest_FUNC_ChangeUsername_Test;
class AuthenticationTest_FUNC_ChangePin_Test;
class AuthenticationTest_FUNC_ChangePassword_Test;
class AuthenticationTest_FUNC_CreatePublicName_Test;
class LocalStoreManagerTest_BEH_DeleteSystemPacketNotOwner_Test;
class LocalStoreManagerTest_BEH_UpdateSystemPacket_Test;
class LocalStoreManagerTest_BEH_UpdateSystemPacketNotOwner_Test;
}  // namespace test

class Authentication;
class ClientUtils;
class PublicContact;
class Share;

struct UserDetails {
  UserDetails()
      : defconlevel(kDefCon3),
        da_modified(false),
        username(),
        pin(),
        password(),
        session_name(),
        public_username(),
        root_db_key(),
        mounted(0),
        win_drive('\0'),
        connection_status(0) {}
  DefConLevels defconlevel;
  bool da_modified;
  std::string username, pin, password, session_name, public_username;
  std::string root_db_key;
  int mounted;
  char win_drive;
  int connection_status;
};

class Session {
 public:
  Session();
  ~Session();
  bool ResetSession();

  std::shared_ptr<ContactsHandler> contacts_handler() const;
  std::shared_ptr<PrivateShareHandler> private_share_handler() const;

  DefConLevels def_con_level() const;
  bool da_modified() const;
  std::string username() const;
  std::string pin() const;
  std::string password() const;
  std::string public_username() const;
  std::string session_name() const;
  std::string root_db_key() const;
  int mounted() const;
  char win_drive() const;
  int connection_status() const;

  void set_def_con_level(DefConLevels defconlevel);
  void set_da_modified(bool da_modified);
  bool set_session_name(bool clear);
  void set_root_db_key(const std::string &root_db_key);
  void set_mounted(int mounted);
  void set_win_drive(char win_drive);
  void set_connection_status(int status);

  friend std::string GetPublicKey(const std::string&, std::shared_ptr<Session>);
  friend class Authentication;
//  friend class ClientUtils;
  friend class test::SessionTest;
  friend class test::ClientControllerTest;
  friend class test::LocalStoreManagerTest;
  friend class test::SessionTest_BEH_SetsGetsAndResetSession_Test;
  friend class test::SessionTest_BEH_SessionName_Test;
  friend class
      test::AuthenticationTest_FUNC_RepeatedSaveSessionBlocking_Test;
  friend class
      test::AuthenticationTest_FUNC_RepeatedSaveSessionCallbacks_Test;
  friend class test::AuthenticationTest_FUNC_ChangeUsername_Test;
  friend class test::AuthenticationTest_FUNC_ChangePin_Test;
  friend class test::AuthenticationTest_FUNC_ChangePassword_Test;
  friend class test::AuthenticationTest_FUNC_CreatePublicName_Test;
  friend class
      test::LocalStoreManagerTest_BEH_DeleteSystemPacketNotOwner_Test;
  friend class test::LocalStoreManagerTest_BEH_UpdateSystemPacket_Test;
  friend class
      test::LocalStoreManagerTest_BEH_UpdateSystemPacketNotOwner_Test;

 private:
  Session &operator=(const Session&);
  Session(const Session&);
  // Following three mutators should only be called by Authentication once
  // associated packets are confirmed as stored.
  void set_username(const std::string &username);
  void set_pin(const std::string &pin);
  void set_password(const std::string &password);
  // Creates signature packets.
  bool CreateTestPackets();

  UserDetails user_details_;
  std::shared_ptr<passport::Passport> passport_;
  std::shared_ptr<ContactsHandler> contacts_handler_;
  std::shared_ptr<PrivateShareHandler> private_share_handler_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_SESSION_H_
