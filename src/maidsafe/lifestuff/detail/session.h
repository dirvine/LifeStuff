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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_SESSION_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_SESSION_H_

#include <map>
#include <string>
#include <set>
#include <vector>

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

namespace maidsafe {

namespace lifestuff {

namespace test {
class AuthenticationTest;
class MessageHandlerTest;
class PublicIdTest;
class SessionTest;
class UserCredentialsTest;
}  // namespace test

class Authentication;
class ContactsHandler;
class MessageHandler;
class PublicId;
class UserCredentials;
class UserStorage;
struct UserDetails;

typedef std::shared_ptr<ContactsHandler> ContactsHandlerPtr;
typedef std::map<std::string, ContactsHandlerPtr> ContactHandlerMap;
typedef std::map<std::string, std::set<std::string>> PublicIdContactMap;

class Session {
 public:
  Session();
  ~Session();
  bool Reset();

  ContactHandlerMap& contact_handler_map();
  PublicIdContactMap GetAllContacts(ContactStatus status);

  DefConLevels def_con_level() const;
  std::string username() const;
  std::string pin() const;
  std::string password() const;
  std::string session_name() const;
  std::string unique_user_id() const;
  std::string root_parent_id() const;
  std::string profile_picture_data_map(const std::string &public_id) const;

  void set_def_con_level(DefConLevels defconlevel);
  bool set_session_name();
  void clear_session_name();
  void set_unique_user_id(const std::string &unique_user_id);
  void set_root_parent_id(const std::string &root_parent_id);
  std::string encrypted_tmid() const;
  std::string encrypted_stmid() const;
  std::string serialised_data_atlas() const;
  std::string uc_serialised_data_atlas() const;
  std::string surrogate_serialised_data_atlas() const;
  bool logging_out() const;
  bool logged_in() const;
  bool set_profile_picture_data_map(
      const std::string &public_id,
      const std::string &profile_picture_data_map);
  void set_encrypted_tmid(const std::string &encrypted_tmid);
  void set_encrypted_stmid(const std::string &encrypted_stmid);
  void set_serialised_data_atlas(const std::string &serialised_data_atlas);
  void set_uc_serialised_data_atlas(
      const std::string &uc_serialised_data_atlas);
  void set_surrogate_serialised_data_atlas(
      const std::string &surrogate_serialised_data_atlas);
  void set_logging_out(const bool &logging_out);
  void set_logged_in(const bool &logged_in);

  int ParseDataAtlas(const std::string &serialised_data_atlas);
  int SerialiseDataAtlas(std::string *serialised_data_atlas);
  std::shared_ptr<asymm::Keys> GetPmidKeys();

//   friend void GetKeyring(const std::string&,
//                          std::shared_ptr<Session>,
//                          asymm::Keys*);
//   friend void GetPublicKey(const std::string&,
//                            std::shared_ptr<Session>,
//                            asymm::PublicKey*);
//   friend void GetPrivateKey(const std::string&,
//                             std::shared_ptr<Session>,
//                             asymm::PrivateKey*);
  friend class Authentication;
  friend class MessageHandler;
  friend class PublicId;
  friend class UserCredentials;
  friend class UserStorage;
  friend class test::AuthenticationTest;
  friend class test::MessageHandlerTest;
  friend class test::PublicIdTest;
  friend class test::SessionTest;
  friend class test::UserCredentialsTest;

 private:
  Session &operator=(const Session&);
  Session(const Session&);
  void set_username(const std::string &username);
  void set_pin(const std::string &pin);
  void set_password(const std::string &password);

  int ParseKeyChain(const std::string &serialised_keyring,
                    const std::string &serialised_selectables);
  void SerialiseKeyChain(std::string *serialised_keyring,
                         std::string *serialised_selectables);

  bool CreateTestPackets(bool with_public_ids);
  std::vector<std::string> GetPublicIdentities();

  std::shared_ptr<UserDetails> user_details_;
  std::shared_ptr<passport::Passport> passport_;
  ContactHandlerMap contact_handler_map_;
  std::map<std::string, std::string> profile_picture_map_;
  std::string encrypted_tmid_, encrypted_stmid_, serialised_data_atlas_,
      uc_serialised_data_atlas_, surrogate_serialised_data_atlas_;
  bool logging_out_, logged_in_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_SESSION_H_
