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

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/lifestuff.h"

namespace maidsafe {

namespace lifestuff {

namespace test { class SessionTest; }

class ContactsHandler;
struct UserDetails;

typedef std::shared_ptr<ContactsHandler> ContactsHandlerPtr;
typedef std::map<std::string, ContactsHandlerPtr> ContactHandlerMap;
typedef std::map<std::string, std::set<std::string>> PublicIdContactMap;

class Session {
 public:
  Session();
  ~Session();
  bool Reset();

  passport::Passport& passport();

  ContactHandlerMap& contact_handler_map();
  PublicIdContactMap GetAllContacts(ContactStatus status);

  DefConLevels def_con_level() const;
  std::string keyword() const;
  std::string pin() const;
  std::string password() const;
  std::string session_name() const;
  std::string unique_user_id() const;
  std::string root_parent_id() const;
  int64_t max_space() const;
  int64_t used_space() const;
  std::string profile_picture_data_map(const std::string &public_id) const;

  void set_def_con_level(DefConLevels defconlevel);
  void set_keyword(const std::string &keyword);
  void set_pin(const std::string &pin);
  void set_password(const std::string &password);
  bool set_session_name();
  void clear_session_name();
  void set_unique_user_id(const std::string &unique_user_id);
  void set_root_parent_id(const std::string &root_parent_id);
  void set_max_space(const int64_t &max_space);
  void set_used_space(const int64_t &used_space);
  std::string encrypted_tmid() const;
  std::string encrypted_stmid() const;
  std::string serialised_data_atlas() const;
  std::string uc_serialised_data_atlas() const;
  std::string surrogate_serialised_data_atlas() const;
  bool logging_out() const;
  bool logged_in() const;
  bool set_profile_picture_data_map(const std::string &public_id,
                                    const std::string &profile_picture_data_map);
  void set_encrypted_tmid(const std::string &encrypted_tmid);
  void set_encrypted_stmid(const std::string &encrypted_stmid);
  void set_serialised_data_atlas(const std::string &serialised_data_atlas);
  void set_uc_serialised_data_atlas(const std::string &uc_serialised_data_atlas);
  void set_surrogate_serialised_data_atlas(const std::string &surrogate_serialised_data_atlas);
  void set_logging_out(const bool &logging_out);
  void set_logged_in(const bool &logged_in);

  int ParseDataAtlas(const std::string &serialised_data_atlas);
  int SerialiseDataAtlas(std::string *serialised_data_atlas);
  std::shared_ptr<asymm::Keys> GetPmidKeys();

  friend class test::SessionTest;

 private:
  Session &operator=(const Session&);
  Session(const Session&);

  int ParseKeyChain(const std::string &serialised_keyring,
                    const std::string &serialised_selectables);
  void SerialiseKeyChain(std::string *serialised_keyring, std::string *serialised_selectables);

  bool CreateTestPackets(bool with_public_ids);
  std::vector<std::string> GetPublicIdentities();

  std::shared_ptr<UserDetails> user_details_;
  passport::Passport passport_;
  ContactHandlerMap contact_handler_map_;
  std::map<std::string, std::string> profile_picture_map_;
  std::string encrypted_tmid_,
              encrypted_stmid_,
              serialised_data_atlas_,
              uc_serialised_data_atlas_,
              surrogate_serialised_data_atlas_;
  bool logging_out_, logged_in_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_SESSION_H_
