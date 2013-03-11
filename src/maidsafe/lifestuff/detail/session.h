/***************************************************************************************************
 *  Copyright 2013 MaidSafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use.  The use of this code is governed by the licence file licence.txt found in the root of    *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit         *
 *  written permission of the board of directors of MaidSafe.net.                                  *
 **************************************************************************************************/

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_SESSION_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_SESSION_H_

#include <mutex>
#include <map>
#include <string>
#include <set>
#include <utility>
#include <vector>

#include "maidsafe/common/utils.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/lifestuff.h"

namespace maidsafe {
namespace lifestuff {

namespace test { class SessionTest; }

class Session {
 public:
  typedef passport::Passport Passport;
  typedef std::pair<std::string, uint16_t> Endpoint;

  Session();
  ~Session();

  Passport& passport();

  NonEmptyString session_name() const;
  Identity unique_user_id() const;
  std::string root_parent_id() const;
  int64_t max_space() const;
  int64_t used_space() const;

  void set_session_name();
  void set_unique_user_id(const Identity& unique_user_id);
  void set_root_parent_id(const std::string& root_parent_id);
  void set_max_space(const int64_t& max_space);
  void set_used_space(const int64_t& used_space);

  void set_bootstrap_endpoints(const std::vector<Endpoint>& bootstrap_endpoints);
  std::vector<Endpoint> bootstrap_endpoints() const;

  void Parse(const NonEmptyString& serialised_session);
  NonEmptyString Serialise();

  friend class test::SessionTest;

 private:
  Session &operator=(const Session&);
  Session(const Session&);

  struct UserDetails {
    UserDetails()
      : unique_user_id(),
        root_parent_id(),
        max_space(1073741824),
        used_space(0),
        session_name(EncodeToHex(crypto::SHA1Hash(RandomAlphaNumericString(20)))) {}
    Identity unique_user_id;
    std::string root_parent_id;
    int64_t max_space;
    int64_t used_space;
    NonEmptyString session_name;
  };

  Passport passport_;
  std::vector<Endpoint> bootstrap_endpoints_;
  UserDetails user_details_;
};

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_SESSION_H_






// /*
// * ============================================================================
// *
// * Copyright [2009] maidsafe.net limited
// *
// * Description:  setting/getting session info
// * Version:      1.0
// * Created:      2009-01-28-16.56.20
// * Revision:     none
// * Compiler:     gcc
// * Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
// * Company:      maidsafe.net limited
// *
// * The following source code is property of maidsafe.net limited and is not
// * meant for external use.  The use of this code is governed by the license
// * file LICENSE.TXT found in the root of this directory and also on
// * www.maidsafe.net.
// *
// * You are not free to copy, amend or otherwise use this source code without
// * the explicit written permission of the board of directors of maidsafe.net.
// *
// * ============================================================================
// */
//
// #ifndef MAIDSAFE_LIFESTUFF_DETAIL_SESSION_H_
// #define MAIDSAFE_LIFESTUFF_DETAIL_SESSION_H_
//
// #include <mutex>
// #include <map>
// #include <string>
// #include <set>
// #include <utility>
// #include <vector>
//
// #include "maidsafe/passport/passport.h"
//
// #include "maidsafe/lifestuff/detail/contacts.h"
// #include "maidsafe/lifestuff/lifestuff.h"
//
// namespace maidsafe {
//
// namespace lifestuff {
//
// namespace test { class SessionTest; }
//
// enum SessionAccessLevel { kNoAccess, kFullAccess, kMustDie };
//
// struct UserDetails {
//  UserDetails()
//      : defconlevel(DefConLevels::kDefCon3),
//        keyword(),
//        pin(),
//        password(),
//        session_name(),
//        unique_user_id(),
//        root_parent_id(),
//        max_space(1073741824),
//        used_space(0),
//        serialised_data_atlas(),
//        changed(false),
//        has_drive_data(false),
//        session_access_level(kNoAccess) {}
//  DefConLevels defconlevel;
//  NonEmptyString keyword, pin, password, session_name;
//  Identity unique_user_id;
//  std::string root_parent_id;
//  int64_t max_space, used_space;
//  NonEmptyString serialised_data_atlas;
//  bool changed, has_drive_data;
//  SessionAccessLevel session_access_level;
// };
//
// struct SocialInfo {
//  SocialInfo(const NonEmptyString& picture_datamap,
//             const Identity& the_card_address);
//  NonEmptyString profile_picture_datamap;
//  Identity card_address;
// };
//
// typedef std::shared_ptr<ContactsHandler> ContactsHandlerPtr;
// typedef std::shared_ptr<SocialInfo> SocialInfoPtr;
//
// typedef std::pair<std::shared_ptr<std::mutex>, SocialInfoPtr> SocialInfoDetail;
//
// struct PublicIdDetails {
//  PublicIdDetails();
//  explicit PublicIdDetails(const Identity& card_address);
//  PublicIdDetails& operator=(const PublicIdDetails& other);
//  PublicIdDetails(const PublicIdDetails& other);
//
//  SocialInfoPtr social_info;
//  ContactsHandlerPtr contacts_handler;
//  std::shared_ptr<std::mutex> social_info_mutex;
// };
//
// class Session {
// public:
//  Session();
//  ~Session();
//  void Reset();
//
//  void set_bootstrap_endpoints(
//      const std::vector<std::pair<std::string, uint16_t> >& bootstrap_endpoints);
//  std::vector<std::pair<std::string, uint16_t> > bootstrap_endpoints() const;
//  passport::Passport& passport();
//
//  int AddPublicId(const NonEmptyString& public_id, const Identity& pointer_to_lifestuff_card);
//  int DeletePublicId(const NonEmptyString& public_id);
//  bool OwnPublicId(const NonEmptyString& public_id);
//  const ContactsHandlerPtr contacts_handler(const NonEmptyString& public_id);
//  const SocialInfoDetail social_info(const NonEmptyString& public_id);
//
//  DefConLevels def_con_level() const;
//  NonEmptyString keyword() const;
//  NonEmptyString pin() const;
//  NonEmptyString password() const;
//  NonEmptyString session_name() const;
//  Identity unique_user_id() const;
//  std::string root_parent_id() const;
//  int64_t max_space() const;
//  int64_t used_space() const;
//  NonEmptyString serialised_data_atlas() const;
//  bool changed() const;
//  bool has_drive_data() const;
//  SessionAccessLevel session_access_level() const;
//
//  void set_def_con_level(DefConLevels defconlevel);
//  void set_keyword(const NonEmptyString& keyword);
//  void set_pin(const NonEmptyString& pin);
//  void set_password(const NonEmptyString& password);
//  void set_session_name();
//  void clear_session_name();
//  void set_unique_user_id(const Identity& unique_user_id);
//  void set_root_parent_id(const std::string& root_parent_id);
//  void set_max_space(const int64_t& max_space);
//  void set_used_space(const int64_t& used_space);
//  void set_serialised_data_atlas(const NonEmptyString& serialised_data_atlas);
//  void set_changed(bool state);
//  void set_session_access_level(SessionAccessLevel session_access_level);
//
//  int ParseDataAtlas(const NonEmptyString& serialised_session);
//  NonEmptyString SerialiseDataAtlas();
//
//  std::vector<NonEmptyString> PublicIdentities() const;
//
//  friend class test::SessionTest;
//
// private:
//  Session &operator=(const Session&);
//  Session(const Session&);
//
//  std::vector<std::pair<std::string, uint16_t> > bootstrap_endpoints_;
//  passport::Passport passport_;
//  UserDetails user_details_;
//  mutable std::mutex user_details_mutex_;
//  std::map<NonEmptyString, PublicIdDetails> public_id_details_;
//  std::mutex public_id_details_mutex_;
//
//  void set_has_drive_data(bool has_drive_data);
//  bool CreateTestPackets(bool with_public_ids, std::vector<NonEmptyString>& public_ids);
// };
//
// }  // namespace lifestuff
//
// }  // namespace maidsafe
//
// #endif  // MAIDSAFE_LIFESTUFF_DETAIL_SESSION_H_
