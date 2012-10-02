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

#include <mutex>
#include <map>
#include <string>
#include <set>
#include <utility>
#include <vector>

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/lifestuff.h"

namespace maidsafe {

namespace lifestuff {

namespace test { class SessionTest; }

enum SessionAccessLevel { kNoAccess, kFullAccess, kMustDie };

struct UserDetails {
  UserDetails()
      : defconlevel(DefConLevels::kDefCon3),
        keyword(),
        pin(),
        password(),
        session_name(),
        unique_user_id(),
        root_parent_id(),
        max_space(1073741824),
        used_space(0),
        serialised_data_atlas(),
        changed(false),
        session_access_level(kNoAccess) {}
  DefConLevels defconlevel;
  std::string keyword, pin, password, session_name, unique_user_id, root_parent_id;
  int64_t max_space, used_space;
  std::string serialised_data_atlas;
  bool changed;
  SessionAccessLevel session_access_level;
};

struct ShareDetails {
  ShareDetails() : share_type(0) {}
  explicit ShareDetails(int type) : share_type(type) {}
  int share_type;
};

typedef std::map<std::string, ShareDetails> ShareInformation;
typedef std::vector<std::string> SocialInfo;

typedef std::shared_ptr<ContactsHandler> ContactsHandlerPtr;
typedef std::shared_ptr<ShareInformation> ShareInformationPtr;
typedef std::shared_ptr<SocialInfo> SocialInfoPtr;

typedef std::pair<std::shared_ptr<std::mutex>, ShareInformationPtr> ShareInformationDetail;
typedef std::pair<std::shared_ptr<std::mutex>, SocialInfoPtr> SocialInfoDetail;

struct PublicIdDetails {
  PublicIdDetails();
  explicit PublicIdDetails(const std::string& card_address);
  PublicIdDetails& operator=(const PublicIdDetails& other);
  PublicIdDetails(const PublicIdDetails& other);

  SocialInfoPtr social_info;
  ContactsHandlerPtr contacts_handler;
  ShareInformationPtr share_information;
  std::shared_ptr<std::mutex> social_info_mutex, share_information_mutex;
};

class Session {
 public:
  Session();
  ~Session();
  void Reset();

  passport::Passport& passport();

  int AddPublicId(const std::string& public_id, const std::string& pointer_to_lifestuff_card);
  int DeletePublicId(const std::string& public_id);
  bool OwnPublicId(const std::string& public_id);
  const ContactsHandlerPtr contacts_handler(const std::string& public_id);
  const ShareInformationDetail share_information(const std::string& public_id);
  const SocialInfoDetail social_info(const std::string& public_id);

  DefConLevels def_con_level() const;
  std::string keyword() const;
  std::string pin() const;
  std::string password() const;
  std::string session_name() const;
  std::string unique_user_id() const;
  std::string root_parent_id() const;
  int64_t max_space() const;
  int64_t used_space() const;
  std::string serialised_data_atlas() const;
  bool changed() const;
  SessionAccessLevel session_access_level() const;

  void set_def_con_level(DefConLevels defconlevel);
  void set_keyword(const std::string& keyword);
  void set_pin(const std::string& pin);
  void set_password(const std::string& password);
  bool set_session_name();
  void clear_session_name();
  void set_unique_user_id(const std::string& unique_user_id);
  void set_root_parent_id(const std::string& root_parent_id);
  void set_max_space(const int64_t& max_space);
  void set_used_space(const int64_t& used_space);
  void set_serialised_data_atlas(const std::string& serialised_data_atlas);
  void set_changed(bool state);
  void set_session_access_level(SessionAccessLevel session_access_level);

  int ParseDataAtlas(const std::string& serialised_session);
  int SerialiseDataAtlas(std::string* serialised_session);

  std::vector<std::string> PublicIdentities() const;

  friend class test::SessionTest;

 private:
  Session &operator=(const Session&);
  Session(const Session&);

  passport::Passport passport_;
  UserDetails user_details_;
  mutable std::mutex user_details_mutex_;
  std::map<std::string, PublicIdDetails> public_id_details_;
  std::mutex public_id_details_mutex_;

  bool CreateTestPackets(bool with_public_ids);
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_SESSION_H_
