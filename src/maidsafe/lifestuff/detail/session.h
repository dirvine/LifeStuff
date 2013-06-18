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
#include "maidsafe/passport/detail/secure_string.h"

#include "maidsafe/lifestuff/lifestuff.h"

namespace maidsafe {
namespace lifestuff {

namespace test { class SessionTest; }

typedef passport::detail::Keyword Keyword;
typedef passport::detail::Pin Pin;
typedef passport::detail::Password Password;

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
  boost::filesystem::path vault_path() const;
  int64_t max_space() const;
  int64_t used_space() const;
  bool initialised();
  const Keyword& keyword() const;
  const Pin& pin() const;
  const Password& password() const;

  void set_session_name();
  void set_unique_user_id(const Identity& unique_user_id);
  void set_root_parent_id(const std::string& root_parent_id);
  void set_vault_path(const boost::filesystem::path& vault_path);
  void set_max_space(const int64_t& max_space);
  void set_used_space(const int64_t& used_space);
  void set_initialised();
  void set_keyword(const Keyword& keyword);
  void set_pin(const Pin& pin);
  void set_password(const Password& password);
  void set_keyword_pin_password(const Keyword& keyword, const Pin& pin, const Password& password);

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
        vault_path(),
        max_space(1073741824),
        used_space(0),
        session_name(EncodeToHex(crypto::SHA1Hash(RandomAlphaNumericString(20)))) {}
    Identity unique_user_id;
    std::string root_parent_id;
    boost::filesystem::path vault_path;
    int64_t max_space;
    int64_t used_space;
    NonEmptyString session_name;
  };

  Passport passport_;
  std::vector<Endpoint> bootstrap_endpoints_;
  UserDetails user_details_;
  bool initialised_;
  std::unique_ptr<Keyword> keyword_;
  std::unique_ptr<Pin> pin_;
  std::unique_ptr<Password> password_;

  // probably need a modified bool here since used_space varies.
};

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_SESSION_H_
