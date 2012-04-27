/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Unit tests for Session
* Version:      1.0
* Created:      2009-07-23
* Revision:     none
* Compiler:     gcc
* Author:       Team Maidsafe
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

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/data_atlas_pb.h"
#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/session.h"

namespace maidsafe {

namespace lifestuff {

namespace test {

class SessionTest : public testing::Test {
 public:
  SessionTest() : session_(new Session) {}

 protected:
  void SetUp() { session_->Reset(); }

  void SetUnamePinWord(const std::string &uname,
                       const std::string &pin,
                       const std::string &word) {
    session_->set_username(uname);
    session_->set_pin(pin);
    session_->set_password(word);
  }

  std::shared_ptr<Session> session_;

 private:
  explicit SessionTest(const SessionTest&);
  SessionTest &operator=(const SessionTest&);
};

TEST_F(SessionTest, BEH_SetsGetsAndReset) {
  // Check session is clean originally
  ASSERT_EQ(kDefCon3, session_->def_con_level());
  ASSERT_EQ("", session_->username());
  ASSERT_EQ("", session_->pin());
  ASSERT_EQ("", session_->password());
  ASSERT_EQ("", session_->session_name());
  ASSERT_EQ("", session_->unique_user_id());
  ASSERT_EQ("", session_->root_parent_id());
  ASSERT_EQ(size_t(0), session_->contact_handler_map().size());

  // Modify session
  session_->set_def_con_level(kDefCon1);
  SetUnamePinWord("aaa", "bbb", "ccc");
  ASSERT_TRUE(session_->set_session_name());
  session_->set_unique_user_id("ddd1");
  session_->set_root_parent_id("ddd2");
  auto result(session_->contact_handler_map().insert(std::make_pair(
                  "My pub name",
                  ContactsHandlerPtr(new ContactsHandler))));
  ASSERT_EQ(kSuccess,
            session_->contact_handler_map()["My pub name"]->AddContact(
                "pub_name",
                "mpid_name",
                "inbox_name",
                "profile_picture_data_map",
                asymm::PublicKey(),
                asymm::PublicKey(),
                kBlocked,
                0, 0));
  // Verify modifications
  ASSERT_EQ(kDefCon1, session_->def_con_level());
  ASSERT_EQ("aaa", session_->username());
  ASSERT_EQ("bbb", session_->pin());
  ASSERT_EQ("ccc", session_->password());
  ASSERT_NE("", session_->session_name());
  ASSERT_EQ("ddd1", session_->unique_user_id());
  ASSERT_EQ("ddd2", session_->root_parent_id());
  std::vector<Contact> list;
  session_->contact_handler_map()["My pub name"]->OrderedContacts(&list);
  ASSERT_EQ(size_t(1), list.size());
  ASSERT_EQ("pub_name", list[0].public_id);
  ASSERT_EQ("mpid_name", list[0].mpid_name);
  ASSERT_EQ("inbox_name", list[0].inbox_name);
  ASSERT_EQ("profile_picture_data_map", list[0].profile_picture_data_map);
  ASSERT_FALSE(asymm::ValidateKey(list[0].mpid_public_key));
  ASSERT_FALSE(asymm::ValidateKey(list[0].mmid_public_key));
  ASSERT_EQ(kBlocked, list[0].status);
  ASSERT_EQ(0, list[0].rank);
  ASSERT_NE(0, list[0].last_contact);

  // Resetting the session
  ASSERT_TRUE(session_->Reset());

  // Check session is clean again
  ASSERT_EQ(kDefCon3, session_->def_con_level());
  ASSERT_EQ("", session_->username());
  ASSERT_EQ("", session_->pin());
  ASSERT_EQ("", session_->password());
  ASSERT_EQ("", session_->session_name());
  ASSERT_EQ("", session_->unique_user_id());
  ASSERT_EQ("", session_->root_parent_id());
  ASSERT_EQ(size_t(0), session_->contact_handler_map().size());
}

TEST_F(SessionTest, BEH_SessionName) {
  // Check session is empty
  ASSERT_EQ("", session_->session_name());
  ASSERT_EQ("", session_->username());
  ASSERT_EQ("", session_->pin());

  // Check username and pin are needed
  ASSERT_FALSE(session_->set_session_name());
  ASSERT_EQ("", session_->session_name());

  std::string username(RandomAlphaNumericString(6));
  std::string pin("1234");
  std::string session_name = EncodeToHex(crypto::Hash<crypto::SHA1>(pin +
                                                                    username));

  // Set the session values
  SetUnamePinWord(username, pin, "ccc");
  ASSERT_TRUE(session_->set_session_name());

  // Check session name
  ASSERT_EQ(session_name, session_->session_name());

  // Reset value and check empty again
  session_->clear_session_name();
  ASSERT_EQ("", session_->session_name());
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
