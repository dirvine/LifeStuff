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

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4244 4127)
#endif
#include "maidsafe/lifestuff/data_atlas.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/lifestuff/session.h"

namespace maidsafe {

namespace lifestuff {

namespace test {

class SessionTest : public testing::Test {
 public:
  SessionTest() : ss_(new Session) {}

 protected:
  void SetUp() {
    ss_->ResetSession();
  }

  std::shared_ptr<Session> ss_;

 private:
  explicit SessionTest(const SessionTest&);
  SessionTest &operator=(const SessionTest&);
};

TEST_F(SessionTest, BEH_SetsGetsAndResetSession) {
  // Check session is clean originally
  ASSERT_FALSE(ss_->da_modified());
  ASSERT_EQ(kDefCon3, ss_->def_con_level());
  ASSERT_EQ("", ss_->username());
  ASSERT_EQ("", ss_->pin());
  ASSERT_EQ("", ss_->password());
  ASSERT_EQ("", ss_->public_username());
  ASSERT_EQ("", ss_->session_name());
  ASSERT_EQ("", ss_->root_db_key());
  ASSERT_EQ(0, ss_->mounted());
  ASSERT_EQ('\0', ss_->win_drive());
  std::vector<mi_contact> list;
  ASSERT_EQ(0, ss_->contacts_handler()->GetContactList(&list));
  ASSERT_EQ(size_t(0), list.size());
  std::list<PrivateShare> ps_list;
  ASSERT_EQ(0, ss_->private_share_handler()->GetFullShareList(
                  kAlpha, kAll, &ps_list));
  ASSERT_EQ(size_t(0), ps_list.size());

  // Modify session
  ss_->set_da_modified(true);
  ss_->set_def_con_level(kDefCon1);
  ss_->set_username("aaa");
  ss_->set_pin("bbb");
  ss_->set_password("ccc");
  ASSERT_TRUE(ss_->set_session_name(false));
  ss_->set_root_db_key("ddd");
  ss_->set_mounted(1);
  ss_->set_win_drive('N');
  ASSERT_EQ(0, ss_->contacts_handler()->AddContact("pub_name", "pub_key",
                               "full_name", "office_phone", "birthday", 'M',
                               18, 6, "city", 'C', 0, 0));
  std::vector<std::string> attributes;
  attributes.push_back("name");
  attributes.push_back("msid");
  attributes.push_back("msid_pub_key");
  attributes.push_back("msid_pri_key");
  std::list<ShareParticipants> participants;
  participants.push_back(ShareParticipants("id", "id_pub_key", 'A'));
  std::vector<boost::uint32_t> share_stats(2, 0);
  ASSERT_EQ(0, ss_->private_share_handler()->AddPrivateShare(
                  attributes, share_stats, &participants));

  // Verify modifications
  ASSERT_TRUE(ss_->da_modified());
  ASSERT_EQ(kDefCon1, ss_->def_con_level());
  ASSERT_EQ("aaa", ss_->username());
  ASSERT_EQ("bbb", ss_->pin());
  ASSERT_EQ("ccc", ss_->password());
  ASSERT_EQ("", ss_->public_username());
  ASSERT_NE("", ss_->session_name());
  ASSERT_EQ("ddd", ss_->root_db_key());
  ASSERT_EQ(1, ss_->mounted());
  ASSERT_EQ('N', ss_->win_drive());
  ASSERT_EQ(0, ss_->contacts_handler()->GetContactList(&list));
  ASSERT_EQ(size_t(1), list.size());
  ASSERT_EQ("pub_name", list[0].pub_name_);
  ASSERT_EQ("pub_key", list[0].pub_key_);
  ASSERT_EQ("full_name", list[0].full_name_);
  ASSERT_EQ("office_phone", list[0].office_phone_);
  ASSERT_EQ("birthday", list[0].birthday_);
  ASSERT_EQ('M', list[0].gender_);
  ASSERT_EQ(18, list[0].language_);
  ASSERT_EQ(6, list[0].country_);
  ASSERT_EQ("city", list[0].city_);
  ASSERT_EQ('C', list[0].confirmed_);
  ASSERT_EQ(0, list[0].rank_);
  ASSERT_NE(0, list[0].last_contact_);
  ASSERT_EQ(0, ss_->private_share_handler()->GetFullShareList(
                  kAlpha, kAll, &ps_list));
  ASSERT_EQ(size_t(1), ps_list.size());
  ASSERT_EQ("name", ps_list.front().Name());
  ASSERT_EQ("msid", ps_list.front().Msid());
  ASSERT_EQ("msid_pub_key", ps_list.front().MsidPubKey());
  ASSERT_EQ("msid_pri_key", ps_list.front().MsidPriKey());
  std::list<ShareParticipants> sp_list = ps_list.front().Participants();
  ASSERT_EQ(size_t(1), sp_list.size());
  ASSERT_EQ("id", sp_list.front().id);
  ASSERT_EQ("id_pub_key", sp_list.front().public_key);
  ASSERT_EQ('A', sp_list.front().role);

  // Resetting the session
  ASSERT_TRUE(ss_->ResetSession());

  // Check session is clean again
  ASSERT_FALSE(ss_->da_modified());
  ASSERT_EQ(kDefCon3, ss_->def_con_level());
  ASSERT_EQ("", ss_->username());
  ASSERT_EQ("", ss_->pin());
  ASSERT_EQ("", ss_->password());
  ASSERT_EQ("", ss_->public_username());
  ASSERT_EQ("", ss_->session_name());
  ASSERT_EQ("", ss_->root_db_key());
  ASSERT_EQ(0, ss_->mounted());
  ASSERT_EQ('\0', ss_->win_drive());
  ASSERT_EQ(0, ss_->contacts_handler()->GetContactList(&list));
  ASSERT_EQ(size_t(0), list.size());
  ASSERT_EQ(0, ss_->private_share_handler()->GetFullShareList(
                  kAlpha, kAll, &ps_list));
  ASSERT_EQ(size_t(0), ps_list.size());
}

TEST_F(SessionTest, BEH_SessionName) {
  // Check session is empty
  ASSERT_EQ("", ss_->session_name());
  ASSERT_EQ("", ss_->username());
  ASSERT_EQ("", ss_->pin());

  // Check username and pin are needed
  ASSERT_FALSE(ss_->set_session_name(false));
  ASSERT_EQ("", ss_->session_name());

  std::string username("user1");
  std::string pin("1234");
  std::string session_name = EncodeToHex(crypto::Hash<crypto::SHA1>(pin +
                                                                    username));

  // Set the session values
  ss_->set_username(username);
  ss_->set_pin(pin);
  ASSERT_TRUE(ss_->set_session_name(false));

  // Check session name
  ASSERT_EQ(session_name, ss_->session_name());

  // Reset value and check empty again
  ss_->set_session_name(true);
  ASSERT_EQ("", ss_->session_name());
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
