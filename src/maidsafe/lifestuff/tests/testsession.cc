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
  ASSERT_EQ(size_t(0), ss_->authorised_users().size());
  ASSERT_EQ(size_t(0), ss_->maid_authorised_users().size());
  ASSERT_EQ(0, ss_->mounted());
  ASSERT_EQ('\0', ss_->win_drive());
  std::vector<mi_contact> list;
  ASSERT_EQ(0, ss_->GetContactList(&list));
  ASSERT_EQ(size_t(0), list.size());
  std::list<PrivateShare> ps_list;
  ASSERT_EQ(0, ss_->GetFullShareList(kAlpha, kAll, &ps_list));
  ASSERT_EQ(size_t(0), ps_list.size());

  // Modify session
  ss_->set_da_modified(true);
  ss_->set_def_con_level(kDefCon1);
  ss_->set_username("aaa");
  ss_->set_pin("bbb");
  ss_->set_password("ccc");
  ASSERT_TRUE(ss_->set_session_name(false));
  ss_->set_root_db_key("ddd");
  std::set<std::string> non_empty_set;
  non_empty_set.insert("eee");
  ss_->set_authorised_users(non_empty_set);
  non_empty_set.insert("fff");
  ss_->set_maid_authorised_users(non_empty_set);
  ss_->set_mounted(1);
  ss_->set_win_drive('N');
  ASSERT_EQ(0, ss_->AddContact("pub_name", "pub_key", "full_name",
                               "office_phone", "birthday", 'M', 18, 6, "city",
                               'C', 0, 0));
  std::vector<std::string> attributes;
  attributes.push_back("name");
  attributes.push_back("msid");
  attributes.push_back("msid_pub_key");
  attributes.push_back("msid_pri_key");
  std::list<ShareParticipants> participants;
  participants.push_back(ShareParticipants("id", "id_pub_key", 'A'));
  std::vector<boost::uint32_t> share_stats(2, 0);
  ASSERT_EQ(0, ss_->AddPrivateShare(attributes, share_stats, &participants));

  // Verify modifications
  ASSERT_TRUE(ss_->da_modified());
  ASSERT_EQ(kDefCon1, ss_->def_con_level());
  ASSERT_EQ("aaa", ss_->username());
  ASSERT_EQ("bbb", ss_->pin());
  ASSERT_EQ("ccc", ss_->password());
  ASSERT_EQ("", ss_->public_username());
  ASSERT_NE("", ss_->session_name());
  ASSERT_EQ("ddd", ss_->root_db_key());
  ASSERT_EQ(size_t(1), ss_->authorised_users().size());
  auto it(ss_->authorised_users().find("eee"));
  ASSERT_FALSE(ss_->authorised_users().end() == it);
  ASSERT_EQ(size_t(2), ss_->maid_authorised_users().size());
  it = ss_->maid_authorised_users().find("eee");
  ASSERT_FALSE(ss_->maid_authorised_users().end() == it);
  it = ss_->maid_authorised_users().find("fff");
  ASSERT_FALSE(ss_->maid_authorised_users().end() == it);
  ASSERT_EQ(1, ss_->mounted());
  ASSERT_EQ('N', ss_->win_drive());
  ASSERT_EQ(0, ss_->GetContactList(&list));
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
  ASSERT_EQ(0, ss_->GetFullShareList(kAlpha, kAll, &ps_list));
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
  ASSERT_EQ(size_t(0), ss_->authorised_users().size());
  ASSERT_EQ(size_t(0), ss_->maid_authorised_users().size());
  ASSERT_EQ(0, ss_->mounted());
  ASSERT_EQ('\0', ss_->win_drive());
  ASSERT_EQ(0, ss_->GetContactList(&list));
  ASSERT_EQ(size_t(0), list.size());
  ASSERT_EQ(0, ss_->GetFullShareList(kAlpha, kAll, &ps_list));
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

TEST_F(SessionTest, BEH_SessionContactsIO) {
  // Add contacts to the session
  for (int n = 0; n < 10; n++) {
    ASSERT_EQ(0, ss_->AddContact("pub_name_" + IntToString(n),
                                 "pub_key_" + IntToString(n),
                                 "full_name_" + IntToString(n),
                                 "office_phone_" + IntToString(n),
                                 "birthday_" + IntToString(n),
                                 'M', n, n,
                                 "city_" + IntToString(n),
                                 'C', 0, 0));
  }

  // Check contacts are in session
  std::vector<mi_contact> list;
  ASSERT_EQ(0, ss_->GetContactList(&list));
  ASSERT_EQ(size_t(10), list.size());

  // Move contacts to a DA
  DataAtlas da;
  for (unsigned int a = 0; a < list.size(); ++a) {
    PublicContact *pc = da.add_contacts();
    pc->set_pub_name(list[a].pub_name_);
    pc->set_pub_key(list[a].pub_key_);
    pc->set_full_name(list[a].full_name_);
    pc->set_office_phone(list[a].office_phone_);
    pc->set_birthday(list[a].birthday_);
    std::string g(1, list[a].gender_);
    pc->set_gender(g);
    pc->set_language(list[a].language_);
    pc->set_country(list[a].country_);
    pc->set_city(list[a].city_);
    std::string c(1, list[a].confirmed_);
    pc->set_confirmed(c);
    pc->set_rank(list[a].rank_);
    pc->set_last_contact(list[a].last_contact_);
  }

  // Clear the values from the session
  ASSERT_TRUE(ss_->ResetSession());

  // Load the values from the DA
  std::list<PublicContact> contacts;
  for (int y = 0; y < da.contacts_size(); ++y) {
    PublicContact pc = da.contacts(y);
    contacts.push_back(pc);
  }
  ASSERT_EQ(0, ss_->LoadContacts(&contacts));

  // Get values from session again
  std::vector<mi_contact> second_list;
  ASSERT_EQ(0, ss_->GetContactList(&second_list));
  ASSERT_EQ(size_t(10), second_list.size());

  // Check the initial values against the seconda values
  for (unsigned int e = 0; e < second_list.size(); ++e) {
    ASSERT_EQ(list[e].pub_name_, second_list[e].pub_name_);
    ASSERT_EQ(list[e].pub_key_, second_list[e].pub_key_);
    ASSERT_EQ(list[e].full_name_, second_list[e].full_name_);
    ASSERT_EQ(list[e].office_phone_, second_list[e].office_phone_);
    ASSERT_EQ(list[e].birthday_, second_list[e].birthday_);
    ASSERT_EQ(list[e].gender_, second_list[e].gender_);
    ASSERT_EQ(list[e].language_, second_list[e].language_);
    ASSERT_EQ(list[e].country_, second_list[e].country_);
    ASSERT_EQ(list[e].city_, second_list[e].city_);
    ASSERT_EQ(list[e].confirmed_, second_list[e].confirmed_);
    ASSERT_EQ(list[e].rank_, second_list[e].rank_);
    ASSERT_EQ(list[e].last_contact_, second_list[e].last_contact_);
  }
}

TEST_F(SessionTest, BEH_SessionPrivateSharesIO) {
  // Add shares to the session
  std::vector<boost::uint32_t> share_stats(2, 2);
  for (int n = 0; n < 10; n++) {
    // Attributes
    std::vector<std::string> atts;
    atts.push_back("NAME_" + IntToString(n));
    atts.push_back("MSID_" + IntToString(n));
    atts.push_back("MSID_PUB_KEY_" + IntToString(n));
    atts.push_back("MSID_PRI_KEY_" + IntToString(n));

    // Participants
    std::list<ShareParticipants> cp;
    for (int a = 0; a <= n; a++) {
      ShareParticipants sps;
      sps.id = "PUB_NAME_" + IntToString(n) + "_" + IntToString(a);
      sps.public_key = "PUB_NAME_PUB_KEY_" + IntToString(n) +
                       "_" + IntToString(a);
      sps.role = 'C';
      cp.push_back(sps);
    }

    // Add private share
    ASSERT_EQ(0, ss_->AddPrivateShare(atts, share_stats, &cp)) <<
              "Failed to add share";
  }

  // Check shares are in session
  std::list<PrivateShare> ps_list;
  ASSERT_EQ(0, ss_->GetFullShareList(kAlpha, kAll, &ps_list));
  ASSERT_EQ(size_t(10), ps_list.size());
  std::list<PrivateShare> ps_list1 = ps_list;

  // Move contacts to a DA
  DataAtlas da;
  while (!ps_list.empty()) {
    PrivateShare this_ps = ps_list.front();
    Share *sh = da.add_shares();
    sh->set_name(this_ps.Name());
    sh->set_msid(this_ps.Msid());
    sh->set_msid_pub_key(this_ps.MsidPubKey());
    sh->set_msid_pri_key(this_ps.MsidPriKey());
    sh->set_rank(this_ps.Rank());
    sh->set_last_view(this_ps.LastViewed());
    std::list<ShareParticipants> this_sp_list = this_ps.Participants();
    while (!this_sp_list.empty()) {
      ShareParticipants this_sp = this_sp_list.front();
      ShareParticipant *shp = sh->add_participants();
      shp->set_public_name(this_sp.id);
      shp->set_public_name_pub_key(this_sp.public_key);
      std::string role(1, this_sp.role);
      shp->set_role(role);
      this_sp_list.pop_front();
    }
    ps_list.pop_front();
  }

  // Clear the values from the session
  ASSERT_TRUE(ss_->ResetSession());

  // Load the values from the DA
  std::list<Share> shares;
  for (int n = 0; n < da.shares_size(); ++n) {
    Share sh = da.shares(n);
    shares.push_back(sh);
  }
  ss_->LoadShares(&shares);

  // Get values from session again
  std::list<PrivateShare> ps_list2;
  ASSERT_EQ(0, ss_->GetFullShareList(kAlpha, kAll, &ps_list2));
  ASSERT_EQ(size_t(10), ps_list2.size());

  // Check the initial values against the seconda values
  while (!ps_list1.empty()) {
    PrivateShare ps1 = ps_list1.front();
    PrivateShare ps2 = ps_list2.front();
    ASSERT_EQ(ps1.Name(), ps2.Name());
    ASSERT_EQ(ps1.Msid(), ps2.Msid());
    ASSERT_EQ(ps1.MsidPubKey(), ps2.MsidPubKey());
    ASSERT_EQ(ps1.MsidPriKey(), ps2.MsidPriKey());
    ASSERT_EQ(ps1.Rank(), ps2.Rank());
    ASSERT_EQ(ps1.LastViewed(), ps2.LastViewed());
    std::list<ShareParticipants> sp_list1 = ps1.Participants();
    std::list<ShareParticipants> sp_list2 = ps2.Participants();
    ASSERT_EQ(sp_list1.size(), sp_list2.size());
    while (!sp_list1.empty()) {
      ShareParticipants this_sp1 = sp_list1.front();
      ShareParticipants this_sp2 = sp_list2.front();
      ASSERT_EQ(this_sp1.id, this_sp2.id);
      ASSERT_EQ(this_sp1.public_key, this_sp2.public_key);
      ASSERT_EQ(this_sp1.role, this_sp2.role);
      sp_list1.pop_front();
      sp_list2.pop_front();
    }
    ps_list1.pop_front();
    ps_list2.pop_front();
  }
}

TEST_F(SessionTest, BEH_PubUsernameList) {
  for (int n = 0; n < 10; n++) {
    ASSERT_EQ(0, ss_->AddContact("pub_name_" + IntToString(n),
              "pub_key_" + IntToString(n),
              "full_name_" + IntToString(n),
              "office_phone_" + IntToString(n),
              "birthday_" + IntToString(n),
              'M', n, n, "city_" + IntToString(n), 'C', 0, 0));
  }
  std::vector<std::string> publicusernames;
  ASSERT_EQ(0, ss_->GetPublicUsernameList(&publicusernames));
  ASSERT_EQ(size_t(10), publicusernames.size());
  for (int a = 0; a < static_cast<int>(publicusernames.size()); ++a)
    ASSERT_EQ("pub_name_" + IntToString(a), publicusernames[a]);
}

TEST_F(SessionTest, BEH_ContactPublicKey) {
  for (int n = 0; n < 10; n++) {
    ASSERT_EQ(0, ss_->AddContact("pub_name_" + IntToString(n),
              "pub_key_" + IntToString(n),
              "full_name_" + IntToString(n),
              "office_phone_" + IntToString(n),
              "birthday_" + IntToString(n),
              'M', n, n, "city_" + IntToString(n), 'C', 0, 0));
  }
  for (int a = 0; a < 10; ++a)
    ASSERT_EQ("pub_key_" + IntToString(a),
              ss_->GetContactPublicKey("pub_name_" + IntToString(a)));
}

TEST_F(SessionTest, BEH_Conversations) {
  std::list<std::string> conv;
  ASSERT_EQ(0, ss_->ConversationList(&conv));
  ASSERT_EQ(size_t(0), conv.size());
  conv.push_back("a");
  ASSERT_EQ(size_t(1), conv.size());
  ASSERT_EQ(0, ss_->ConversationList(&conv));
  ASSERT_EQ(size_t(0), conv.size());
  ASSERT_EQ(kNonExistentConversation, ss_->ConversationExits("a"));
  ASSERT_EQ(kNonExistentConversation, ss_->RemoveConversation("a"));

  ASSERT_EQ(0, ss_->AddConversation("a"));
  ASSERT_EQ(0, ss_->ConversationExits("a"));
  ASSERT_EQ(0, ss_->ConversationList(&conv));
  ASSERT_EQ(size_t(1), conv.size());
  ASSERT_EQ("a", conv.front());
  ASSERT_EQ(kExistingConversation, ss_->AddConversation("a"));
  ASSERT_EQ(0, ss_->RemoveConversation("a"));
  ASSERT_EQ(kNonExistentConversation, ss_->ConversationExits("a"));
  ASSERT_EQ(kNonExistentConversation, ss_->RemoveConversation("a"));
  ASSERT_EQ(0, ss_->ConversationList(&conv));
  ASSERT_EQ(size_t(0), conv.size());

  for (int n = 0; n < 10; ++n)
    ASSERT_EQ(0, ss_->AddConversation(IntToString(n)));
  ASSERT_EQ(0, ss_->ConversationList(&conv));
  ASSERT_EQ(size_t(10), conv.size());

  std::string remove = IntToString(RandomUint32() % 10);
  ASSERT_EQ(0, ss_->RemoveConversation(remove));
  ASSERT_EQ(0, ss_->ConversationList(&conv));
  ASSERT_EQ(size_t(9), conv.size());
  std::list<std::string>::iterator it;
  for (it = conv.begin(); it != conv.end(); ++it) {
    int a = boost::lexical_cast<int>(*it);
    ASSERT_TRUE(a > -1 && a < 10);
    ASSERT_EQ(0, ss_->RemoveConversation(*it));
  }
  for (int y = 0; y < 10; ++y)
    ASSERT_EQ(kNonExistentConversation,
              ss_->ConversationExits(IntToString(y)));

  for (int e = 0; e < 10; ++e)
    ASSERT_EQ(0, ss_->AddConversation(IntToString(e)));
  ASSERT_EQ(0, ss_->ConversationList(&conv));
  ASSERT_EQ(size_t(10), conv.size());
  ss_->ClearConversations();
  for (int l = 0; l < 10; ++l)
    ASSERT_EQ(kNonExistentConversation,
              ss_->ConversationExits(IntToString(l)));
  ASSERT_EQ(0, ss_->ConversationList(&conv));
  ASSERT_EQ(size_t(0), conv.size());
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
