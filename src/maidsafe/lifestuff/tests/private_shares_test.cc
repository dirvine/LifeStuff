/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Handles user's list of maidsafe private shares
* Version:      1.0
* Created:      2009-01-28-23.19.56
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh)
*               alias "The Hutch"
*               fraser.hutchison@maidsafe.net
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

#include "boost/filesystem.hpp"
#include "boost/thread.hpp"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/lifestuff/private_shares.h"

namespace maidsafe {

namespace lifestuff {

namespace test {

class PrivateSharesTest : public testing::Test {
 protected:
  PrivateSharesTest()
      : psh_(NULL),
        ps_(NULL),
        name(),
        participants(),
        attributes() {}

  virtual void SetUp() {
    psh_ = new PrivateShareHandler();
    std::string share_name("My First Share");
    attributes.push_back(share_name);
    attributes.push_back(RandomString(64));
    attributes.push_back(RandomString(512));
    attributes.push_back(RandomString(512));
    ShareParticipants r;
    r.id = "Dan";
    r.public_key = RandomString(512);
    r.role = 'R';
    participants.push_back(r);
    r.id = "The Hutch";
    r.public_key = RandomString(512);
    r.role = 'A';
    participants.push_back(r);
    ps_ = new PrivateShare(attributes, participants);
  }

  virtual void TearDown() {
    delete psh_;
    delete ps_;
  }

  PrivateShareHandler *psh_;
  PrivateShare *ps_;
  std::string name;
  std::list<ShareParticipants> participants;
  std::vector<std::string> attributes;

 private:
  PrivateSharesTest(const PrivateSharesTest&);
  PrivateSharesTest& operator=(const PrivateSharesTest&);
};

TEST_F(PrivateSharesTest, BEH_Create_ListShares) {
  // Test share list to be empty
  std::list<private_share> share_list;
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kAll));
  ASSERT_EQ(size_t(0), share_list.size());

  // Test full share list to be empty
  std::list<PrivateShare> full_share_list;
  ASSERT_EQ(0, psh_->GetFullShareList(kAlpha, kAll, &full_share_list));
  ASSERT_EQ(size_t(0), full_share_list.size());

  // Test lower bound of field index
  PrivateShare ps;
  ASSERT_EQ(-2014, psh_->GetShareInfo("aaa", -1, &ps));
  ASSERT_EQ("", ps.Name());
  ASSERT_EQ("", ps.Msid());
  ASSERT_EQ("", ps.MsidPubKey());
  ASSERT_EQ("", ps.MsidPriKey());
  ASSERT_EQ(size_t(0), ps.Participants().size());

  // Test upper bound of field index
  ASSERT_EQ(-2014, psh_->GetShareInfo("aaa", 2, &ps));
  ASSERT_EQ("", ps.Name());
  ASSERT_EQ("", ps.Msid());
  ASSERT_EQ("", ps.MsidPubKey());
  ASSERT_EQ("", ps.MsidPriKey());
  ASSERT_EQ(size_t(0), ps.Participants().size());

  // Test wrong share name
  ASSERT_EQ(-2014, psh_->GetShareInfo("aaa", 0, &ps));
  ASSERT_EQ("", ps.Name());
  ASSERT_EQ("", ps.Msid());
  ASSERT_EQ("", ps.MsidPubKey());
  ASSERT_EQ("", ps.MsidPriKey());
  ASSERT_EQ(size_t(0), ps.Participants().size());

  // Test wrong share msid
  ASSERT_EQ(-2014, psh_->GetShareInfo("aaa", 1, &ps));
  ASSERT_EQ("", ps.Name());
  ASSERT_EQ("", ps.Msid());
  ASSERT_EQ("", ps.MsidPubKey());
  ASSERT_EQ("", ps.MsidPriKey());
  ASSERT_EQ(size_t(0), ps.Participants().size());

  // Test wrong index for field in share participant lookup
  std::list<share_participant> sp_list;
  ASSERT_EQ(-2015, psh_->GetParticipantsList("aaa", -1, &sp_list));
  ASSERT_EQ(size_t(0), sp_list.size());
  ASSERT_EQ(-2015, psh_->GetParticipantsList("aaa", 2, &sp_list));
  ASSERT_EQ(size_t(0), sp_list.size());

  // Test wrong share name for participant list
  ASSERT_EQ(-2015, psh_->GetParticipantsList("aaa", 0, &sp_list));
  ASSERT_EQ(size_t(0), sp_list.size());

  // Test wrong share msid for participant list
  ASSERT_EQ(-2015, psh_->GetParticipantsList("aaa", 1, &sp_list));
  ASSERT_EQ(size_t(0), sp_list.size());
}

TEST_F(PrivateSharesTest, BEH_AddShare) {
  // Test share list to be empty
  std::list<private_share> share_list;
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kAll));
  ASSERT_EQ(size_t(0), share_list.size());

  // Copy the list for comparison
  std::list<ShareParticipants> cp = participants;

  // Add private share
  std::vector<boost::uint32_t> share_stats(2, 0);
  ASSERT_EQ(0, psh_->AddPrivateShare(attributes, share_stats, &cp));

  // Check with GetShareInfo
  PrivateShare by_name;
  ASSERT_EQ(0, psh_->GetShareInfo(attributes[0], 0, &by_name));
  ASSERT_EQ(attributes[0], by_name.Name());
  ASSERT_EQ(attributes[1], by_name.Msid());
  ASSERT_EQ(attributes[2], by_name.MsidPubKey());
  ASSERT_EQ(attributes[3], by_name.MsidPriKey());
  ASSERT_EQ(boost::uint32_t(0), by_name.Rank());
  ASSERT_EQ(boost::uint32_t(0), by_name.LastViewed());
  ASSERT_EQ(participants.size(), by_name.Participants().size());

  PrivateShare by_msid;
  ASSERT_EQ(0, psh_->GetShareInfo(attributes[1], 1, &by_msid));
  ASSERT_EQ(attributes[0], by_msid.Name());
  ASSERT_EQ(attributes[1], by_msid.Msid());
  ASSERT_EQ(attributes[2], by_msid.MsidPubKey());
  ASSERT_EQ(attributes[3], by_msid.MsidPriKey());
  ASSERT_EQ(boost::uint32_t(0), by_name.Rank());
  ASSERT_EQ(boost::uint32_t(0), by_name.LastViewed());
  ASSERT_EQ(participants.size(), by_msid.Participants().size());

  // Check with GetShareList
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kAll));
  ASSERT_EQ(size_t(1), share_list.size());
  ASSERT_EQ(attributes[0], share_list.front().name_);
  ASSERT_EQ(attributes[1], share_list.front().msid_);
  ASSERT_EQ(attributes[2], share_list.front().msid_pub_key_);
  ASSERT_EQ(attributes[3], share_list.front().msid_priv_key_);
  ASSERT_EQ(boost::uint32_t(0), share_list.front().rank_);
  ASSERT_EQ(boost::uint32_t(0), share_list.front().last_view_);

  // Check Participants with share name
  std::list<share_participant> sp_list;
  ASSERT_EQ(0, psh_->GetParticipantsList(attributes[0], 0, &sp_list));
  ASSERT_EQ(size_t(2), participants.size());
  ASSERT_EQ(participants.size(), sp_list.size());
  share_participant sp1 = sp_list.front();
  sp_list.pop_front();
  share_participant sp2 = sp_list.front();
  sp_list.pop_front();
  ASSERT_EQ(size_t(0), sp_list.size());

  for (auto it = participants.begin(); it != participants.end(); it++) {
    ASSERT_TRUE((*it).id == sp1.public_name_ || (*it).id == sp2.public_name_);
    ASSERT_TRUE((*it).public_key == sp1.public_key_ ||
                (*it).public_key == sp2.public_key_);
    ASSERT_TRUE((*it).role == sp1.role_ || (*it).role == sp2.role_);
  }

  // Check Participants with share msid
  ASSERT_EQ(0, psh_->GetParticipantsList(attributes[1], 1, &sp_list));
  ASSERT_EQ(size_t(2), participants.size());
  ASSERT_EQ(participants.size(), sp_list.size());
  sp1 = sp_list.front();
  sp_list.pop_front();
  sp2 = sp_list.front();
  sp_list.pop_front();
  ASSERT_EQ(size_t(0), sp_list.size());

  for (auto it = participants.begin(); it != participants.end(); it++) {
    ASSERT_TRUE((*it).id == sp1.public_name_ || (*it).id == sp2.public_name_);
    ASSERT_TRUE((*it).public_key == sp1.public_key_ ||
                (*it).public_key == sp2.public_key_);
    ASSERT_TRUE((*it).role == sp1.role_ || (*it).role == sp2.role_);
  }

  cp = participants;

  // Add same private share again
  ASSERT_EQ(-2010, psh_->AddPrivateShare(attributes, share_stats, &cp));
  // Check with GetShareList
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kAll));
  ASSERT_EQ(size_t(1), share_list.size());
}

TEST_F(PrivateSharesTest, BEH_AddMultipleShares) {
  // Test share list to be empty
  std::list<private_share> share_list;
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kAll));
  ASSERT_EQ(size_t(0), share_list.size());

  // Copy the list for comparison
  std::list<ShareParticipants> cp;

  std::vector<boost::uint32_t> share_stats(2, 0);
  for (int n = 0; n < 10; ++n) {
    // Attributes
    std::vector<std::string> atts;
    atts.push_back("NAME_" + IntToString(n));
    atts.push_back("MSID_" + IntToString(n));
    atts.push_back("MSID_PUB_KEY_" + IntToString(n));
    atts.push_back("MSID_PRI_KEY_" + IntToString(n));

    // Participants
    cp.clear();
    for (int a = 0; a <= n; a++) {
      ShareParticipants sps;
      sps.id = "PUB_NAME_" + IntToString(n) + "_" + IntToString(a);
      sps.public_key = "PUB_NAME_PUB_KEY_" + IntToString(n) +
                       "_" + IntToString(a);
      sps.role = 'C';
      cp.push_back(sps);
    }

    // Add private share
    ASSERT_EQ(0, psh_->AddPrivateShare(atts, share_stats, &cp));
  }

  // Test full share list
  std::list<PrivateShare> full_share_list;
  ASSERT_EQ(0, psh_->GetFullShareList(kAlpha, kAll, &full_share_list));
  ASSERT_EQ(size_t(10), full_share_list.size());
  int y = 0;
  while (!full_share_list.empty()) {
    int e = 0;
    PrivateShare ps = full_share_list.front();
    full_share_list.pop_front();
    ASSERT_EQ("NAME_" + IntToString(y), ps.Name());
    ASSERT_EQ("MSID_" + IntToString(y), ps.Msid());
    ASSERT_EQ("MSID_PUB_KEY_" + IntToString(y), ps.MsidPubKey());
    ASSERT_EQ("MSID_PRI_KEY_" + IntToString(y), ps.MsidPriKey());
    std::list<ShareParticipants> sps = ps.Participants();
    ASSERT_EQ(size_t(y + 1), sps.size());
    while (!sps.empty()) {
      ShareParticipants sp = sps.front();
      sps.pop_front();
      ASSERT_EQ("PUB_NAME_" + IntToString(y) + "_" + IntToString(e), sp.id);
      ASSERT_EQ("PUB_NAME_PUB_KEY_" + IntToString(y) + "_" + IntToString(e),
                sp.public_key);
      ASSERT_EQ('C', sp.role);
      e++;
    }
    y++;
  }

  unsigned int l = RandomUint32() % 10;
  PrivateShare by_name;
  ASSERT_EQ(0, psh_->GetShareInfo("NAME_" + IntToString(l), 0, &by_name));
  ASSERT_EQ("NAME_" + IntToString(l), by_name.Name());
  ASSERT_EQ("MSID_" + IntToString(l), by_name.Msid());
  ASSERT_EQ("MSID_PUB_KEY_" + IntToString(l), by_name.MsidPubKey());
  ASSERT_EQ("MSID_PRI_KEY_" + IntToString(l), by_name.MsidPriKey());
  ASSERT_EQ(size_t(l + 1), by_name.Participants().size());
  std::list<ShareParticipants> sps = by_name.Participants();
  int i = 0;
  while (!sps.empty()) {
    ShareParticipants sp = sps.front();
    sps.pop_front();
    ASSERT_EQ("PUB_NAME_" + IntToString(l) + "_" + IntToString(i), sp.id);
    ASSERT_EQ("PUB_NAME_PUB_KEY_" + IntToString(l) + "_" + IntToString(i),
              sp.public_key);
    ASSERT_EQ('C', sp.role);
    i++;
  }
}

TEST_F(PrivateSharesTest, BEH_DeleteShare) {
  // Test share list to be empty
  std::list<private_share> share_list;
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kAll));
  ASSERT_EQ(size_t(0), share_list.size());

  // Copy the list for comparison
  std::list<ShareParticipants> cp;

  std::vector<boost::uint32_t> share_stats(2, 0);
  for (int n = 0; n < 10; ++n) {
    // Attributes
    std::vector<std::string> atts;
    atts.push_back("NAME_" + IntToString(n));
    atts.push_back("MSID_" + IntToString(n));
    atts.push_back("MSID_PUB_KEY_" + IntToString(n));
    atts.push_back("MSID_PRI_KEY_" + IntToString(n));

    // Participants
    cp.clear();
    for (int a = 0; a <= n; a++) {
      ShareParticipants sps;
      sps.id = "PUB_NAME_" + IntToString(n) + "_" + IntToString(a);
      sps.public_key = "PUB_NAME_PUB_KEY_" + IntToString(n) +
                       "_" + IntToString(a);
      sps.role = 'C';
      cp.push_back(sps);
    }

    // Add private share
    ASSERT_EQ(0, psh_->AddPrivateShare(atts, share_stats, &cp));
  }

  // Test full share list
  std::list<PrivateShare> full_share_list;
  ASSERT_EQ(0, psh_->GetFullShareList(kAlpha, kAll, &full_share_list));
  ASSERT_EQ(size_t(10), full_share_list.size());

  // Delete random share by name
  unsigned int l = RandomUint32() % 10;
  ASSERT_EQ(0, psh_->DeletePrivateShare("NAME_" + IntToString(l), 0));

  // Full share list
  ASSERT_EQ(0, psh_->GetFullShareList(kAlpha, kAll, &full_share_list));
  ASSERT_EQ(size_t(9), full_share_list.size());

  PrivateShare by_name, by_msid;
  std::list<share_participant> sp_list;
  // Find by share name
  ASSERT_EQ(-2014, psh_->GetShareInfo("NAME_" + IntToString(l), 0, &by_name));
  // Find by share msid
  ASSERT_EQ(-2014, psh_->GetShareInfo("MSID_" + IntToString(l), 1, &by_msid));
  // Find the participants of the share
  ASSERT_EQ(-2015, psh_->GetParticipantsList("MSID_" + IntToString(l), 1,
                                             &sp_list));
  ASSERT_EQ(size_t(0), sp_list.size());

  unsigned int e = l;
  while (e == l)
    e = RandomUint32() % 10;

  // Delete random share by msid
  ASSERT_EQ(0, psh_->DeletePrivateShare("MSID_" + IntToString(e), 1));

  // Full share list
  ASSERT_EQ(0, psh_->GetFullShareList(kAlpha, kAll, &full_share_list));
  ASSERT_EQ(size_t(8), full_share_list.size());

  // Find by share name
  ASSERT_EQ(-2014, psh_->GetShareInfo("NAME_" + IntToString(e), 0, &by_name));
  // Find by share msid
  ASSERT_EQ(-2014, psh_->GetShareInfo("MSID_" + IntToString(e), 1, &by_msid));
  // Find the participants of the share
  ASSERT_EQ(-2015, psh_->GetParticipantsList("MSID_" + IntToString(e), 1,
                                             &sp_list));
}

TEST_F(PrivateSharesTest, BEH_AddContactToShare) {
  // Test share list to be empty
  std::list<private_share> share_list;
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kAll));
  ASSERT_EQ(size_t(0), share_list.size());

  // Copy the list for comparison
  std::list<ShareParticipants> cp = participants;

  // Add private share
  std::vector<boost::uint32_t> share_stats(2, 0);
  ASSERT_EQ(0, psh_->AddPrivateShare(attributes, share_stats, &cp));

  // Check with GetShareInfo by name
  PrivateShare by_name;
  ASSERT_EQ(0, psh_->GetShareInfo(attributes[0], 0, &by_name));

  // Check Participants with share msid
  std::list<share_participant> sp_list;
  ASSERT_EQ(0, psh_->GetParticipantsList(attributes[1], 1, &sp_list));
  ASSERT_EQ(size_t(2), participants.size());
  ASSERT_EQ(participants.size(), sp_list.size());

  // Add contact by msid
  std::list<ShareParticipants> sps;
  for (int a = 0; a < 3; a++) {
    ShareParticipants sp;
    sp.id = "PUB_NAME_" + IntToString(a);
    sp.public_key = "PUB_NAME_PUB_KEY_" + IntToString(a);
    sp.role = 'N';
    sps.push_back(sp);
  }
  ASSERT_EQ(0, psh_->AddContactsToPrivateShare(attributes[1], 1, &sps));

  // Get list by share name
  ASSERT_EQ(0, psh_->GetParticipantsList(attributes[0], 0, &sp_list));
  ASSERT_EQ(size_t(5), sp_list.size());

  // Add same contacts by msid
  sps.clear();
  for (int a = 0; a < 3; a++) {
    ShareParticipants sp;
    sp.id = "PUB_NAME_" + IntToString(a);
    sp.public_key = "PUB_NAME_PUB_KEY_" + IntToString(a);
    sp.role = 'N';
    sps.push_back(sp);
  }
  ASSERT_EQ(0, psh_->AddContactsToPrivateShare(attributes[1], 1, &sps));

  // Get list by share msid
  ASSERT_EQ(0, psh_->GetParticipantsList(attributes[1], 1, &sp_list));
  ASSERT_EQ(size_t(5), sp_list.size());

  // Add more contacts by name
  sps.clear();
  for (int a = 3; a < 7; a++) {
    ShareParticipants sp;
    sp.id = "PUB_NAME_" + IntToString(a);
    sp.public_key = "PUB_NAME_PUB_KEY_" + IntToString(a);
    sp.role = 'N';
    sps.push_back(sp);
  }
  ASSERT_EQ(0, psh_->AddContactsToPrivateShare(attributes[0], 0, &sps));

  // Get list by share name
  ASSERT_EQ(0, psh_->GetParticipantsList(attributes[0], 0, &sp_list));
  ASSERT_EQ(size_t(9), sp_list.size());

  int n = 0;
  while (!sp_list.empty()) {
    ASSERT_EQ(attributes[1], sp_list.front().msid_);
    if (sp_list.front().public_name_ != "Dan" &&
        sp_list.front().public_name_ != "The Hutch") {
      ASSERT_EQ("PUB_NAME_" + IntToString(n), sp_list.front().public_name_);
      ASSERT_EQ("PUB_NAME_PUB_KEY_" + IntToString(n),
                sp_list.front().public_key_);
      ASSERT_EQ('N', sp_list.front().role_);
      ++n;
    }
    sp_list.pop_front();
  }
}

TEST_F(PrivateSharesTest, BEH_DeleteContactFromShare) {
  // Test share list to be empty
  std::list<private_share> share_list;
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kAll));
  ASSERT_EQ(size_t(0), share_list.size());

  // Copy the list for comparison
  std::list<ShareParticipants> cp = participants;

  // Add private share
  std::vector<boost::uint32_t> share_stats(2, 0);
  ASSERT_EQ(0, psh_->AddPrivateShare(attributes, share_stats, &cp));

  // Check with GetShareInfo by name
  PrivateShare by_name;
  ASSERT_EQ(0, psh_->GetShareInfo(attributes[0], 0, &by_name));

  // Add contact by msid
  std::list<ShareParticipants> sps;
  for (int a = 0; a < 7; a++) {
    ShareParticipants sp;
    sp.id = "PUB_NAME_" + IntToString(a);
    sp.public_key = "PUB_NAME_PUB_KEY_" + IntToString(a);
    sp.role = 'N';
    sps.push_back(sp);
  }
  ASSERT_EQ(0, psh_->AddContactsToPrivateShare(attributes[1], 1, &sps));

  // Get list by share name
  std::list<share_participant> sp_list;
  ASSERT_EQ(0, psh_->GetParticipantsList(attributes[0], 0, &sp_list));
  ASSERT_EQ(size_t(9), sp_list.size());

  // Delete random contact
  unsigned int l = RandomUint32() % 7;
  std::list<std::string> del_list;
  del_list.push_back("PUB_NAME_" + IntToString(l));
  ASSERT_EQ(0, psh_->DeleteContactsFromPrivateShare(attributes[1], 1,
                                                    &del_list));

  // Get list by share name
  ASSERT_EQ(0, psh_->GetParticipantsList(attributes[0], 0, &sp_list));
  ASSERT_EQ(size_t(8), sp_list.size());

  // Try to delete same participant from same share
  del_list.push_back("PUB_NAME_" + IntToString(l));
  ASSERT_EQ(-2013, psh_->DeleteContactsFromPrivateShare(attributes[1], 1,
                                                        &del_list));
  ASSERT_EQ(size_t(8), sp_list.size());

  // create new share details
  std::string msid1 = attributes[1];
  attributes.clear();
  attributes.push_back("Some share");
  attributes.push_back(RandomString(64));
  attributes.push_back(RandomString(512));
  attributes.push_back(RandomString(512));
  for (int a = 0; a < 7; a++) {
    ShareParticipants sp;
    sp.id = "PUB_NAME_" + IntToString(a);
    sp.public_key = "PUB_NAME_PUB_KEY_" + IntToString(a);
    sp.role = 'N';
    sps.push_back(sp);
  }

  // Add private share
  ASSERT_EQ(0, psh_->AddPrivateShare(attributes, share_stats, &sps));
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kAll));
  ASSERT_EQ(size_t(2), share_list.size()) <<
            "Share container empty after insertions.";

  // Get list by share name
  ASSERT_EQ(0, psh_->GetParticipantsList(attributes[0], 0, &sp_list));
  ASSERT_EQ(size_t(7), sp_list.size());

  // New random participant to delete
  unsigned int e = l;
  while (e == l)
    e = RandomUint32() % 7;
  del_list.push_back("PUB_NAME_" + IntToString(e));
  ASSERT_EQ(0, psh_->DeleteContactsFromPrivateShare(attributes[1], 1,
                                                    &del_list));

  // Get list by share name
  ASSERT_EQ(0, psh_->GetParticipantsList(attributes[0], 0, &sp_list));
  ASSERT_EQ(size_t(6), sp_list.size());

  // Check other share to see that the contact
  // wasn't deleted from the other share
  ASSERT_EQ(0, psh_->GetParticipantsList(msid1, 1, &sp_list));
  ASSERT_EQ(size_t(8), sp_list.size());
  bool found = false;
  while (!sp_list.empty() && !found) {
    if (sp_list.front().public_name_ == "PUB_NAME_" + IntToString(e))
      found = true;
    sp_list.pop_front();
  }
}

TEST_F(PrivateSharesTest, BEH_TouchShare) {
  // Test share list to be empty
  std::list<private_share> share_list;
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kAll));
  ASSERT_EQ(size_t(0), share_list.size());

  // Copy the list for comparison
  std::list<ShareParticipants> cp = participants;

  // Add private share
  std::vector<boost::uint32_t> share_stats(2, 0);
  ASSERT_EQ(0, psh_->AddPrivateShare(attributes, share_stats, &cp));
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kAll));
  ASSERT_EQ(size_t(1), share_list.size());

  ASSERT_EQ(0 , psh_->TouchShare(attributes[0], 0));
  PrivateShare by_name;
  ASSERT_EQ(0, psh_->GetShareInfo(attributes[0], 0, &by_name));
  ASSERT_EQ(attributes[0], by_name.Name());
  ASSERT_EQ(attributes[1], by_name.Msid());
  ASSERT_EQ(attributes[2], by_name.MsidPubKey());
  ASSERT_EQ(attributes[3], by_name.MsidPriKey());
  ASSERT_EQ(boost::uint32_t(1), by_name.Rank());
  ASSERT_NE(boost::uint32_t(0), by_name.LastViewed());
  boost::uint32_t last_view(by_name.LastViewed());

  Sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(0 , psh_->TouchShare(attributes[1], 1));
  ASSERT_EQ(0, psh_->GetShareInfo(attributes[0], 0, &by_name));
  ASSERT_EQ(attributes[0], by_name.Name());
  ASSERT_EQ(attributes[1], by_name.Msid());
  ASSERT_EQ(attributes[2], by_name.MsidPubKey());
  ASSERT_EQ(attributes[3], by_name.MsidPriKey());
  ASSERT_EQ(boost::uint32_t(2), by_name.Rank());
  ASSERT_LT(last_view, by_name.LastViewed());
}

TEST_F(PrivateSharesTest, BEH_ListByRank) {
  // Test share list to be empty
  std::list<private_share> share_list;
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kAll));
  ASSERT_EQ(size_t(0), share_list.size());

  // Copy the list for comparison
  std::list<ShareParticipants> cp;

  std::vector<boost::uint32_t> share_stats(2, 0);
  for (int n = 0; n < 10; ++n) {
    // Attributes
    std::vector<std::string> atts;
    atts.push_back("NAME_" + IntToString(n));
    atts.push_back("MSID_" + IntToString(n));
    atts.push_back("MSID_PUB_KEY_" + IntToString(n));
    atts.push_back("MSID_PRI_KEY_" + IntToString(n));

    // Add private share
    ASSERT_EQ(0, psh_->AddPrivateShare(atts, share_stats, &cp));

    int r = (RandomUint32() % 10) + 1;
    for (int n = 0; n < r; ++n) {
      ASSERT_EQ(0 , psh_->TouchShare(atts[0], 0));
    }
    Sleep(boost::posix_time::seconds(1));
  }

  ASSERT_EQ(0, psh_->GetShareList(&share_list, kRank, kAll));
  ASSERT_EQ(size_t(10), share_list.size());

  private_share past;
  while (!share_list.empty()) {
    ASSERT_LE(past.rank_, share_list.front().rank_);
    past = share_list.front();
    share_list.pop_front();
  }
}

TEST_F(PrivateSharesTest, BEH_ListByLastViewed) {
  // Test share list to be empty
  std::list<private_share> share_list;
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kAll));
  ASSERT_EQ(size_t(0), share_list.size());

  // Copy the list for comparison
  std::list<ShareParticipants> cp;

  std::vector<boost::uint32_t> share_stats(2, 0);
  for (int n = 0; n < 10; ++n) {
    // Attributes
    std::vector<std::string> atts;
    atts.push_back("NAME_" + IntToString(n));
    atts.push_back("MSID_" + IntToString(n));
    atts.push_back("MSID_PUB_KEY_" + IntToString(n));
    atts.push_back("MSID_PRI_KEY_" + IntToString(n));

    // Add private share
    ASSERT_EQ(0, psh_->AddPrivateShare(atts, share_stats, &cp));
  }
  for (int nn = 9; nn > -1; --nn) {
    ASSERT_EQ(0 , psh_->TouchShare("NAME_" + IntToString(nn), 0));
    Sleep(boost::posix_time::seconds(1));
  }

  ASSERT_EQ(0, psh_->GetShareList(&share_list, kLast, kAll));
  ASSERT_EQ(size_t(10), share_list.size());

  private_share past;
  while (!share_list.empty()) {
    ASSERT_LE(past.last_view_, share_list.front().last_view_);
    past = share_list.front();
    share_list.pop_front();
  }
}

TEST_F(PrivateSharesTest, BEH_DecideInclusion) {
  private_share ps;
  ps.name_ = "AA";
  ps.msid_ = "BB";
  ps.msid_pub_key_ = "CC";
  ps.msid_priv_key_ = "";
  std::list<private_share> share_list;

  psh_->DecideInclusion(ps, kRo, &share_list);
  ASSERT_EQ(size_t(1), share_list.size());
  ps.msid_priv_key_ = "DD";
  psh_->DecideInclusion(ps, kRo, &share_list);
  ASSERT_EQ(size_t(1), share_list.size());

  psh_->DecideInclusion(ps, kAdmin, &share_list);
  ASSERT_EQ(size_t(2), share_list.size());
  ps.msid_priv_key_ = "";
  psh_->DecideInclusion(ps, kAdmin, &share_list);
  ASSERT_EQ(size_t(2), share_list.size());

  psh_->DecideInclusion(ps, kAll, &share_list);
  ASSERT_EQ(size_t(3), share_list.size());
  ps.msid_priv_key_ = "DD";
  psh_->DecideInclusion(ps, kAll, &share_list);
  ASSERT_EQ(size_t(4), share_list.size());
}

TEST_F(PrivateSharesTest, BEH_ShareFilter) {
  // Test share list to be empty
  std::list<private_share> share_list;
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kAll));
  ASSERT_EQ(size_t(0), share_list.size());

  // Copy the list for comparison
  std::list<ShareParticipants> cp;

  std::vector<boost::uint32_t> share_stats(2, 0);
  for (int n = 0; n < 10; ++n) {
    // Attributes
    std::vector<std::string> atts;
    atts.push_back("NAME_" + IntToString(n));
    atts.push_back("MSID_" + IntToString(n));
    atts.push_back("MSID_PUB_KEY_" + IntToString(n));
    if (n > 4)
      atts.push_back("MSID_PRI_KEY_" + IntToString(n));
    else
      atts.push_back("");

    // Add private share
    ASSERT_EQ(0, psh_->AddPrivateShare(atts, share_stats, &cp));
  }
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kRo));
  ASSERT_EQ(size_t(5), share_list.size());
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kAdmin));
  ASSERT_EQ(size_t(5), share_list.size());
  ASSERT_EQ(0, psh_->GetShareList(&share_list, kAlpha, kAll));
  ASSERT_EQ(size_t(10), share_list.size());
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
