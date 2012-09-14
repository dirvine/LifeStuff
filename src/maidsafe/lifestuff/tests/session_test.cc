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

#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace maidsafe {

namespace lifestuff {

namespace test {

class SessionTest : public testing::Test {
 public:
  SessionTest() : session_() {}

 protected:
  Session session_;

  void SetUp() { session_.Reset(); }

  void SetUsernamePinPassword(const std::string& keyword,
                              const std::string& pin,
                              const std::string& password) {
    session_.set_keyword(keyword);
    session_.set_pin(pin);
    session_.set_password(password);
  }

  void CreateTestSession(bool with_public_ids) {
    ASSERT_TRUE(session_.CreateTestPackets(with_public_ids));
    session_.set_unique_user_id(RandomString(64));
    session_.set_root_parent_id(RandomString(64));
    std::vector<std::string> public_ids(session_.PublicIdentities());
    std::for_each(public_ids.begin(),
                  public_ids.end(),
                  [this] (const std::string& pub_id) {
                      const ContactsHandlerPtr ch(this->session_.contacts_handler(pub_id));
                      const ShareInformationDetail si(this->session_.share_information(pub_id));
                      for (int n(0); n < 5; ++n) {
                        Contact c(RandomAlphaNumericString(5),
                                  "",
                                  "inbox_name_in",
                                  kBlankProfilePicture,
                                  RandomString(64),
                                  asymm::PublicKey(),
                                  asymm::PublicKey(),
                                  kConfirmed);
                        ch->AddContact(c);

                        // Shares
                        si.second->insert(std::make_pair("share_" + IntToString(n),
                                                         ShareDetails(n)));
                      }
                  });
  }

  bool EqualShareInformationContainers(const ShareInformationContainer& lhs,
                                       const ShareInformationContainer& rhs) {
    return lhs.share_name() == rhs.share_name() && lhs.share_type() == rhs.share_type();
  }

  bool EqualPublicContacts(const PublicContact& lhs, const PublicContact& rhs) {
    // required
    if (lhs.public_id() != rhs.public_id())
      return false;
    if (lhs.inbox_name() != rhs.inbox_name())
      return false;
    if (lhs.status() != rhs.status())
      return false;
    if (lhs.rank() != rhs.rank())
      return false;
    if (lhs.last_contact() != rhs.last_contact())
      return false;
    if (lhs.profile_picture_data_map() != rhs.profile_picture_data_map())
      return false;
    // optionals
    bool left(lhs.has_mpid_name()), right(rhs.has_mpid_name());
    if ((left && !right) || (!left && right))
      return false;
    if (left && right) {
      if (lhs.mpid_name() != rhs.mpid_name())
        return false;
    }
    left = lhs.has_mpid_public_key();
    right = rhs.has_mpid_public_key();
    if ((left && !right) || (!left && right))
      return false;
    if (left && right) {
      if (lhs.mpid_public_key() != rhs.mpid_public_key())
        return false;
    }
    left = lhs.has_inbox_public_key();
    right = rhs.has_inbox_public_key();
    if ((left && !right) || (!left && right))
      return false;
    if (left && right) {
      if (lhs.inbox_public_key() != rhs.inbox_public_key())
        return false;
    }
    left = lhs.has_pointer_to_info();
    right = rhs.has_pointer_to_info();
    if ((left && !right) || (!left && right))
      return false;
    if (left && right) {
      if (lhs.pointer_to_info() != rhs.pointer_to_info())
        return false;
    }
    return true;
  }

  bool EqualPublicIdentities(const PublicIdentity& lhs, const PublicIdentity& rhs) {
    if (lhs.public_id() != rhs.public_id())
      return false;
    if (lhs.profile_picture_data_map() != rhs.profile_picture_data_map())
      return false;
    if (lhs.pointer_to_info() != rhs.pointer_to_info())
      return false;
    if (lhs.contacts_size() != rhs.contacts_size())
      return false;
    for (int n(0); n < lhs.contacts_size(); ++n) {
      if (!EqualPublicContacts(lhs.contacts(n), rhs.contacts(n)))
        return false;
    }
    for (int n(0); n < lhs.shares_size(); ++n) {
      if (!EqualShareInformationContainers(lhs.shares(n), rhs.shares(n)))
        return false;
    }
    return true;
  }

  bool EquivalentDataAtlases(const DataAtlas& lhs, const DataAtlas& rhs) {
    // Drive data
    if (lhs.drive_data().root_parent_id() != rhs.drive_data().root_parent_id() ||
        lhs.drive_data().unique_user_id() != rhs.drive_data().unique_user_id()) {
      return false;
    }

    // Passport data
    if (lhs.passport_data().serialised_keyring() != rhs.passport_data().serialised_keyring()) {
      return false;
    }

    // Public Id data
    if (lhs.public_ids_size() != rhs.public_ids_size()) {
      return false;
    }
    for (int n(0); n < lhs.public_ids_size(); ++n) {
      if (!EqualPublicIdentities(lhs.public_ids(n), rhs.public_ids(n)))
        return false;
    }

    return true;
  }

  bool EqualShareInformations(const ShareInformationPtr lhs, const ShareInformationPtr rhs) {
    if (lhs->size() != rhs->size())
      return false;
    for (auto lhs_it(lhs->begin()); lhs_it != lhs->end(); ++lhs_it) {
      auto rhs_it(rhs->find(lhs_it->first));
      if (rhs_it == rhs->end())
        return false;
      if (lhs_it->second.share_type != rhs_it->second.share_type)
        return false;
    }

    return true;
  }

  bool EqualContactHandlers(const ContactsHandlerPtr lhs, const ContactsHandlerPtr rhs) {
    std::vector<Contact> lhs_contacts, rhs_contacts;
    lhs->OrderedContacts(&lhs_contacts, kAlphabetical, kConfirmed);
    rhs->OrderedContacts(&rhs_contacts, kAlphabetical, kConfirmed);
    if (lhs_contacts.size() != rhs_contacts.size())
      return false;
    for (size_t n(0); n < lhs_contacts.size(); ++n) {
      if (!lhs_contacts.at(n).Equals(rhs_contacts.at(n)))
        return false;
    }

    return true;
  }

  bool EqualSessions(Session& lhs, Session& rhs) {
    if (lhs.def_con_level() != rhs.def_con_level())
      return false;
    if (lhs.keyword() != rhs.keyword())
      return false;
    if (lhs.pin() != rhs.pin())
      return false;
    if (lhs.password() != rhs.password())
      return false;
    if (lhs.session_name() != rhs.session_name())
      return false;
    if (lhs.unique_user_id() != rhs.unique_user_id())
      return false;
    if (lhs.root_parent_id() != rhs.root_parent_id())
      return false;
    if (lhs.serialised_data_atlas() != rhs.serialised_data_atlas())
      return false;

    std::vector<std::string> lhs_public_ids(lhs.PublicIdentities());
    std::vector<std::string> rhs_public_ids(rhs.PublicIdentities());
    if (lhs_public_ids.size() != rhs_public_ids.size())
      return false;

    for (size_t n(0); n < rhs_public_ids.size(); ++n) {
      if (lhs_public_ids[n] != rhs_public_ids[n])
        return false;
      if (!EqualContactHandlers(lhs.contacts_handler(lhs_public_ids[n]),
                                rhs.contacts_handler(rhs_public_ids[n])))
        return false;
      if (lhs.social_info(lhs_public_ids[n]).second->at(kPicture) !=
          rhs.social_info(rhs_public_ids[n]).second->at(kPicture))
        return false;
      if (lhs.social_info(lhs_public_ids[n]).second->at(kInfoPointer) !=
          rhs.social_info(rhs_public_ids[n]).second->at(kInfoPointer))
        return false;
      if (!EqualShareInformations(lhs.share_information(lhs_public_ids[n]).second,
                                  rhs.share_information(rhs_public_ids[n]).second))
        return false;
    }

    return true;
  }

 private:
  explicit SessionTest(const SessionTest&);
  SessionTest& operator=(const SessionTest&);
};

TEST_F(SessionTest, BEH_SetsGetsAndReset) {
  // Check session is clean originally
  ASSERT_EQ(DefConLevels::kDefCon3, session_.def_con_level());
  ASSERT_EQ("", session_.keyword());
  ASSERT_EQ("", session_.pin());
  ASSERT_EQ("", session_.password());
  ASSERT_EQ("", session_.session_name());
  ASSERT_EQ("", session_.unique_user_id());
  ASSERT_EQ("", session_.root_parent_id());

  // Modify session
  session_.set_def_con_level(DefConLevels::kDefCon1);
  SetUsernamePinPassword("aaa", "bbb", "ccc");
  ASSERT_TRUE(session_.set_session_name());
  session_.set_unique_user_id("ddd1");
  session_.set_root_parent_id("ddd2");

  // Verify modifications
  ASSERT_EQ(DefConLevels::kDefCon1, session_.def_con_level());
  ASSERT_EQ("aaa", session_.keyword());
  ASSERT_EQ("bbb", session_.pin());
  ASSERT_EQ("ccc", session_.password());
  ASSERT_NE("", session_.session_name());
  ASSERT_EQ("ddd1", session_.unique_user_id());
  ASSERT_EQ("ddd2", session_.root_parent_id());

  // Resetting the session
  session_.Reset();

  // Check session is clean again
  ASSERT_EQ(DefConLevels::kDefCon3, session_.def_con_level());
  ASSERT_EQ("", session_.keyword());
  ASSERT_EQ("", session_.pin());
  ASSERT_EQ("", session_.password());
  ASSERT_EQ("", session_.session_name());
  ASSERT_EQ("", session_.unique_user_id());
  ASSERT_EQ("", session_.root_parent_id());
}

TEST_F(SessionTest, BEH_SessionName) {
  // Check session is empty
  ASSERT_EQ("", session_.session_name());
  ASSERT_EQ("", session_.keyword());
  ASSERT_EQ("", session_.pin());

  // Check keyword and pin are needed
  ASSERT_FALSE(session_.set_session_name());
  ASSERT_EQ("", session_.session_name());

  // Set the session values
  std::string keyword(RandomAlphaNumericString(6));
  std::string pin(CreatePin());
  SetUsernamePinPassword(keyword, pin, "ccc");
  ASSERT_TRUE(session_.set_session_name());

  // Check session name
  ASSERT_FALSE(session_.session_name().empty());

  // Reset value and check empty again
  session_.clear_session_name();
  ASSERT_EQ("", session_.session_name());
}

TEST_F(SessionTest, BEH_SerialisationAndParsing) {
  CreateTestSession(true);
  std::string serialised_data_atlas;
  ASSERT_EQ(kSuccess, session_.SerialiseDataAtlas(&serialised_data_atlas));
  ASSERT_FALSE(serialised_data_atlas.empty());
  DataAtlas atlas;
  ASSERT_TRUE(atlas.ParseFromString(serialised_data_atlas));

  // Compare surrogate. Different timestamp only.
  std::string surrogate_serialised_data_atlas;
  ASSERT_EQ(kSuccess, session_.SerialiseDataAtlas(&surrogate_serialised_data_atlas));
  ASSERT_FALSE(serialised_data_atlas.empty());
  DataAtlas surrogate_atlas;
  ASSERT_TRUE(surrogate_atlas.ParseFromString(surrogate_serialised_data_atlas));

  ASSERT_TRUE(EquivalentDataAtlases(atlas, surrogate_atlas));
  ASSERT_NE(atlas.timestamp(), surrogate_atlas.timestamp());

  // After a reset
  session_.Reset();
  ASSERT_EQ(kSuccess, session_.ParseDataAtlas(serialised_data_atlas));
  std::string new_serialised_data_atlas;
  ASSERT_EQ(kSuccess, session_.SerialiseDataAtlas(&new_serialised_data_atlas));
  ASSERT_FALSE(new_serialised_data_atlas.empty());
  DataAtlas new_atlas;
  ASSERT_TRUE(new_atlas.ParseFromString(new_serialised_data_atlas));
  ASSERT_TRUE(EquivalentDataAtlases(atlas, new_atlas));

  // Another session
  Session local_session;
  local_session.ParseDataAtlas(surrogate_serialised_data_atlas);
  std::string other_session_serialised;
  ASSERT_EQ(kSuccess, local_session.SerialiseDataAtlas(&other_session_serialised));
  ASSERT_FALSE(other_session_serialised.empty());
  DataAtlas other_session_atlas;
  ASSERT_TRUE(other_session_atlas.ParseFromString(other_session_serialised));
  ASSERT_TRUE(EquivalentDataAtlases(atlas, other_session_atlas));

  // Compare two session objects
  ASSERT_TRUE(EqualSessions(session_, local_session));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
