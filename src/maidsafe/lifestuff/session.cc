/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Singleton for setting/getting session info
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

#include "maidsafe/lifestuff/session.h"

#include <memory>

#include "maidsafe/common/crypto.h"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4244 4127)
#endif
#include "maidsafe/lifestuff/data_atlas.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

namespace maidsafe {

namespace lifestuff {

Session::Session()
    : ud_(),
      io_service_(),
      work_(new boost::asio::io_service::work(io_service_)),
      threads_(),
      passport_(new passport::Passport(io_service_, kRsaKeySize)),
      ch_(),
      psh_(),
      conversations_(),
      live_contacts_(),
      lc_mutex_() {
  for (int i(0); i != 10; ++i) {
    threads_.create_thread(
        std::bind(static_cast<size_t(boost::asio::io_service::*)()>(
            &boost::asio::io_service::run), &io_service_));
  }
  passport_->Init();
}

bool Session::ResetSession() {
  ud_.defconlevel = kDefCon3;
  ud_.da_modified = false;
  ud_.username.clear();
  ud_.pin.clear();
  ud_.password.clear();
  ud_.session_name.clear();
  ud_.root_db_key.clear();
  ud_.self_encrypting = true;
  ud_.authorised_users.clear();
  ud_.maid_authorised_users.clear();
  ud_.mounted = 0;
  ud_.win_drive = '\0';
  ud_.connection_status = 1;
  passport_->ClearKeyring();
  ch_.ClearContacts();
  psh_.ClearPrivateShares();
  conversations_.clear();
  live_contacts_.clear();
  return true;
}



// // / // / // / // / // / // / // / // / // / //
// // User Details Handling // //
// // / // / // / // / // / // / // / // / // / //

// Accessors
DefConLevels Session::def_con_level() { return ud_.defconlevel; }
bool Session::da_modified() { return ud_.da_modified; }
std::string Session::username() { return ud_.username; }
std::string Session::pin() { return ud_.pin; }
std::string Session::password() { return ud_.password; }
std::string Session::public_username() {
    return passport_->public_name();
}
std::string Session::session_name() { return ud_.session_name; }
std::string Session::root_db_key() { return ud_.root_db_key; }
bool Session::self_encrypting() { return ud_.self_encrypting; }
const std::set<std::string> &Session::authorised_users() {
  return ud_.authorised_users;
}
const std::set<std::string> &Session::maid_authorised_users() {
  return ud_.maid_authorised_users;
}
int Session::mounted() { return ud_.mounted; }
char Session::win_drive() { return ud_.win_drive; }
int Session::connection_status() { return ud_.connection_status; }
boost::asio::io_service& Session::io_service() { return io_service_; }

// Mutators
void Session::set_def_con_level(DefConLevels defconlevel) {
  ud_.defconlevel = defconlevel;
}
void Session::set_da_modified(bool da_modified) {
  ud_.da_modified = da_modified;
}
void Session::set_username(const std::string &username) {
  ud_.username = username;
}
void Session::set_pin(const std::string &pin) { ud_.pin = pin; }
void Session::set_password(const std::string &password) {
  ud_.password = password;
}
bool Session::set_session_name(bool clear) {
  if (clear) {
    ud_.session_name.clear();
  } else {
    if (username().empty() || pin().empty())
      return false;
    ud_.session_name = EncodeToHex(crypto::Hash<crypto::SHA1>(pin() +
                                                              username()));
  }
  return true;
}
void Session::set_root_db_key(const std::string &root_db_key) {
  ud_.root_db_key = root_db_key;
}
void Session::set_self_encrypting(bool self_encrypting) {
  ud_.self_encrypting = self_encrypting;
}
void Session::set_authorised_users(
    const std::set<std::string> &authorised_users) {
  ud_.authorised_users = authorised_users;
}
void Session::set_maid_authorised_users(
    const std::set<std::string> &maid_authorised_users) {
  ud_.maid_authorised_users = maid_authorised_users;
}
void Session::set_mounted(int mounted) { ud_.mounted = mounted; }
void Session::set_win_drive(char win_drive) {
  ud_.win_drive = win_drive;
}
void Session::set_connection_status(int status) {
  ud_.connection_status = status;
}


// // / // / // / // / // / // / // / //
// Key ring operations //
// // / // / // / // / // / // / // / //

int Session::ParseKeyring(const std::string &serialised_keyring) {
  return passport_->ParseKeyring(serialised_keyring);
}

std::string Session::SerialiseKeyring() {
  return passport_->SerialiseKeyring();
}

int Session::ProxyMID(std::string *id,
                               std::string *public_key,
                               std::string *private_key,
                               std::string *public_key_signature) {
  return GetKey(passport::PMID, id, public_key, private_key,
                public_key_signature);
}

int Session::MPublicID(std::string *id,
                                std::string *public_key,
                                std::string *private_key,
                                std::string *public_key_signature) {
  return GetKey(passport::MPID, id, public_key, private_key,
                public_key_signature);
}

int Session::GetKey(const passport::PacketType &packet_type,
                             std::string *id,
                             std::string *public_key,
                             std::string *private_key,
                             std::string *public_key_signature) {
  std::shared_ptr<passport::SignaturePacket> packet(
      std::static_pointer_cast<passport::SignaturePacket>(
          passport_->GetPacket(packet_type, true)));
  int result(packet ? kSuccess : kGetKeyFailure);
  if (id) {
    if (result == kSuccess)
      *id = packet->name();
    else
      id->clear();
  }
  if (public_key) {
    if (result == kSuccess)
      *public_key = packet->value();
    else
      public_key->clear();
  }
  if (private_key) {
    if (result == kSuccess)
      *private_key = packet->private_key();
    else
      private_key->clear();
  }
  if (public_key_signature) {
    if (result == kSuccess)
      *public_key_signature = packet->public_key_signature();
    else
      public_key_signature->clear();
  }
  return result;
}

bool Session::CreateTestPackets(const std::string &public_username) {
  passport_->Init();
  std::shared_ptr<passport::SignaturePacket>
      pkt(new passport::SignaturePacket);
  if (passport_->InitialiseSignaturePacket(passport::ANMAID, pkt) != kSuccess)
    return false;
  if (passport_->ConfirmSignaturePacket(pkt) != kSuccess)
    return false;
  if (passport_->InitialiseSignaturePacket(passport::MAID, pkt) != kSuccess)
    return false;
  if (passport_->ConfirmSignaturePacket(pkt) != kSuccess)
    return false;
  if (passport_->InitialiseSignaturePacket(passport::PMID, pkt) != kSuccess)
    return false;
  if (passport_->ConfirmSignaturePacket(pkt) != kSuccess)
    return false;
  if (public_username.empty())
    return true;
  if (passport_->InitialiseSignaturePacket(passport::ANMPID, pkt) != kSuccess)
    return false;
  if (passport_->ConfirmSignaturePacket(pkt) != kSuccess)
    return false;
  if (passport_->InitialiseMpid(public_username, pkt) != kSuccess)
    return false;
  if (passport_->ConfirmSignaturePacket(pkt) != kSuccess)
    return false;
  return true;
}

std::string Session::Id(const passport::PacketType &packet_type,
                                 bool confirmed_as_stored) {
  return passport_->SignaturePacketName(packet_type, confirmed_as_stored);
}

std::string Session::PublicKey(const passport::PacketType &packet_type,
                                        bool confirmed_as_stored) {
  return passport_->SignaturePacketPublicKey(packet_type, confirmed_as_stored);
}

std::string Session::PrivateKey(
    const passport::PacketType &packet_type,
    bool confirmed_as_stored) {
  return passport_->SignaturePacketPrivateKey(packet_type, confirmed_as_stored);
}

std::string Session::PublicKeySignature(
    const passport::PacketType &packet_type,
    bool confirmed_as_stored) {
  return passport_->SignaturePacketPublicKeySignature(packet_type,
                                                      confirmed_as_stored);
}


// // / // / // / // / // / // / // / /
// Contact operations //
// // / // / // / // / // / // / // / /

int Session::LoadContacts(std::list<PublicContact> *contacts) {
  int n = 0;
  while (!contacts->empty()) {
    PublicContact pc = contacts->front();
    n += AddContact(pc.pub_name(), pc.pub_key(), pc.full_name(),
                    pc.office_phone(), pc.birthday(), pc.gender().at(0),
                    pc.language(), pc.country(), pc.city(),
                    pc.confirmed().at(0), pc.rank(), pc.last_contact());
    contacts->pop_front();
  }
  return n;
}

int Session::AddContact(const std::string &pub_name,
                                 const std::string &pub_key,
                                 const std::string &full_name,
                                 const std::string &office_phone,
                                 const std::string &birthday,
                                 const char &gender,
                                 const int &language,
                                 const int &country,
                                 const std::string &city,
                                 const char &confirmed,
                                 const int &rank,
                                 const int &last_contact) {
  return ch_.AddContact(pub_name, pub_key, full_name, office_phone, birthday,
                           gender, language, country, city, confirmed, rank,
                           last_contact);
}
int Session::DeleteContact(const std::string &pub_name) {
  return ch_.DeleteContact(pub_name);
}
int Session::UpdateContact(const mi_contact &mic) {
  return ch_.UpdateContact(mic);
}
int Session::UpdateContactKey(const std::string &pub_name,
                                       const std::string &value) {
  return ch_.UpdateContactKey(pub_name, value);
}
int Session::UpdateContactFullName(const std::string &pub_name,
                                            const std::string &value) {
  return ch_.UpdateContactFullName(pub_name, value);
}
int Session::UpdateContactOfficePhone(const std::string &pub_name,
                                               const std::string &value) {
  return ch_.UpdateContactOfficePhone(pub_name, value);
}
int Session::UpdateContactBirthday(const std::string &pub_name,
                                            const std::string &value) {
  return ch_.UpdateContactBirthday(pub_name, value);
}
int Session::UpdateContactGender(const std::string &pub_name,
                                          const char &value) {
  return ch_.UpdateContactGender(pub_name, value);
}
int Session::UpdateContactLanguage(const std::string &pub_name,
                                            const int &value) {
  return ch_.UpdateContactLanguage(pub_name, value);
}
int Session::UpdateContactCountry(const std::string &pub_name,
                                           const int &value) {
  return ch_.UpdateContactCountry(pub_name, value);
}
int Session::UpdateContactCity(const std::string &pub_name,
                                        const std::string &value) {
  return ch_.UpdateContactCity(pub_name, value);
}
int Session::UpdateContactConfirmed(const std::string &pub_name,
                                             const char &value) {
  return ch_.UpdateContactConfirmed(pub_name, value);
}
int Session::SetLastContactRank(const std::string &pub_name) {
  return ch_.SetLastContactRank(pub_name);
}
int Session::GetContactInfo(const std::string &pub_name,
                                     mi_contact *mic) {
  return ch_.GetContactInfo(pub_name, mic);
}
std::string Session::GetContactPublicKey(const std::string &pub_name) {
  mi_contact mic;
  if (ch_.GetContactInfo(pub_name, &mic) != 0)
    return "";
  return mic.pub_key_;
}

// type:  1  - for most contacted
//        2  - for most recent
//        0  - (default) alphabetical
int Session::GetContactList(std::vector<mi_contact> *list,
                                     int type) {
  return ch_.GetContactList(list, type);
}
int Session::GetPublicUsernameList(std::vector<std::string> *list) {
  list->clear();
  std::vector<mi_contact> mic_list;
  if (ch_.GetContactList(&mic_list, 0) != 0)
    return kContactListFailure;
  for (size_t n = 0; n < mic_list.size(); ++n)
    list->push_back(mic_list[n].pub_name_);
  return 0;
}
int Session::ClearContacts() {
  return ch_.ClearContacts();
}


// // / // / // / // / // / // / // / // / // / /
// Private Share operations //
// // / // / // / // / // / // / // / // / // / /

int Session::LoadShares(std::list<Share> *shares) {
  int a = 0;
  while (!shares->empty()) {
    Share sh = shares->front();
    std::list<ShareParticipants> sp;
    for (int n = 0; n < sh.participants_size(); n++) {
      sp.push_back(ShareParticipants(sh.participants(n).public_name(),
                                     sh.participants(n).public_name_pub_key(),
                                     sh.participants(n).role().at(0)));
    }
    std::vector<std::string> attributes;
    attributes.push_back(sh.name());
    attributes.push_back(sh.msid());
    attributes.push_back(sh.msid_pub_key());
    if (sh.has_msid_pri_key())
      attributes.push_back(sh.msid_pri_key());
    else
      attributes.push_back("");
    std::vector<boost::uint32_t> share_stats;
    share_stats.push_back(sh.rank());
    share_stats.push_back(sh.last_view());
    shares->pop_front();
    a += AddPrivateShare(attributes, share_stats, &sp);
  }
  return a;
}
int Session::AddPrivateShare(
    const std::vector<std::string> &attributes,
    const std::vector<boost::uint32_t> &share_stats,
    std::list<ShareParticipants> *participants) {
  return psh_.AddPrivateShare(attributes, share_stats, participants);
}
int Session::DeletePrivateShare(const std::string &value,
                                         const int &field) {
  return psh_.DeletePrivateShare(value, field);
}
int Session::AddContactsToPrivateShare(
    const std::string &value,
    const int &field,
    std::list<ShareParticipants> *participants) {
  return psh_.AddContactsToPrivateShare(value, field, participants);
}
int Session::DeleteContactsFromPrivateShare(
    const std::string &value,
    const int &field,
    std::list<std::string> *participants) {
  return psh_.DeleteContactsFromPrivateShare(value, field, participants);
}
int Session::TouchShare(const std::string &value, const int &field) {
  return psh_.TouchShare(value, field);
}
int Session::GetShareInfo(const std::string &value,
                                   const int &field,
                                   PrivateShare *ps) {
  return psh_.GetShareInfo(value, field, ps);
}
int Session::GetShareKeys(const std::string &msid,
                                   std::string *public_key,
                                   std::string *private_key) {
  PrivateShare ps;
  if (GetShareInfo(msid, 1, &ps) != 0) {
    printf("Pelation en SS::GetShareKeys\n");
    *public_key = "";
    *private_key = "";
    return -1;
  }
  *public_key = ps.MsidPubKey();
  *private_key = ps.MsidPriKey();
  return 0;
}
int Session::GetShareList(std::list<private_share> *ps_list,
                                   const SortingMode &sm,
                                   const ShareFilter &sf) {
  return psh_.GetShareList(ps_list, sm, sf);
}
int Session::GetFullShareList(const SortingMode &sm,
                                       const ShareFilter &sf,
                                       std::list<PrivateShare> *ps_list) {
  return psh_.GetFullShareList(sm, sf, ps_list);
}
int Session::GetParticipantsList(
    const std::string &value,
    const int &field,
    std::list<share_participant> *sp_list) {
  return psh_.GetParticipantsList(value, field, sp_list);
}
void Session::ClearPrivateShares() {
  return psh_.ClearPrivateShares();
}


// // / // / // / // / // / // / // / // / // / //
// // Conversation Handling // //
// // / // / // / // / // / // / // / // / // / //

int Session::ConversationList(std::list<std::string> *conversations) {
  conversations->clear();
  *conversations = std::list<std::string>(conversations_.begin(),
                                          conversations_.end());
  return 0;
}
int Session::AddConversation(const std::string &id) {
  if (id.empty())
    return kEmptyConversationId;

  std::pair<std::set<std::string>::iterator, bool> ret;
  ret = conversations_.insert(id);

  if (!ret.second)
    return kExistingConversation;

  return 0;
}
int Session::RemoveConversation(const std::string &id) {
  if (id.empty())
    return kEmptyConversationId;

  size_t t = conversations_.erase(id);
  if (t == 0)
    return kNonExistentConversation;

  return 0;
}
int Session::ConversationExits(const std::string &id) {
  if (id.empty())
    return kEmptyConversationId;

  std::set<std::string>::iterator it = conversations_.find(id);
  if (it == conversations_.end())
    return kNonExistentConversation;

  return 0;
}
void Session::ClearConversations() {
  conversations_.clear();
}


// // / // / // / // / // / // / // / // / // / //
// // Live Contact Handling // //
// // / // / // / // / // / // / // / // / // / //

/*
int Session::AddLiveContact(const std::string &contact,
                                     const EndPoint &end_points,
                                     int status) {
  ConnectionDetails cd;
  cd.ep = end_points;
  cd.status = status;
  cd.transport = 0;
  cd.connection_id = 0;
  cd.init_timestamp = 0;

  std::pair<live_map::iterator, bool> p;
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    p = live_contacts_.insert(
        std::pair<std::string, ConnectionDetails>(contact, cd));
  }
  if (!p.second)
    return kAddLiveContactFailure;

  return kSuccess;
}

int Session::LivePublicUsernameList(std::list<std::string> *contacts) {
  contacts->clear();
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it;
    for (it = live_contacts_.begin(); it != live_contacts_.end(); ++it)
      contacts->push_back(it->first);
  }
  return kSuccess;
}

int Session::LiveContactMap(
    std::map<std::string, ConnectionDetails> *live_contacts) {
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    *live_contacts = live_contacts_;
  }
  return kSuccess;
}

int Session::LiveContactDetails(const std::string &contact,
                                         EndPoint *end_points,
                                         boost::uint16_t *transport_id,
                                         boost::uint32_t *connection_id,
                                         int *status,
                                         boost::uint32_t *init_timestamp) {
  end_points->Clear();
  *transport_id = 0;
  *connection_id = 0;
  *status = 0;
  *init_timestamp = 0;
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;
    *end_points = it->second.ep;
    *transport_id = it->second.transport;
    *connection_id = it->second.connection_id;
    *status = it->second.status;
    *init_timestamp = it->second.init_timestamp;
  }
  return kSuccess;
}

int Session::LiveContactTransportConnection(
    const std::string &contact,
    boost::uint16_t *transport_id,
    boost::uint32_t *connection_id) {
  *transport_id = 0;
  *connection_id = 0;
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;
    *transport_id = it->second.transport;
    *connection_id = it->second.connection_id;
  }
  return kSuccess;
}

int Session::LiveContactStatus(const std::string &contact,
                                        int *status) {
  *status = -1;
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;
    *status = it->second.status;
  }
  return kSuccess;
}

int Session::StartLiveConnection(const std::string &contact,
                                          boost::uint16_t transport_id,
                                          const boost::uint32_t &conn_id) {
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;
    it->second.transport = transport_id;
    it->second.connection_id = conn_id;
    it->second.init_timestamp = GetDurationSinceEpoch();
  }
  return kSuccess;
}

int Session::ModifyTransportId(const std::string &contact,
                                        boost::uint16_t transport_id) {
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;
    it->second.transport = transport_id;
  }
  return kSuccess;
}

int Session::ModifyConnectionId(const std::string &contact,
                                         const boost::uint32_t &connection_id) {
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;
    it->second.connection_id = connection_id;
  }
  return kSuccess;
}

int Session::ModifyEndPoint(const std::string &contact,
                                     const std::string &ip,
                                     const boost::uint16_t &port,
                                     int which) {
  if (which < 0 || which > 2)
    return kLiveContactNoEp;
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;

    if (which >= it->second.ep.ip_size())
      return kLiveContactNoEp;
    it->second.ep.set_ip(which, ip);
    it->second.ep.set_port(which, port);
  }
  return kSuccess;
}

int Session::ModifyEndPoint(const std::string &contact,
                                     const EndPoint end_point) {
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;
    it->second.ep = end_point;
  }
  return kSuccess;
}

int Session::ModifyStatus(const std::string &contact, int status) {
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;
    it->second.status = status;
  }
  return kSuccess;
}

int Session::DeleteLiveContact(const std::string &contact) {
  size_t n(0);
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    n = live_contacts_.erase(contact);
  }
  return n;
}

void Session::ClearLiveContacts() {
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_contacts_.clear();
  }
}
*/

}  // namespace lifestuff

}  // namespace maidsafe


