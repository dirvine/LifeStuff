/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  class which controls all maidsafe client operations
* Version:      1.0
* Created:      2009-01-28-10.59.46
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

#include "maidsafe/lifestuff/client_controller.h"

#ifdef MAIDSAFE_WIN32
#  include <shlwapi.h>
#endif

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4308)
#endif
#include "boost/archive/text_oarchive.hpp"
#include "boost/archive/text_iarchive.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "boost/foreach.hpp"

#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/buffered_chunk_store.h"
#include "maidsafe/common/hashable_chunk_validation.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/authentication.h"
#include "maidsafe/lifestuff/client_utils.h"
#include "maidsafe/lifestuff/data_atlas_pb.h"
#include "maidsafe/lifestuff/session.h"

namespace arg = std::placeholders;

namespace maidsafe {

namespace lifestuff {

void CCCallback::IntCallback(int return_code) {
  boost::mutex::scoped_lock lock(mutex_);
  return_int_ = return_code;
  cv_.notify_one();
}

int CCCallback::WaitForIntResult() {
  int result;
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (return_int_ == kPendingResult)
      cv_.wait(lock);
    result = return_int_;
    return_int_ = kPendingResult;
  }
  return result;
}

void PacketOpCallback(const int &store_manager_result,
                      boost::mutex *mutex,
                      boost::condition_variable *cond_var,
                      int *op_result) {
  boost::mutex::scoped_lock lock(*mutex);
  *op_result = store_manager_result;
  cond_var->notify_one();
}

ClientController::ClientController()
    : client_chunkstore_(),
      session_(new Session()),
      packet_manager_(),
      auth_(new Authentication(session_)),
      ser_da_(),
      client_store_(),
      initialised_(false),
      logging_out_(false),
      logged_in_(false) {}

ClientController::~ClientController() {
  packet_manager_->Close(false);
}

int ClientController::Initialise() {
  CCCallback cb;
  packet_manager_->Init(std::bind(&CCCallback::IntCallback, &cb, arg::_1));
  int result(cb.WaitForIntResult());
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to initialise packet_manager_.";
    return result;
  }
  auth_->Init(packet_manager_);
  initialised_ = true;
  return kSuccess;
}

int ClientController::ParseDa() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return kClientControllerNotInitialised;
  }
  DataAtlas data_atlas;
  if (ser_da_.empty()) {
    DLOG(ERROR) << "TMID brought is empty.";
    return -9000;
  }
  if (!data_atlas.ParseFromString(ser_da_)) {
    DLOG(ERROR) << "TMID doesn't parse.";
    return -9000;
  }
  if (!data_atlas.has_root_db_key()) {
    DLOG(ERROR) << "DA doesn't have a root db key.";
    return -9001;
  }
  session_->set_root_db_key(data_atlas.root_db_key());

  if (!data_atlas.has_serialised_keyring()) {
    DLOG(ERROR) << "Missing serialised keyring.";
    return -9003;
  }
  session_->ParseKeyring(data_atlas.serialised_keyring());

  std::list<PublicContact> contacts;
  for (int n = 0; n < data_atlas.contacts_size(); ++n) {
    PublicContact pc = data_atlas.contacts(n);
    contacts.push_back(pc);
  }

  std::list<Share> shares;
  for (int n = 0; n < data_atlas.shares_size(); ++n) {
    Share sh = data_atlas.shares(n);
    shares.push_back(sh);
  }

  return 0;
}

int ClientController::SerialiseDa() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return kClientControllerNotInitialised;
  }

  DataAtlas data_atlas;
  data_atlas.set_root_db_key(session_->root_db_key());

  std::string serialised_keyring = session_->SerialiseKeyring();
  if (serialised_keyring.empty()) {
    DLOG(ERROR) << "Serialising keyring failed.";
    return -1;
  }
  data_atlas.set_serialised_keyring(serialised_keyring);

  std::vector<mi_contact> contacts;
  session_->contacts_handler()->GetContactList(&contacts);
  for (size_t n = 0; n < contacts.size(); ++n) {
    PublicContact *pc = data_atlas.add_contacts();
    pc->set_pub_name(contacts[n].pub_name_);
    pc->set_pub_key(contacts[n].pub_key_);
    pc->set_full_name(contacts[n].full_name_);
    pc->set_office_phone(contacts[n].office_phone_);
    pc->set_birthday(contacts[n].birthday_);
    std::string g(1, contacts[n].gender_);
    pc->set_gender(g);
    pc->set_language(contacts[n].language_);
    pc->set_country(contacts[n].country_);
    pc->set_city(contacts[n].city_);
    std::string c(1, contacts[n].confirmed_);
    pc->set_confirmed(c);
    pc->set_rank(contacts[n].rank_);
    pc->set_last_contact(contacts[n].last_contact_);
  }

  std::list<PrivateShare> ps_list;
  session_->private_share_handler()->GetFullShareList(kAlpha, kAll, &ps_list);
  while (!ps_list.empty()) {
    PrivateShare this_ps = ps_list.front();
    Share *sh = data_atlas.add_shares();
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


  ser_da_.clear();
  data_atlas.SerializeToString(&ser_da_);

  return 0;
}

int ClientController::CheckUserExists(const std::string &username,
                                      const std::string &pin) {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return kClientControllerNotInitialised;
  }
  session_->ResetSession();
  session_->set_def_con_level(kDefCon1);
  return auth_->GetUserInfo(username, pin);
}

bool ClientController::CreateUser(const std::string &username,
                                  const std::string &pin,
                                  const std::string &password) {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return false;
  }

  session_->ResetSession();
  session_->set_connection_status(0);
  int result = auth_->CreateUserSysPackets(username, pin);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to create user system packets.";
    session_->ResetSession();
    return false;
  } else {
    DLOG(ERROR) << "auth_->CreateUserSysPackets DONE.";
  }

  // std::string ser_da(session_->SerialiseKeyring());
  int n = SerialiseDa();
  if (n != 0) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return false;
  }

  result = auth_->CreateTmidPacket(username, pin, password, ser_da_);
  if (result != kSuccess) {
    DLOG(ERROR) << "Cannot create tmid packet.";
    session_->ResetSession();
    return false;
  } else {
    DLOG(ERROR) << "auth_->CreateTmidPacket DONE.";
  }

  session_->set_session_name(false);
  logged_in_ = true;
  return true;
}

bool ClientController::ValidateUser(const std::string &password) {
  if (!initialised_) {
    DLOG(ERROR) << "CC::ValidateUser - Not initialised.";
    return false;
  }
  ser_da_.clear();

  std::shared_ptr<std::string> serialised_master_datamap(new std::string);
  std::shared_ptr<std::string> surrogate_serialised_master_datamap(
      new std::string);
  int res = auth_->GetMasterDataMap(password,
                                   serialised_master_datamap,
                                   surrogate_serialised_master_datamap);
  if (res != 0) {
    DLOG(ERROR) << "CC::ValidateUser - Failed retrieving DA.";
    return false;
  }

  if (!serialised_master_datamap->empty()) {
    DLOG(INFO) << "ClientController::ValidateUser - Using TMID";
    ser_da_ = *serialised_master_datamap;
  } else if (!surrogate_serialised_master_datamap->empty()) {
    DLOG(INFO) << "ClientController::ValidateUser - Using STMID";
    ser_da_ = *surrogate_serialised_master_datamap;
  } else {
    // Password validation failed
    ser_da_.clear();
    session_->ResetSession();
    DLOG(INFO) << "ClientController::ValidateUser - Invalid password";
    return false;
  }

  session_->set_connection_status(0);
  session_->set_session_name(false);
  if (ParseDa() != 0) {
    DLOG(INFO) << "ClientController::ValidateUser - Cannot parse DA";
    session_->ResetSession();
    return false;
  }
  logged_in_ = true;
  return true;
}

bool ClientController::Logout() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return false;
  }
  logging_out_ = true;
//  clear_messages_thread_.join();
  int result = SaveSession();
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to save session " << result;
    return false;
  }

  ser_da_.clear();
  logging_out_ = false;
  logged_in_ = false;
  session_->ResetSession();
  return true;
}

int ClientController::SaveSession() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return kClientControllerNotInitialised;
  }

  int n = SerialiseDa();
  if (n != 0) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return n;
  }

  n = kPendingResult;
  boost::mutex mutex;
  boost::condition_variable cond_var;
  VoidFuncOneInt func = std::bind(&PacketOpCallback, arg::_1, &mutex,
                                  &cond_var, &n);
  auth_->SaveSession(ser_da_, func);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (n == kPendingResult)
      cond_var.wait(lock);
  }

  if (n != kSuccess) {
    if (n == kFailedToDeleteOldPacket) {
      DLOG(ERROR) << "Failed to delete old TMID otherwise saved session OK.";
    } else {
      DLOG(ERROR) << "Failed to Save Session.";
      return n;
    }
  }
  return 0;
}

bool ClientController::LeaveMaidsafeNetwork() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return false;
  }
  if (auth_->RemoveMe() == kSuccess)
    return true;

  return false;
}

std::string ClientController::SessionName() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return "";
  }
  return session_->session_name();
}

bool ClientController::ChangeUsername(const std::string &new_username) {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return false;
  }
  SerialiseDa();

  int result = auth_->ChangeUsername(ser_da_, new_username);
  if (result != kSuccess) {
    if (result == kFailedToDeleteOldPacket) {
      DLOG(ERROR) << "Failed to delete old packets, changed username OK.";
      return true;
    } else {
      DLOG(ERROR) << "Failed to change username.";
      return false;
    }
  }
  return true;
}

bool ClientController::ChangePin(const std::string &new_pin) {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return false;
  }
  SerialiseDa();

  int result = auth_->ChangePin(ser_da_, new_pin);
  if (result != kSuccess) {
    if (result == kFailedToDeleteOldPacket) {
      DLOG(ERROR) << "Failed to delete old packets, otherwise changed PIN OK.";
      return true;
    } else {
      DLOG(ERROR) << "Failed to change PIN.";
      return false;
    }
  }
  return true;
}

bool ClientController::ChangePassword(const std::string &new_password) {
  if (!initialised_) {
    DLOG(ERROR) << " Not initialised.";
    return false;
  }
  SerialiseDa();

  int result = auth_->ChangePassword(ser_da_, new_password);
  if (result != kSuccess) {
    DLOG(ERROR) << " Authentication failed: " << result;
    return false;
  }
  return true;
}

std::string ClientController::Username() {
  return session_->username();
}

std::string ClientController::Pin() {
  return session_->pin();
}

std::string ClientController::Password() {
  return session_->password();
}
}  // namespace lifestuff

}  // namespace maidsafe
