/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  class which controls all maidsafe client operations
* Version:      1.0
* Created:      2009-01-28-10.59.46
* Revision:     none
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENCE.TXT found in the root of this directory and also on
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

#include "maidsafe/common/buffered_chunk_store.h"
#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"

#include "maidsafe/pd/client/client_container.h"
#include "maidsafe/pd/client/remote_chunk_store.h"

#include "maidsafe/lifestuff/authentication.h"
#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/data_atlas_pb.h"
#include "maidsafe/lifestuff/local_chunk_manager.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/ye_olde_signal_to_callback_converter.h"

namespace args = std::placeholders;

namespace maidsafe {

namespace lifestuff {

ClientController::ClientController(boost::asio::io_service &service,  // NOLINT (Dan)
                                   std::shared_ptr<Session> session)
    : session_(session),
      remote_chunk_store_(),
      auth_(new Authentication(session)),
      ser_da_(),
      surrogate_ser_da_(),
      initialised_(false),
      logging_out_(false),
      logged_in_(false),
      service_(service),
      converter_(new YeOldeSignalToCallbackConverter) {}

ClientController::~ClientController() {}

void ClientController::Init(bool local, const fs::path &base_dir) {
  if (initialised_)
    return;

  if (local) {
    std::shared_ptr<BufferedChunkStore> bcs(new BufferedChunkStore(service_));
    bcs->Init(base_dir / "buffered_chunk_store");
    std::shared_ptr<priv::ChunkActionAuthority> caa(
        new priv::ChunkActionAuthority(bcs));
    std::shared_ptr<LocalChunkManager> local_chunk_manager(
        new LocalChunkManager(bcs, base_dir / "local_chunk_manager"));
    remote_chunk_store_.reset(new pd::RemoteChunkStore(bcs,
                                                       local_chunk_manager,
                                                       caa));
  } else {
    pd::ClientContainer container;
    container.Init(base_dir / "buffer", 10);
    remote_chunk_store_.reset(
        new pd::RemoteChunkStore(container.chunk_store(),
                                 container.chunk_manager(),
                                 container.chunk_action_authority()));
  }

  remote_chunk_store_->sig_chunk_stored()->connect(
      std::bind(&YeOldeSignalToCallbackConverter::Stored, converter_.get(),
                args::_1, args::_2));
  remote_chunk_store_->sig_chunk_deleted()->connect(
      std::bind(&YeOldeSignalToCallbackConverter::Deleted, converter_.get(),
                args::_1, args::_2));
  remote_chunk_store_->sig_chunk_modified()->connect(
      std::bind(&YeOldeSignalToCallbackConverter::Modified, converter_.get(),
                args::_1, args::_2));

  auth_->Init(remote_chunk_store_, converter_);
  initialised_ = true;
}

int ClientController::ParseDa() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return kClientControllerNotInitialised;
  }
  DataAtlas data_atlas;
  if (ser_da_.empty() && surrogate_ser_da_.empty()) {
    DLOG(ERROR) << "TMID brought is empty.";
    return -9000;
  }
  if (!data_atlas.ParseFromString(ser_da_)) {
    DLOG(ERROR) << "TMID doesn't parse.";
    return -9000;
  }
  if (!data_atlas.has_timestamp()) {
    DLOG(ERROR) << "DA doesn't have a timestamp.";
    return -9001;
  }
  if (!data_atlas.has_unique_user_id() || !data_atlas.has_root_parent_id()) {
    DLOG(ERROR) << "DA doesn't have keys for root directory.";
    return -9001;
  }
  session_->set_unique_user_id(data_atlas.unique_user_id());
  session_->set_root_parent_id(data_atlas.root_parent_id());
  DLOG(INFO) << "UUID: " << Base32Substr(session_->unique_user_id());
  DLOG(INFO) << "PID: " << Base32Substr(session_->root_parent_id());

  if (!data_atlas.has_serialised_keyring()) {
    DLOG(ERROR) << "Missing serialised keyring.";
    return -9003;
  }

  int n(session_->ParseKeyChain(data_atlas.serialised_keyring(),
                                data_atlas.serialised_selectables()));
  if (n != kSuccess) {
    DLOG(ERROR) << "Failed ParseKeyChain: " << n;
    return -9003;
  }

  n = auth_->SetLoggedInData(ser_da_, surrogate_ser_da_);
  if (n != kSuccess) {
    DLOG(ERROR) << "Failed SetLoggedInData: " << n;
    return -9003;
  }

  std::set<std::string> public_usernames;
  std::string public_username;
  for (int n = 0; n < data_atlas.contacts_size(); ++n) {
    if (public_usernames.find(data_atlas.contacts(n).own_public_username()) ==
        public_usernames.end()) {
      session_->contact_handler_map().insert(
          std::make_pair(data_atlas.contacts(n).own_public_username(),
                         ContactsHandlerPtr(new ContactsHandler)));
      public_username = data_atlas.contacts(n).own_public_username();
    }
    Contact c(data_atlas.contacts(n));
    int res(session_->contact_handler_map()[public_username]->AddContact(c));
    DLOG(ERROR) << "Result of adding " << c.public_username << ": " << res;
  }

  return 0;
}

int ClientController::SerialiseDa() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return kClientControllerNotInitialised;
  }

  DataAtlas data_atlas;
  data_atlas.set_unique_user_id(session_->unique_user_id());
  data_atlas.set_root_parent_id(session_->root_parent_id());
  DLOG(INFO) << "UUID: " << Base32Substr(session_->unique_user_id());
  DLOG(INFO) << "PID: " << Base32Substr(session_->root_parent_id());
  data_atlas.set_timestamp(boost::lexical_cast<std::string>(
      GetDurationSinceEpoch().total_microseconds()));
  DLOG(INFO) << "data_atlas.set_timestamp: " << data_atlas.timestamp();

  std::string serialised_keyring, serialised_selectables;
  session_->SerialiseKeyChain(&serialised_keyring, &serialised_selectables);
  if (serialised_keyring.empty()) {
    DLOG(ERROR) << "Serialising keyring failed.";
    return -1;
  }
  data_atlas.set_serialised_keyring(serialised_keyring);
  data_atlas.set_serialised_selectables(serialised_selectables);

  std::vector<Contact> contacts;
  for (auto it(session_->contact_handler_map().begin());
       it != session_->contact_handler_map().end();
       ++it) {
    contacts.clear();
    (*it).second->OrderedContacts(&contacts);
    for (size_t n = 0; n < contacts.size(); ++n) {
      PublicContact *pc = data_atlas.add_contacts();
      pc->set_own_public_username((*it).first);
      pc->set_public_username(contacts[n].public_username);
      pc->set_mpid_name(contacts[n].mpid_name);
      pc->set_mmid_name(contacts[n].mmid_name);
      pc->set_status(contacts[n].status);
      pc->set_rank(contacts[n].rank);
      pc->set_last_contact(contacts[n].last_contact);
    }
  }

  ser_da_.clear();
  data_atlas.SerializeToString(&ser_da_);

  return 0;
}

bool ClientController::CreateUser(const std::string &username,
                                  const std::string &pin,
                                  const std::string &password) {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return false;
  }

  session_->ResetSession();
  int result = auth_->CreateUserSysPackets(username, pin);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to create user system packets.";
    session_->ResetSession();
    return false;
  } else {
    DLOG(INFO) << "auth_->CreateUserSysPackets DONE.";
  }

  int n = SerialiseDa();
  if (n != 0) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return false;
  }
  std::string ser_da(ser_da_);

  // Need different timestamps
  Sleep(boost::posix_time::milliseconds(1));
  n = SerialiseDa();
  if (n != 0) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return false;
  }
  std::string surrogate_ser_da(ser_da_);

  ser_da_ = ser_da;

  result = auth_->CreateTmidPacket(password, ser_da, surrogate_ser_da);
  if (result != kSuccess) {
    DLOG(ERROR) << "Cannot create tmid packet.";
    session_->ResetSession();
    return false;
  } else {
    DLOG(INFO) << "auth_->CreateTmidPacket DONE.";
  }

  session_->set_session_name(false);
  logged_in_ = true;
  return true;
}

int ClientController::CheckUserExists(const std::string &username,
                                      const std::string &pin) {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return kClientControllerNotInitialised;
  }
  session_->ResetSession();
  session_->set_def_con_level(kDefCon1);
  ser_da_.clear();
  return auth_->GetUserInfo(username, pin);
}

bool ClientController::ValidateUser(const std::string &password) {
  if (!initialised_) {
    DLOG(ERROR) << "CC::ValidateUser - Not initialised.";
    return false;
  }
//  ser_da_.clear();

  std::string serialised_data_atlas, surrogate_serialised_data_atlas;
  int res(auth_->GetMasterDataMap(password,
                                  &serialised_data_atlas,
                                  &surrogate_serialised_data_atlas));
  if (res != 0) {
    DLOG(ERROR) << "CC::ValidateUser - Failed retrieving DA.";
    return false;
  }

  if (!serialised_data_atlas.empty()) {
    DLOG(INFO) << "ClientController::ValidateUser - Using TMID";
    ser_da_ = serialised_data_atlas;
    surrogate_ser_da_ = surrogate_serialised_data_atlas;
  } else if (!surrogate_serialised_data_atlas.empty()) {
    DLOG(INFO) << "ClientController::ValidateUser - Using STMID";
    surrogate_ser_da_ = surrogate_serialised_data_atlas;
  } else {
    // Password validation failed
//    session_->ResetSession();
    DLOG(INFO) << "ClientController::ValidateUser - Invalid password";
    return false;
  }

  session_->set_session_name(false);
  if (ParseDa() != 0) {
    DLOG(INFO) << "ClientController::ValidateUser - Cannot parse DA";
//    session_->ResetSession();
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
  if (n != kSuccess) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return n;
  }

  n = auth_->SaveSession(ser_da_);
  if (n != kSuccess) {
    if (n == kFailedToDeleteOldPacket) {
      DLOG(WARNING) << "Failed to delete old TMID otherwise saved session OK.";
    } else {
      DLOG(ERROR) << "Failed to Save Session.";
      return n;
    }
  }
  return kSuccess;
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
      DLOG(WARNING) << "Failed to delete old packets, changed username OK.";
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
      DLOG(WARNING) <<
          "Failed to delete old packets, otherwise changed PIN OK.";
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

std::shared_ptr<pd::RemoteChunkStore> ClientController::remote_chunk_store() {
  return remote_chunk_store_;
}

std::shared_ptr<YeOldeSignalToCallbackConverter> ClientController::converter() {
  return converter_;
}

}  // namespace lifestuff

}  // namespace maidsafe
