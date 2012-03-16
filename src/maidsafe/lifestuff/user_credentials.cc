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

#include "maidsafe/lifestuff/user_credentials.h"

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

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/pd/client/client_container.h"
#endif

#include "maidsafe/lifestuff/authentication.h"
#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/data_atlas_pb.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/utils.h"
#include "maidsafe/lifestuff/ye_olde_signal_to_callback_converter.h"

namespace args = std::placeholders;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

UserCredentials::UserCredentials(boost::asio::io_service &service,  // NOLINT (Dan)
                                 std::shared_ptr<Session> session)
    : session_(session),
      remote_chunk_store_(),
      authentication_(new Authentication(session)),
      serialised_da_(),
      surrogate_serialised_da_(),
      initialised_(false),
      logging_out_(false),
      logged_in_(false),
      service_(service),
#ifndef LOCAL_TARGETS_ONLY
      client_container_(),
#endif
      converter_(new YeOldeSignalToCallbackConverter) {}

UserCredentials::~UserCredentials() {}

void UserCredentials::Init(const fs::path &base_dir) {
  if (initialised_)
    return;

#ifdef LOCAL_TARGETS_ONLY
  remote_chunk_store_ = pcs::CreateLocalChunkStore(base_dir, service_);
#else
  client_container_ = SetUpClientContainer(base_dir);
  if (client_container_) {
    remote_chunk_store_.reset(new pcs::RemoteChunkStore(
        client_container_->chunk_store(),
        client_container_->chunk_manager(),
        client_container_->chunk_action_authority()));
  } else {
    DLOG(ERROR) << "Failed to initialise client container.";
    return;
  }
#endif

  remote_chunk_store_->sig_chunk_stored()->connect(
      std::bind(&YeOldeSignalToCallbackConverter::Stored, converter_.get(),
                args::_1, args::_2));
  remote_chunk_store_->sig_chunk_deleted()->connect(
      std::bind(&YeOldeSignalToCallbackConverter::Deleted, converter_.get(),
                args::_1, args::_2));
  remote_chunk_store_->sig_chunk_modified()->connect(
      std::bind(&YeOldeSignalToCallbackConverter::Modified, converter_.get(),
                args::_1, args::_2));

  authentication_->Init(remote_chunk_store_, converter_);
  initialised_ = true;
}

int UserCredentials::ParseDa() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return kUserCredentialsNotInitialised;
  }
  DataAtlas data_atlas;
  if (serialised_da_.empty() && surrogate_serialised_da_.empty()) {
    DLOG(ERROR) << "TMID brought is empty.";
    return -9000;
  }
  if (!data_atlas.ParseFromString(serialised_da_)) {
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

  if (!data_atlas.profile_picture_data_map()) {
    DLOG(ERROR) << "DA doesn't have profile picture data map.";
    return -9001;
  }

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

  n = authentication_->SetLoggedInData(serialised_da_,
                                       surrogate_serialised_da_);
  if (n != kSuccess) {
    DLOG(ERROR) << "Failed SetLoggedInData: " << n;
    return -9003;
  }

  std::string pub_name;
  for (int n(0); n < data_atlas.public_usernames_size(); ++n) {
    pub_name = data_atlas.public_usernames(n).own_public_username();
    session_->contact_handler_map().insert(
        std::make_pair(pub_name,
                       std::make_shared<ContactsHandler>()));
    for (int a(0); a < data_atlas.public_usernames(n).contacts_size(); ++a) {
      Contact c(data_atlas.public_usernames(n).contacts(a));
      int res(session_->contact_handler_map()[pub_name]->AddContact(c));
      DLOG(ERROR) << "Result of adding (" << pub_name << ") - "
                  << c.public_username << ": " << res;
    }
  }

  return 0;
}

int UserCredentials::SerialiseDa() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return kUserCredentialsNotInitialised;
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

  // Profile picture
  data_atlas.set_profile_picture_data_map(session_->profile_picture_data_map());

  std::vector<Contact> contacts;
  for (auto it(session_->contact_handler_map().begin());
       it != session_->contact_handler_map().end();
       ++it) {
    contacts.clear();
    PublicUsername *pub_name = data_atlas.add_public_usernames();
    pub_name->set_own_public_username((*it).first);
    (*it).second->OrderedContacts(&contacts, kAlphabetical, kRequestSent |
                                                            kPendingResponse |
                                                            kConfirmed |
                                                            kBlocked);
    for (size_t n(0); n < contacts.size(); ++n) {
      PublicContact *pc = pub_name->add_contacts();
      pc->set_public_username(contacts[n].public_username);
      pc->set_mpid_name(contacts[n].mpid_name);
      pc->set_mmid_name(contacts[n].mmid_name);
      pc->set_status(contacts[n].status);
      pc->set_rank(contacts[n].rank);
      pc->set_last_contact(contacts[n].last_contact);
      DLOG(ERROR) << "Added contact " << contacts[n].public_username
                  << " of own pubname " << (*it).first;
    }
  }

  serialised_da_.clear();
  data_atlas.SerializeToString(&serialised_da_);

  return 0;
}

bool UserCredentials::CreateUser(const std::string &username,
                                 const std::string &pin,
                                 const std::string &password) {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return false;
  }

  session_->ResetSession();
  int result = authentication_->CreateUserSysPackets(username, pin);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to create user system packets.";
    session_->ResetSession();
    return false;
  } else {
    DLOG(INFO) << "authentication_->CreateUserSysPackets DONE.";
  }

  int n = SerialiseDa();
  if (n != 0) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return false;
  }
  std::string serialised_da(serialised_da_);

  // Need different timestamps
  Sleep(boost::posix_time::milliseconds(1));
  n = SerialiseDa();
  if (n != 0) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return false;
  }
  std::string surrogate_serialised_da(serialised_da_);

  serialised_da_ = serialised_da;

  result = authentication_->CreateTmidPacket(password,
                                             serialised_da,
                                             surrogate_serialised_da);
  if (result != kSuccess) {
    DLOG(ERROR) << "Cannot create tmid packet.";
    session_->ResetSession();
    return false;
  } else {
    DLOG(INFO) << "authentication_->CreateTmidPacket DONE.";
  }

  session_->set_session_name(false);
  logged_in_ = true;
  return true;
}

int UserCredentials::CheckUserExists(const std::string &username,
                                     const std::string &pin) {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return kUserCredentialsNotInitialised;
  }
  session_->ResetSession();
  session_->set_def_con_level(kDefCon1);
  serialised_da_.clear();
  return authentication_->GetUserInfo(username, pin);
}

bool UserCredentials::ValidateUser(const std::string &password) {
  if (!initialised_) {
    DLOG(ERROR) << "CC::ValidateUser - Not initialised.";
    return false;
  }

  std::string serialised_data_atlas, surrogate_serialised_data_atlas;
  authentication_->GetMasterDataMap(password,
                          &serialised_data_atlas,
                          &surrogate_serialised_data_atlas);

  if (!serialised_data_atlas.empty()) {
    DLOG(INFO) << "UserCredentials::ValidateUser - Using TMID";
    serialised_da_ = serialised_data_atlas;
    surrogate_serialised_da_ = surrogate_serialised_data_atlas;
  } else if (!surrogate_serialised_data_atlas.empty()) {
    DLOG(INFO) << "UserCredentials::ValidateUser - Using STMID";
    surrogate_serialised_da_ = surrogate_serialised_data_atlas;
  } else {
    // Password validation failed
    DLOG(INFO) << "UserCredentials::ValidateUser - Invalid password";
    return false;
  }

  session_->set_password(password);
  session_->set_session_name(false);

  if (ParseDa() != 0) {
    DLOG(INFO) << "UserCredentials::ValidateUser - Cannot parse DA";
    return false;
  }
  logged_in_ = true;
  return true;
}

bool UserCredentials::Logout() {
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

  serialised_da_.clear();
  logging_out_ = false;
  logged_in_ = false;
  session_->ResetSession();
  return true;
}

int UserCredentials::SaveSession() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return kUserCredentialsNotInitialised;
  }

  int n = SerialiseDa();
  if (n != kSuccess) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return n;
  }

  n = authentication_->SaveSession(serialised_da_);
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

bool UserCredentials::LeaveMaidsafeNetwork() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return false;
  }
  if (authentication_->RemoveMe() == kSuccess)
    return true;

  return false;
}

std::string UserCredentials::SessionName() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return "";
  }
  return session_->session_name();
}

bool UserCredentials::ChangeUsername(const std::string &new_username) {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return false;
  }
  SerialiseDa();

  int result = authentication_->ChangeUsername(serialised_da_, new_username);
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

bool UserCredentials::ChangePin(const std::string &new_pin) {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return false;
  }
  SerialiseDa();

  int result = authentication_->ChangePin(serialised_da_, new_pin);
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

bool UserCredentials::ChangePassword(const std::string &new_password) {
  if (!initialised_) {
    DLOG(ERROR) << " Not initialised.";
    return false;
  }
  SerialiseDa();

  int result = authentication_->ChangePassword(serialised_da_, new_password);
  if (result != kSuccess) {
    DLOG(ERROR) << " Authentication failed: " << result;
    return false;
  }
  return true;
}

std::string UserCredentials::Username() {
  return session_->username();
}

std::string UserCredentials::Pin() {
  return session_->pin();
}

std::string UserCredentials::Password() {
  return session_->password();
}

std::shared_ptr<pcs::RemoteChunkStore> UserCredentials::remote_chunk_store() {
  return remote_chunk_store_;
}

std::shared_ptr<YeOldeSignalToCallbackConverter> UserCredentials::converter() {
  return converter_;
}

}  // namespace lifestuff

}  // namespace maidsafe
