/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Version:      1.0
* Created:      2011-04-18
* Author:       Team
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

#include "maidsafe/lifestuff/user_storage.h"

#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/version.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

UserStorage::UserStorage(std::shared_ptr<ChunkStore> chunk_store,
                         std::shared_ptr<PacketManager> packet_manager,
                         std::shared_ptr<MessageHandler> message_handler)
    : mount_status_(false),
      chunk_store_(chunk_store),
      drive_in_user_space_(),
      packet_manager_(packet_manager),
      session_(),
      message_handler_(message_handler),
      g_mount_dir_() {}

void UserStorage::MountDrive(const fs::path &mount_dir_path,
                             const std::string &session_name,
                             std::shared_ptr<Session> session,
                             bool creation) {
  if (mount_status_)
    return;
  if (!fs::exists(mount_dir_path))
    fs::create_directory(mount_dir_path);

  session_ = session;
  asymm::Keys key_ring;
  key_ring.identity = session->passport_->PacketName(passport::kPmid, true);
  key_ring.public_key =
      session->passport_->SignaturePacketValue(passport::kPmid, true);
  key_ring.private_key = session->passport_->PacketPrivateKey(passport::kPmid,
                                                              true);
  key_ring.validation_token =
      session->passport_->PacketSignature(passport::kPmid, true);
  drive_in_user_space_.reset(new MaidDriveInUserSpace(chunk_store_, key_ring));

  int n(0);
  if (creation) {
    session->set_unique_user_id(crypto::Hash<crypto::SHA512>(session_name));
    n = drive_in_user_space_->Init(session->unique_user_id(), "");
    session->set_root_parent_id(drive_in_user_space_->root_parent_id());
  } else {
    n = drive_in_user_space_->Init(session->unique_user_id(),
                                   session->root_parent_id());
  }
  DLOG(INFO) << "drive_in_user_space_ Init: " << n;

#ifdef WIN32
  std::uint32_t drive_letters, mask = 0x4, count = 2;
  drive_letters = GetLogicalDrives();
  while ((drive_letters & mask) != 0) {
    mask <<= 1;
    ++count;
  }
  if (count > 25) {
    DLOG(ERROR) << "No available drive letters:";
    return;
  }

  char drive_name[3] = {'A' + static_cast<char>(count), ':', '\0'};
  g_mount_dir_ = drive_name;
  drive_in_user_space_->Mount(g_mount_dir_, L"LifeStuff Drive");
#else
  g_mount_dir_ = mount_dir_path / session_name;
  boost::system::error_code ec;
  if (fs::exists(g_mount_dir_, ec))
    fs::remove_all(g_mount_dir_, ec);
  fs::create_directories(g_mount_dir_, ec);
  boost::thread(std::bind(&MaidDriveInUserSpace::Mount,
                          drive_in_user_space_,
                          g_mount_dir_,
                          "LifeStuff Drive"));
  drive_in_user_space_->WaitUntilMounted();
#endif
  mount_status_ = true;
}

void UserStorage::UnMountDrive() {
  if (!mount_status_)
    return;
#ifdef WIN32
  std::static_pointer_cast<MaidDriveInUserSpace>(
      drive_in_user_space_)->CleanUp();
#else
  drive_in_user_space_->Unmount();
  drive_in_user_space_->WaitUntilUnMounted();
  boost::system::error_code error_code;
  fs::remove_all(g_mount_dir_, error_code);
#endif
  mount_status_ = false;
}

fs::path UserStorage::g_mount_dir() {
  return g_mount_dir_;
}

bool UserStorage::mount_status() {
  return mount_status_;
}

int UserStorage::GetDataMap(const fs::path &absolute_path,
                            std::string *serialised_data_map) const {
  return drive_in_user_space_->GetDataMap(absolute_path, serialised_data_map);
}

int UserStorage::InsertDataMap(const fs::path &absolute_path,
                               const std::string &serialised_data_map) {
  return drive_in_user_space_->InsertDataMap(absolute_path,
                                             serialised_data_map);
}

int UserStorage::SetShareDetails(const fs::path &absolute_path,
                                 const std::string &share_id,
                                 const asymm::Keys &share_keyring,
                                 const std::string &this_user_id,
                                 std::string *directory_id) {
  return drive_in_user_space_->SetShareDetails(absolute_path,
                                               share_id,
                                               share_keyring,
                                               this_user_id,
                                               directory_id);
}

int UserStorage::InsertShare(const fs::path &absolute_path,
                             const std::string &directory_id,
                             const std::string &share_id,
                             const asymm::Keys &share_keyring) {
  return drive_in_user_space_->InsertShare(absolute_path,
                                           directory_id,
                                           share_id,
                                           share_keyring);
}

int UserStorage::StopShare(const fs::path &absolute_path){
  drive::ShareData old_shared_data(
      drive_in_user_space_->FetchSharedData(absolute_path));

  std::string directory_id;
  int result(drive_in_user_space_->SetShareDetails(absolute_path,
                                                   "",
                                                   asymm::PrivateKey(),
                                                   session_->unique_user_id(),
                                                   &directory_id));
  if (result != kSuccess)
    return result;

  std::vector<int> results;
  results.push_back(kPendingResult);
  packet_manager_->DeletePacket(ComposeSignaturePacketName(
                                    old_shared_data.identity),
                                old_shared_data.identity,
                                std::bind(&SendContactInfoCallback,
                                          std::placeholders::_1,
                                          &mutex, &cond_var, &results[0]));
  int result(AwaitingResponse(mutex, cond_var, results));
  if (result != kSuccess)
    return result;
  if (results[0] != kSuccess) {
    DLOG(ERROR) << "Failed to remove packet.  Packet 1 : " << results[0];
    return kDeletePacketFailure;
  }

  return kSuccess;
}

int UserStorage::LeaveShare(const fs::path &absolute_path){
  std::string directory_id;
  return drive_in_user_space_->SetShareDetails(absolute_path,
                                               "",
                                               asymm::PrivateKey(),
                                               session_->unique_user_id(),
                                               &directory_id);
}

int UserStorage::CreateShare(const fs::path &absolute_path,
                             std::map<Contact, bool> contacts,
                             std::string *directory_id,
                             std::string *share_id) {
  *share_id = crypto::Hash<crypto::SHA512>(absolute_path.string());

  std::vector<pki::SignaturePacketPtr> signature_packets;
  pki::CreateChainedId(&signature_packets, 2);
  // Store packets
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);
  results.push_back(kPendingResult);
  packet_manager_->StorePacket(ComposeSignaturePacketName(
                                  signature_packets[1]->name()),
                               ComposeSignaturePacketValue(
                                  *signature_packets[1]),
                               signature_packets[1]->name(),
                               std::bind(&SendContactInfoCallback,
                                         std::placeholders::_1,
                                         &mutex, &cond_var, &results[1]));
  packet_manager_->StorePacket(ComposeSignaturePacketName(
                                  signature_packets[0]->name()),
                               ComposeSignaturePacketValue(
                                  *signature_packets[0]),
                               signature_packets[1]->name(),
                               std::bind(&SendContactInfoCallback,
                                         std::placeholders::_1,
                                         &mutex, &cond_var, &results[0]));
  int result(AwaitingResponse(mutex, cond_var, results));
  if (result != kSuccess)
    return result;
  if (results[0] != kSuccess || results[1] != kSuccess) {
    DLOG(ERROR) << "Failed to store packets.  Packet 1 : " << results[0]
                << "   Packet 2 : " << results[1];
    return kStorePacketFailure;
  }

  asymm::Keys key_ring;
  key_ring.identity = signature_packets[1]->name();
  key_ring.public_key = signature_packets[1]->value();
  key_ring.private_key = signature_packets[1]->private_key();
  key_ring.validation_token = signature_packets[1]->signature();
  result = drive_in_user_space_->SetShareDetails(absolute_path,
                                                 *share_id,
                                                 key_ring,
                                                 session_->unique_user_id(),
                                                 directory_id);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed in creating share of " << absolute_path.string()
                << ", with result of : " << result;
    return result;
  }

  for (auto it = contacts.begin(); it != contacts.end(); ++it) {
    // AddShareUser will send out the informing msg
    int result(drive_in_user_space_->AddShareUser(absolute_path,
                                                  (*it).first.public_username,
                                                  (*it).second));
    if (result != kSuccess)
      DLOG(ERROR) << "Failed in add contact of " << (*it).first.public_username
                  << "  into the share of " << absolute_path.string()
                  << ", with result of : " << result;
  }
  return kSuccess;
}

int UserStorage::AddShareUser(const fs::path &absolute_path,
                              const std::string &user_id,
                              bool admin_rights) {
  int result(drive_in_user_space_->AddShareUser(absolute_path,
                                                user_id,
                                                admin_rights));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed in add contact of " << user_id
                << "  into the share of " << absolute_path.string()
                << ", with result of : " << result;
    return result;
  }
  drive::ShareData old_shared_data(
      drive_in_user_space_->FetchSharedData(absolute_path));
  if (!admin_rights)
    old_shared_data.keyring.private_key = asymm::PrivateKey();
  pca::Message sent;
  sent.set_type(pca::Message::kSharedDirectory);
  sent.set_parent_id(RandomString(64));
  sent.set_sender_public_username(session_->unique_user_id());
  sent.set_subject("new sharing");
  sent.add_content(old_shared_data.SerializeAsString());
  sent.set_id(RandomUint32());
  result = message_handler_.Send(session_->unique_user_id(),
                                 user_id,
                                 sent);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed in informing contact " << user_id
                << "  of the sharing of " << absolute_path.string()
                << ", with result of : " << result;
    return result;
  }
  return kSuccess;
}

void UserStorage::GetAllShareUsers(
    const fs::path &absolute_path,
    std::map<std::string, bool> *all_share_users) const {
  return drive_in_user_space_->GetAllShareUsers(absolute_path, all_share_users);
}

int UserStorage::RemoveShareUser(const fs::path &absolute_path,
                                 const std::vector<std::string> &user_ids) {
  for (auto it = user_ids.begin(); it != user_ids.end(); ++it) {
    int result(drive_in_user_space_->RemoveShareUser(absolute_path, *it));
    if (result != kSuccess)
      DLOG(ERROR) << "Failed in removing contact " << *it;
  }

  std::string new_share_id(RandomString(512));
  drive::ShareData old_shared_data(
      drive_in_user_space_->FetchSharedData(absolute_path));

  std::vector<pki::SignaturePacketPtr> signature_packets;
  pki::CreateChainedId(&signature_packets, 1);
  // Store packets
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);
  packet_manager_->StorePacket(ComposeSignaturePacketName(
                                  signature_packets[0]->name()),
                               ComposeSignaturePacketValue(
                                  *signature_packets[0]),
                               signature_packets[0]->name(),
                               std::bind(&SendContactInfoCallback,
                                         std::placeholders::_1,
                                         &mutex, &cond_var, &results[0]));
  int result(AwaitingResponse(mutex, cond_var, results));
  if (result != kSuccess)
    return result;
  if (results[0] != kSuccess) {
    DLOG(ERROR) << "Failed to store packets.  Packet 1 : " << results[0];
    return kStorePacketFailure;
  }

  asymm::Keys key_ring;
  key_ring.identity = signature_packets[0]->name();
  key_ring.public_key = signature_packets[0]->value();
  key_ring.private_key = signature_packets[0]->private_key();
  key_ring.validation_token = signature_packets[0]->signature();
  std::string directory_id;
  result = drive_in_user_space_->SetShareDetails(absolute_path,
                                                 new_share_id,
                                                 key_ring,
                                                 session_->unique_user_id(),
                                                 &directory_id);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed in creating share of " << absolute_path.string()
                << ", with result of : " << result;
    return result;
  }

  results.clear();
  results.push_back(kPendingResult);
  packet_manager_->DeletePacket(ComposeSignaturePacketName(
                                    old_shared_data.identity),
                                old_shared_data.identity,
                                std::bind(&SendContactInfoCallback,
                                          std::placeholders::_1,
                                          &mutex, &cond_var, &results[0]));
  int result(AwaitingResponse(mutex, cond_var, results));
  if (result != kSuccess)
    return result;
  if (results[0] != kSuccess) {
    DLOG(ERROR) << "Failed to remove packet.  Packet 1 : " << results[0];
    return kDeletePacketFailure;
  }

  drive::ShareData new_shared_data(new_share_id, absolute_path, key_ring);
  std::map<std::string, bool> contacts;
  drive_in_user_space_->GetAllShareUsers(absolute_path, &contacts);
  pca::Message sent_admin;
  sent_admin.set_type(pca::Message::kSharedDirectory);
  sent_admin.set_parent_id(RandomString(64));
  sent_admin.set_sender_public_username(session_->unique_user_id());
  sent_admin.set_subject("moving an existing sharing");

  pca::Message sent_normal(sent_admin);
  sent_admin.add_content(old_shared_data.SerializeAsString());
  sent_admin.add_content(new_shared_data.SerializeAsString());
  old_shared_data.keyring.private_key = asymm::PrivateKey();
  new_shared_data.keyring.private_key = asymm::PrivateKey();
  sent_normal.add_content(old_shared_data.SerializeAsString());
  sent_normal.add_content(new_shared_data.SerializeAsString());

  int result;
  for (auto it = contacts.begin(); it != contacts.end(); ++it) {
    if ((*it).second) {
      sent_admin.set_id(RandomUint32());
      result = message_handler_.Send(session_->unique_user_id(),
                                     (*it).first,
                                     sent_admin);
    } else {
      sent_normal.set_id(RandomUint32());
      result = message_handler_.Send(session_->unique_user_id(),
                                     (*it).first,
                                     sent_normal);
    }
    if (result != kSuccess)
      DLOG(ERROR) << "Failed in informing contact " << (*it).first
                  << "  of the moving share of " << absolute_path.string()
                  << ", with result of : " << result;
  }
  return kSuccess;
}

int UserStorage::GetShareUsersRights(const fs::path &absolute_path,
                                     const std::string &user_id,
                                     bool *admin_rights) const {
  return drive_in_user_space_->GetShareUsersRights(absolute_path,
                                                   user_id,
                                                   admin_rights);
}

int UserStorage::SetShareUsersRights(const fs::path &absolute_path,
                                     const std::string &user_id,
                                     bool admin_rights) {
  bool old_admin_right;
  drive_in_user_space_->GetShareUsersRights(absolute_path,
                                            user_id,
                                            &old_admin_right);
  int result(drive_in_user_space_->SetShareUsersRights(absolute_path,
                                                       user_id,
                                                       admin_rights));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed in seting admin right for contact " << user_id
                << "  of the sharing of " << absolute_path.string()
                << ", with result of : " << result;
    return result;
  }
  drive::ShareData old_shared_data(
      drive_in_user_space_->FetchSharedData(absolute_path));
  if ((!old_admin_right) && admin_rights) {
    // in case of upgrading : just inform the contact the private_key
    pca::Message sent;
    sent.set_type(pca::Message::kSharedDirectory);
    sent.set_parent_id(RandomString(64));
    sent.set_sender_public_username(session_->unique_user_id());
    sent.set_subject("upgrading to admin right");
    sent.add_content(old_shared_data.SerializeAsString());
    sent.set_id(RandomUint32());
    int result(message_handler_.Send(session_->unique_user_id(),
                                     user_id,
                                     sent));
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed in informing contact " << user_id
                  << "  of the upgrading to admin right "
                  << ", with result of : " << result;
      return result;
    }
  } else if (old_admin_right && (!admin_rights)) {
    // in case of downgrading : generate new share_id/key and inform all
    // i.e. remove that contact at first then add it back
    int result(RemoveShareUser(absolute_path, user_id));
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed in remove contact " << user_id
                  << "  during the downgrading "
                  << ", with result of : " << result;
      return result;
    }
    result = AddShareUser(absolute_path, user_id, admin_rights);
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed in add contact " << user_id
                  << "  during the downgrading "
                  << ", with result of : " << result;
      return result;
    }
  }

  return kSuccess;
}

int UserStorage::GetNotes(const fs::path &absolute_path,
                          std::vector<std::string> *notes) const {
  return drive_in_user_space_->GetNotes(absolute_path, notes);
}

int UserStorage::AddNote(const fs::path &absolute_path,
                         const std::string &note) {
  return drive_in_user_space_->AddNote(absolute_path, note);
}

int UserStorage::ReadHiddenFile(const fs::path &absolute_path,
                                std::string *content) const {
  return drive_in_user_space_->ReadHiddenFile(absolute_path, content);
}

int UserStorage::WriteHiddenFile(const fs::path &absolute_path,
                                 const std::string &content,
                                 bool overwrite_existing) {
  return drive_in_user_space_->WriteHiddenFile(absolute_path,
                                               content,
                                               overwrite_existing);
}

int UserStorage::DeleteHiddenFile(const fs::path &absolute_path) {
  return drive_in_user_space_->DeleteHiddenFile(absolute_path);
}

bs2::connection UserStorage::ConnectToDriveChanged(
    drive::DriveChangedSlotPtr slot) const {
  return drive_in_user_space_->ConnectToDriveChanged(slot);
}

bs2::connection UserStorage::ConnectToShareChanged(
    drive::ShareChangedSlotPtr slot) const {
  return drive_in_user_space_->ConnectToShareChanged(slot);
}


}  // namespace lifestuff

}  // namespace maidsafe
