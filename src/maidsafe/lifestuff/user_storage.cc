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
                         std::shared_ptr<PacketManager> packet_manager)
    : mount_status_(false),
      chunk_store_(chunk_store),
      drive_in_user_space_(),
      packet_manager_(packet_manager),
      session_(),
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
  fs::create_directories(g_mount_dir_);
  boost::thread(std::bind(&MaidDriveInUserSpace::Mount, drive_in_user_space_,
                          g_mount_dir_, "LifeStuff Drive"));
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
                            std::string *serialised_data_map) {
  return drive_in_user_space_->GetDataMap(absolute_path,
                                          serialised_data_map);
}

int UserStorage::InsertDataMap(const fs::path &absolute_path,
                               const std::string &serialised_data_map) {
  return drive_in_user_space_->InsertDataMap(absolute_path,
                                             serialised_data_map);
}

int UserStorage::ShareExisting(const fs::path &/*absolute_path*/,
                               std::string * /*directory_id*/,
                               std::string * /*share_id*/) {
                                                                        return 9999;
//  return drive_in_user_space_->SetShareDetails(absolute_path,
//                                               directory_id,
//                                               share_id);
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

}  // namespace lifestuff

}  // namespace maidsafe
