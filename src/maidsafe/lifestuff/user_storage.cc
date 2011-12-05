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

UserStorage::UserStorage(ChunkStorePtr chunk_store)
    : mount_status_(false),
      chunk_store_(chunk_store),
      listing_handler_(),
      drive_in_user_space_(),
      g_mount_dir_() {}

void UserStorage::MountDrive(const fs::path &mount_dir_path,
                             const std::string &session_name,
                             std::shared_ptr<Session> session,
                             bool creation) {
  if (mount_status_)
    return;
  if (!fs::exists(mount_dir_path))
    fs::create_directory(mount_dir_path);
  listing_handler_.reset(new DirectoryListingHandler(chunk_store_));

  int n(0);
  if (creation) {
    session->set_unique_user_id(crypto::Hash<crypto::SHA512>(session_name));
    n = listing_handler_->Initialise(session->unique_user_id(), "");
    session->set_root_parent_id(listing_handler_->root_parent_id());
  } else {
    n = listing_handler_->Initialise(session->unique_user_id(),
                                     session->root_parent_id());
  }
  DLOG(ERROR) << "DLH Init: " << n;

  drive_in_user_space_.reset(new MaidDriveInUserSpace(chunk_store_,
                                                      listing_handler_));
#ifdef WIN32
  std::uint32_t drive_letters, mask = 0x4, count = 2;
  drive_letters = GetLogicalDrives();
  while ((drive_letters & mask) != 0) {
    mask <<= 1;
    ++count;
  }
  if (count > 25)
    DLOG(ERROR) << "No available drive letters:";

  char drive_name[3] = {'A' + static_cast<char>(count), ':', '\0'};
  g_mount_dir_ = drive_name;
  std::static_pointer_cast<MaidDriveInUserSpace>(drive_in_user_space_)->Init();
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

int UserStorage::ShareExisting(const fs::path &absolute_path,
                               std::string *directory_id,
                               std::string *share_id) {
  return drive_in_user_space_->ShareExisting(absolute_path,
                                             directory_id,
                                             share_id);
}

int UserStorage::InsertShare(const fs::path &absolute_path,
                             const std::string &directory_id,
                             const std::string &share_id) {
  return drive_in_user_space_->InsertShare(absolute_path,
                                           directory_id,
                                           share_id);
}

}  // namespace lifestuff

}  // namespace maidsafe

