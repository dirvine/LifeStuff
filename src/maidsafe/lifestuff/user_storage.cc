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

#include "maidsafe/common/buffered_chunk_store.h"
#include "maidsafe/common/hashable_chunk_validation.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/version.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

UserStorage::UserStorage()
    : mount_status_(false),
      asio_service_(),
      work_(),
      thread_group_(),
      chunk_store_(),
      listing_handler_(),
      drive_in_user_space_(),
      g_mount_dir_() {}

void UserStorage::MountDrive(fs::path mount_dir_path,
                             std::string session_name) {
  if (mount_status_)
    return;
  if (!fs::exists(mount_dir_path))
    fs::create_directory(mount_dir_path);
  fs::path chunkstore_dir(mount_dir_path / "ChunkStore");
  fs::path meta_data_dir(mount_dir_path / "MetaData" / session_name);
  work_.reset(new boost::asio::io_service::work(asio_service_));
  for (int i = 0; i < 3; ++i)
    thread_group_.create_thread(std::bind(static_cast<
        std::size_t(boost::asio::io_service::*)()>
            (&boost::asio::io_service::run), &asio_service_));
  chunk_store_.reset(new BufferedChunkStore(
      false, std::shared_ptr<ChunkValidation>(
          new HashableChunkValidation<crypto::SHA512>), asio_service_));
  listing_handler_.reset(new DirectoryListingHandler(meta_data_dir,
                                                     chunk_store_));
  drive_in_user_space_.reset(new MaidDriveInUserSpace(chunk_store_,
                                                      listing_handler_));
  std::static_pointer_cast<BufferedChunkStore>(
      chunk_store_)->Init(chunkstore_dir);

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
  work_.reset();
  asio_service_.stop();
  thread_group_.join_all();
  mount_status_ = false;
}

fs::path UserStorage::g_mount_dir() {
  return g_mount_dir_;
}

bool UserStorage::mount_status() {
  return mount_status_;
}
}  // namespace lifestuff

}  // namespace maidsafe

