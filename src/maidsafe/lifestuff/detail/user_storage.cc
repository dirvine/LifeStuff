/***************************************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use.  The use of this code is governed by the licence file licence.txt found in the root of    *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit         *
 *  written permission of the board of directors of MaidSafe.net.                                  *
 **************************************************************************************************/

#include "maidsafe/lifestuff/detail/user_storage.h"

#include <limits>
#include <list>
#include <string>

#include "boost/filesystem.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/self_encryptor.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/detail/data_atlas.pb.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {
namespace lifestuff {

const NonEmptyString kDriveLogo("Lifestuff Drive");
const boost::filesystem::path kLifeStuffConfigPath("LifeStuff-Config");

UserStorage::UserStorage()
    : mount_status_(false),
      mount_path_(),
      drive_(),
      mount_thread_() {}

void UserStorage::MountDrive(ClientNfs& client_nfs, Session& session) {
  if (mount_status_)
    return;
  boost::filesystem::path data_store_path(
      GetHomeDir() / kAppHomeDirectory / session.session_name().string());
  DiskUsage disk_usage(10995116277760);  // arbitrary 10GB
#ifdef WIN32
  std::uint32_t drive_letters, mask = 0x4, count = 2;
  drive_letters = GetLogicalDrives();
  while ((drive_letters & mask) != 0) {
    mask <<= 1;
    ++count;
  }
  if (count > 25) {
    LOG(kError) << "No available drive letters.";
    return;
  }
  char drive_name[3] = {'A' + static_cast<char>(count), ':', '\0'};
  mount_path_ = drive_name;
  data_store_.reset(new PermanentStore(data_store_path, disk_usage));
  drive_.reset(new MaidDrive(client_nfs,
                             *data_store_,
                             session.passport().Get<Maid>(true),
                             session.unique_user_id(),
                             session.root_parent_id(),
                             mount_path_,
                             kDriveLogo.string(),
                             session.max_space(),
                             session.used_space()));
  mount_status_ = true;
  if (session.root_parent_id() != drive_->root_parent_id())
    session.set_root_parent_id(drive_->root_parent_id());
#else
  boost::system::error_code error_code;
  if (!fs::exists(mount_path_)) {
    fs::create_directories(mount_path_, error_code);
    if (error_code) {
      LOG(kError) << "Failed to create mount dir(" << mount_path_ << "): "
                  << error_code.message();
    }
  }
  drive_.reset(new MaidDrive(client_nfs,
                             *data_store_,
                             session.passport().Get<Maid>(true),
                             session.unique_user_id(),
                             session.root_parent_id(),
                             mount_path_,
                             kDriveLogo.string(),
                             session.max_space(),
                             session.used_space()));
  mount_thread_ = std::move(std::thread([this] {
                                          drive_->Mount();
                                        }));
  mount_status_ = drive_->WaitUntilMounted();
#endif
}

void UserStorage::UnMountDrive(Session& session) {
  if (!mount_status_)
    return;
  int64_t max_space(0), used_space(0);
#ifdef WIN32
  drive_->Unmount(max_space, used_space);
#else
  drive_->Unmount(max_space, used_space);
  drive_->WaitUntilUnMounted();
  mount_thread_.join();
  boost::system::error_code error_code;
  fs::remove_all(mount_path_, error_code);
#endif
  mount_status_ = false;
  session.set_max_space(max_space);
  session.set_used_space(used_space);
}

boost::filesystem::path UserStorage::mount_path() {
#ifdef WIN32
  return mount_path_ / fs::path("/").make_preferred();
#else
  return mount_path_;
#endif
}

boost::filesystem::path UserStorage::owner_path() {
  return mount_path() / kOwner;
}

bool UserStorage::mount_status() {
  return mount_status_;
}

}  // namespace lifestuff
}  // namespace maidsafe
