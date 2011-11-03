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

#ifndef MAIDSAFE_LIFESTUFF_USER_STORAGE_H_
#define MAIDSAFE_LIFESTUFF_USER_STORAGE_H_

#include <string>
#include "boost/filesystem.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/drive/directory_listing_handler.h"
#include "maidsafe/lifestuff/version.h"

#ifdef WIN32
#  include "maidsafe/drive/win_drive.h"
#else
#  include "maidsafe/drive/unix_drive.h"
#endif


#if MAIDSAFE_LIFESTUFF_VERSION != 109
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif

#ifdef WIN32
  typedef maidsafe::CbfsDriveInUserSpace MaidDriveInUserSpace;
#else
  typedef maidsafe::FuseDriveInUserSpace MaidDriveInUserSpace;
#endif

namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

// Credentials operation interface
class UserStorage {
 public:
  UserStorage();
  virtual ~UserStorage() {}

  virtual void MountDrive(fs::path mount_dir_path, std::string session_name);
  virtual void UnMountDrive();
  virtual fs::path g_mount_dir();
  virtual bool mount_status();

 private:
  bool mount_status_;
  boost::asio::io_service asio_service_;
  std::shared_ptr<boost::asio::io_service::work> work_;
  boost::thread_group thread_group_;
  ChunkStorePtr chunk_store_;
  std::shared_ptr<DirectoryListingHandler> listing_handler_;
  std::shared_ptr<MaidDriveInUserSpace> drive_in_user_space_;
  fs::path g_mount_dir_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_USER_STORAGE_H_
