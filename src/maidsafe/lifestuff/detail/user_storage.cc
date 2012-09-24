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

#include "maidsafe/lifestuff/detail/user_storage.h"

#include <limits>
#include <list>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/utils/utilities.h"

#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/self_encryptor.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/message_handler.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace args = std::placeholders;
namespace fs = boost::filesystem;
namespace utils = maidsafe::priv::utilities;

namespace maidsafe {

namespace lifestuff {

UserStorage::UserStorage(std::shared_ptr<pcs::RemoteChunkStore> chunk_store,
                         MessageHandler& message_handler)
    : mount_status_(false),
      chunk_store_(chunk_store),
      drive_in_user_space_(),
      share_renamed_function_(),
      share_changed_function_(),
      session_(),
      message_handler_(message_handler),
      mount_dir_(),
      mount_thread_() {}

void UserStorage::MountDrive(const fs::path& mount_dir_path,
                             Session* session,
                             bool creation,
                             bool read_only,
                             const std::string& drive_logo) {
  if (mount_status_) {
    LOG(kInfo) << "Already mounted.";
    return;
  }
  if (!fs::exists(mount_dir_path))
    fs::create_directory(mount_dir_path);

  session_ = session;
  asymm::Keys key_ring(session->passport().SignaturePacketDetails(passport::kPmid, true));
  drive_in_user_space_.reset(new MaidDriveInUserSpace(*chunk_store_, key_ring));

  int result(kGeneralError);
  if (creation) {
    session->set_unique_user_id(crypto::Hash<crypto::SHA512>(session->session_name()));
    result = drive_in_user_space_->Init(session->unique_user_id(), "");
    session->set_root_parent_id(drive_in_user_space_->root_parent_id());
  } else {
    result = drive_in_user_space_->Init(session->unique_user_id(), session->root_parent_id());
  }

  if (result != kSuccess) {
    LOG(kError) << "Failed to Init Drive: " << result;
    return;
  }

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
  mount_dir_ = drive_name;
  result = drive_in_user_space_->Mount(mount_dir_,
                                       drive_logo,
                                       session->max_space(),
                                       session->used_space(),
                                       read_only);
  if (result != kSuccess) {
    LOG(kError) << "Failed to Mount Drive: " << result;
    return;
  }
  mount_status_ = true;
#else
  mount_dir_ = mount_dir_path;
  mount_thread_ = std::move(std::thread([this, drive_logo, read_only] {
                                          drive_in_user_space_->Mount(mount_dir_,
                                                                      drive_logo,
                                                                      session_->max_space(),
                                                                      session_->used_space(),
                                                                      read_only);
                                        }));
  mount_status_ = drive_in_user_space_->WaitUntilMounted();
#endif
  ConnectToShareRenamedSignal(share_renamed_function_);
  ConnectToShareChangedSignal(share_changed_function_);
}

void UserStorage::UnMountDrive() {
  if (!mount_status_)
    return;
  int64_t max_space(0), used_space(0);
#ifdef WIN32
  std::static_pointer_cast<MaidDriveInUserSpace>(drive_in_user_space_)->Unmount(max_space,
                                                                                used_space);
#else
  drive_in_user_space_->Unmount(max_space, used_space);
  drive_in_user_space_->WaitUntilUnMounted();
  mount_thread_.join();
  boost::system::error_code error_code;
  fs::remove_all(mount_dir_, error_code);
#endif
  session_->set_max_space(max_space);  // unnecessary
  session_->set_used_space(used_space);
  mount_status_ = false;
}

fs::path UserStorage::mount_dir() {
#ifdef WIN32
  return mount_dir_ / fs::path("/").make_preferred();
#else
  return mount_dir_;
#endif
}

bool UserStorage::mount_status() {
  return mount_status_;
}

bool UserStorage::ParseAndSaveDataMap(const std::string& file_name,
                                      const std::string& serialised_data_map,
                                      std::string* data_map_hash) {
  encrypt::DataMapPtr data_map(ParseSerialisedDataMap(serialised_data_map));
  if (!data_map) {
    LOG(kError) << "Serialised DM doesn't parse.";
    return false;
  }

  *data_map_hash = EncodeToBase32(crypto::Hash<crypto::SHA1>(serialised_data_map)) +
                                  boost::lexical_cast<std::string>(
                                      GetDurationSinceEpoch().total_microseconds());
  std::string filename_data(PutFilenameData(file_name));
  if (filename_data.empty()) {
    LOG(kError) << "No suitable filename given: " << file_name;
    return false;
  }

  int result(WriteHiddenFile(mount_dir() / std::string(*data_map_hash + kHiddenFileExtension),
                             filename_data + serialised_data_map,
                             true));
  if (result != kSuccess) {
    LOG(kError) << "Failed to create file: " << result;
    return false;
  }

  return true;
}

int UserStorage::GetDataMap(const fs::path& absolute_path, std::string* serialised_data_map) {
  return drive_in_user_space_->GetDataMap(drive::RelativePath(mount_dir(), absolute_path),
                                          serialised_data_map);
}

int UserStorage::InsertDataMap(const fs::path& absolute_path,
                               const std::string& serialised_data_map) {
  return drive_in_user_space_->InsertDataMap(drive::RelativePath(mount_dir(), absolute_path),
                                             serialised_data_map);
}

bool UserStorage::SavePrivateShareData(const std::string& serialised_share_data,
                                       const std::string& share_id) {
  fs::path store_path(mount_dir() / kSharedStuff);
  if (!VerifyOrCreatePath(store_path)) {
    LOG(kError) << "Failed to verify or create path to shared stuff.";
    return false;
  }

  std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)) +
                        kHiddenFileExtension);
  int result(WriteHiddenFile(store_path / temp_name, serialised_share_data, true));
  if (result != kSuccess) {
    LOG(kError) << "Failed to create file: " << result;
    return false;
  }
  return true;
}

bool UserStorage::DeletePrivateShareData(const std::string& share_id) {
  fs::path store_path(mount_dir() / kSharedStuff);
  std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)) +
                        drive::kMsHidden.string());
  int result(DeleteHiddenFile(store_path / temp_name));
  if (result != kSuccess) {
    LOG(kError) << "Failed to delete private share data.";
    return false;
  }
  return true;
}

bool UserStorage::SaveOpenShareData(const std::string& serialised_share_data,
                                    const std::string& share_id) {
  fs::path store_path(mount_dir() / kSharedStuff);
  if (!VerifyOrCreatePath(store_path)) {
    LOG(kError) << "Failed to verify or create path to shared stuff.";
    return false;
  }

  std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)) +
                        kHiddenFileExtension);
  int result(WriteHiddenFile(store_path / temp_name, serialised_share_data, true));
  if (result != kSuccess) {
    LOG(kError) << "Failed to create file: " << result;
    return false;
  }
  return true;
}

int UserStorage::CreateShare(const std::string& sender_public_id,
                             const fs::path& drive_path,
                             const fs::path& share_path,
                             const StringIntMap& contacts,
                             bool private_share,
                             StringIntMap* contacts_results) {
  int result(kSuccess);
  if (!drive_path.empty()) {
    /*result = drive_in_user_space_->MoveDirectory(drive_path, share_path);
    if (result != kSuccess) {
      LOG(kError) << "Failed to create share directory " << share_path;
      return result;
    }*/
    boost::system::error_code error_code;
    fs::create_directory(share_path, error_code);
    if (error_code) {
      LOG(kError) << "Failed creating directory " << share_path << ": " << error_code.message();
      return kGeneralError;
    }
    result = CopyDirectoryContent(drive_path, share_path);
    if (result != kSuccess) {
      LOG(kError) << "Failed to copy share directory content " << share_path;
      return result;
    }
    fs::remove_all(drive_path, error_code);
    if (error_code) {
      LOG(kError) << "Failed deleting directory " << drive_path << ": " << error_code.message();
    }
  } else {
    boost::system::error_code error_code;
    fs::create_directory(share_path, error_code);
    if (error_code) {
      LOG(kError) << "Failed creating directory " << share_path << ": " << error_code.message();
      return kGeneralError;
    }
  }

  std::string share_id(crypto::Hash<crypto::SHA512>(share_path.string()));
  asymm::Keys key_ring;
  result = passport::CreateSignaturePacket(key_ring);
  if (result != kSuccess) {
    LOG(kError) << "failed to create private share keys.";
    return result;
  }

  // Store packets
  std::mutex mutex;
  std::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(priv::utilities::kPendingResult);

  std::string packet_id(ComposeSignaturePacketName(key_ring.identity));
  VoidFunctionOneBool callback([&] (const bool& response) {
                                 utils::ChunkStoreOperationCallback(response,
                                                                    &mutex,
                                                                    &cond_var,
                                                                    &results[0]);
                               });
  asymm::Keys key_shared(key_ring);
  if (!chunk_store_->Store(packet_id,
                           utils::SerialisedSignedData(key_ring),
                           callback,
                           key_shared)) {
    std::unique_lock<std::mutex> lock(mutex);
    results[0] = kRemoteChunkStoreFailure;
  }
  result = utils::WaitForResults(mutex, cond_var, results);
  if (result != kSuccess) {
    LOG(kError) << "Timed out waiting for the response";
    return result;
  }

  if (results[0] != kSuccess) {
    LOG(kError) << "Failed to store packet.  Packet 1 : " << results[0];
    return results[0];
  }
  std::string directory_id;
  result = drive_in_user_space_->SetShareDetails(drive::RelativePath(mount_dir(), share_path),
                                                 share_id,
                                                 key_ring,
                                                 sender_public_id,
                                                 private_share,
                                                 &directory_id);
  if (result != kSuccess) {
    LOG(kError) << "Failed in creating share of " << share_path.string()
                << ", with result of : " << result;
    return result;
  }
  // AddShareUser will send out the informing msg to contacts
  result = AddShareUsers(sender_public_id, share_path, contacts, private_share, contacts_results);
  if (result != kSuccess) {
    LOG(kError) << "Failed to add users to share at " << share_path;
    return result;
  }
  return kSuccess;
}

int UserStorage::CreateOpenShare(const std::string& sender_public_id,
                                 const fs::path& drive_path,
                                 const fs::path& share_path,
                                 const StringIntMap& contacts,
                                 StringIntMap* contacts_results) {
  int result(kSuccess);
  if (!drive_path.empty()) {
    /*result = drive_in_user_space_->MoveDirectory(drive_path, share_path);
    if (result != kSuccess) {
      LOG(kError) << "Failed to create share directory " << share_path;
      return result;
    }*/
    boost::system::error_code error_code;
    fs::create_directory(share_path, error_code);
    if (error_code) {
      LOG(kError) << "Failed creating directory " << share_path << ": " << error_code.message();
      return kGeneralError;
    }
    result = CopyDirectoryContent(drive_path, share_path);
    if (result != kSuccess) {
      LOG(kError) << "Failed to copy share directory content " << share_path;
      return result;
    }
    fs::remove_all(drive_path, error_code);
    if (error_code) {
      LOG(kError) << "Failed deleting directory " << drive_path << ": " << error_code.message();
    }
  } else {
    boost::system::error_code error_code;
    fs::create_directory(share_path, error_code);
    if (error_code) {
      LOG(kError) << "Failed creating directory " << share_path << ": " << error_code.message();
      return kGeneralError;
    }
  }
  std::string share_id(crypto::Hash<crypto::SHA512>(share_path.string()));
  asymm::Keys key_ring;
  result = passport::CreateSignaturePacket(key_ring);
  if (result != kSuccess) {
    LOG(kError) << "failed to create open share keys.";
    return result;
  }

  // Store packets
  std::mutex mutex;
  std::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(priv::utilities::kPendingResult);

  std::string packet_id(ComposeSignaturePacketName(key_ring.identity));
  VoidFunctionOneBool callback([&] (const bool& response) {
                                 utils::ChunkStoreOperationCallback(response,
                                                                    &mutex,
                                                                    &cond_var,
                                                                    &results[0]);
                               });
  asymm::Keys key_shared(key_ring);
  if (!chunk_store_->Store(packet_id,
                           utils::SerialisedSignedData(key_ring),
                           callback,
                           key_shared)) {
    std::unique_lock<std::mutex> lock(mutex);
    results[0] = kRemoteChunkStoreFailure;
  }
  result = utils::WaitForResults(mutex, cond_var, results);
  if (result != kSuccess) {
    LOG(kError) << "Timed out waiting for the response";
    return result;
  }
  if (results[0] != kSuccess) {
    LOG(kError) << "Failed to store packet.  Packet 1 : " << results[0];
    return results[0];
  }
  std::string directory_id;
  result = drive_in_user_space_->SetShareDetails(drive::RelativePath(mount_dir(), share_path),
                                                 share_id,
                                                 key_ring,
                                                 sender_public_id,
                                                 false,
                                                 &directory_id);
  if (result != kSuccess) {
    LOG(kError) << "Failed creating share " << share_path.string() << ", with result: " << result;
    return result;
  }
  result = OpenShareInvitation(sender_public_id, share_path, contacts, contacts_results);
  if (result != kSuccess) {
    LOG(kError) << "Failed to invite users to share " << share_path;
    return result;
  }
  return kSuccess;
}

int UserStorage::GetAllShares(StringIntMap* shares_names) {
  return drive_in_user_space_->GetAllShares(shares_names);
}

int UserStorage::InsertShare(const fs::path& absolute_path,
                             const std::string& share_id,
                             const std::string& inviter_id,
                             std::string* share_name,
                             const std::string& directory_id,
                             const asymm::Keys& share_keyring) {
  std::string generated_name(GetNameInPath(mount_dir() / kSharedStuff, *share_name));
  if (generated_name.empty()) {
    LOG(kError) << "Failed to generate name for Share: " << *share_name;
    return kGeneralError;
  }

  fs::path share_dir(absolute_path.parent_path() / generated_name);
  int result(drive_in_user_space_->InsertShare(drive::RelativePath(mount_dir(), share_dir),
                                               inviter_id,
                                               directory_id,
                                               share_id,
                                               share_keyring));
  if (result != kSuccess) {
    LOG(kError) << "Failed to insert share: " << result;
    return result;
  }

  *share_name = generated_name;
  return result;
}

int UserStorage::StopShare(const std::string& sender_public_id,
                           const fs::path& absolute_path,
                           bool delete_data) {
  fs::path relative_path(drive::RelativePath(mount_dir(), absolute_path));
  fs::path share_name;
  std::map<std::string, int> contacts;
  asymm::Keys key_ring;
  std::string share_id;
  maidsafe::drive::DirectoryId directory_id;
  boost::system::error_code error_code;
  // here all contacts need to be informed, even those un-confirmed users
  int result(drive_in_user_space_->GetShareDetails(relative_path, &share_name, &key_ring,
                                                   &share_id, nullptr, &contacts, nullptr));
  if (result != kSuccess) {
    LOG(kError) << "Failed to get share details for " << absolute_path;
    return result;
  }
  if (delete_data) {
    result = drive_in_user_space_->RemoveShare(relative_path);
    if (result != kSuccess)
      return result;
  } else {
    result = drive_in_user_space_->SetShareDetails(relative_path,
                                                   "",
                                                   key_ring,
                                                   sender_public_id,
                                                   drive::kMsPrivateShare,
                                                   &directory_id);
    if (result != kSuccess) {
      LOG(kError) << "Failed to set share details for " << absolute_path;
      return result;
    }
    std::string generated_name(GetNameInPath(mount_dir() / kMyStuff, share_name.string()));
    if (generated_name.empty()) {
      LOG(kError) << "Failed to generate name for My Stuff.";
      return kGeneralError;
    }
    fs::path my_path(mount_dir() / kMyStuff / generated_name);
    result = drive_in_user_space_->MoveDirectory(absolute_path, my_path);
    if (result != kSuccess) {
      LOG(kError) << "Failed to move directory " << absolute_path;
      return result;
    }
  }
  InformContactsOperation(kPrivateShareDeletion, sender_public_id, contacts, share_id);
  std::mutex mutex;
  std::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(priv::utilities::kPendingResult);

  std::string packet_id(ComposeSignaturePacketName(key_ring.identity));

  VoidFunctionOneBool callback([&] (const bool& response) {
                                 utils::ChunkStoreOperationCallback(response,
                                                                    &mutex,
                                                                    &cond_var,
                                                                    &results[0]);
                               });
  asymm::Keys key_shared(key_ring);
  if (!chunk_store_->Delete(packet_id, callback, key_shared)) {
    std::unique_lock<std::mutex> lock(mutex);
    results[0] = kRemoteChunkStoreFailure;
  }

  result = utils::WaitForResults(mutex, cond_var, results);
  if (result != kSuccess) {
    LOG(kError) << "Failed to get a response.";
    return result;
  }
  if (results[0] != kSuccess) {
    LOG(kError) << "Failed to remove packet. Packet 1 : " << results[0];
    return results[0];
  }

  return kSuccess;
}

int UserStorage::RemoveShare(const fs::path& absolute_path,
                             const std::string& sender_public_id,
                             bool inform_contact) {
  // when own name not provided, this indicates being asked to leave
  // i.e. no notification of leaving to the owner required to be sent
  if (sender_public_id.empty()) {
    return drive_in_user_space_->RemoveShare(drive::RelativePath(mount_dir(), absolute_path));
  }

  fs::path relative_path(drive::RelativePath(mount_dir(), absolute_path));
  std::string share_id;
  std::string owner_id;
  int result(GetShareDetails(relative_path,
                             nullptr,
                             nullptr,
                             &share_id,
                             nullptr,
                             nullptr,
                             &owner_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed to get share details for " << absolute_path;
    return result;
  }
  // Owner doesn't allow to leave (shall use StopShare method)
  if (owner_id == sender_public_id)
    return kOwnerTryingToLeave;

  result = drive_in_user_space_->RemoveShare(drive::RelativePath(mount_dir(), absolute_path));
  if (result != kSuccess) {
    LOG(kError) << "Failed to remove share " << absolute_path;
    return result;
  }
  if (inform_contact) {
    std::map<std::string, int> owner;
    owner.insert(std::make_pair(owner_id , 0));
    return InformContactsOperation(kPrivateShareMemberLeft, sender_public_id, owner, share_id);
  }
  return kSuccess;
}

void UserStorage::ShareDeleted(const std::string& share_name) {
  fs::path share(mount_dir() / kSharedStuff / share_name);
  RemoveShare(share);
}

int UserStorage::UpdateShare(const std::string& share_id,
                             const std::string* new_share_id,
                             const std::string* new_directory_id,
                             const asymm::Keys* new_key_ring,
                             int* access_right) {
  fs::path relative_path;
  int result(GetShareDetails(share_id, &relative_path, nullptr, nullptr, nullptr));
  if (result != kSuccess) {
    LOG(kError) << "Failed to get share details for " << mount_dir() / relative_path;
    return result;
  }
  return drive_in_user_space_->UpdateShare(relative_path,
                                           share_id,
                                           new_share_id,
                                           new_directory_id,
                                           new_key_ring,
                                           access_right);
}

int UserStorage::AddShareUsers(const std::string& sender_public_id,
                               const fs::path& absolute_path,
                               const StringIntMap& contacts,
                               bool private_share,
                               StringIntMap* contacts_results) {
  fs::path relative_path(drive::RelativePath(mount_dir(), absolute_path));

  int result(drive_in_user_space_->AddShareUsers(relative_path,
                                                 contacts,
                                                 private_share));
  if (result != kSuccess) {
    LOG(kError) << "Failed to add users to share: " << absolute_path.string();
    return result;
  }

  std::string share_id;
  std::string directory_id;
  asymm::Keys key_ring;

  result = GetShareDetails(relative_path,
                           nullptr,
                           &key_ring,
                           &share_id,
                           &directory_id,
                           nullptr,
                           nullptr);
  if (result != kSuccess) {
    LOG(kError) << "Failed to get share details: " << absolute_path.string();
    return result;
  }
  std::vector<std::string> contacts_to_remove;
  result = InformContactsOperation(kPrivateShareInvitation,
                                   sender_public_id,
                                   contacts,
                                   share_id,
                                   absolute_path.filename().string(),
                                   directory_id,
                                   key_ring,
                                   "",
                                   contacts_results);
  if (result != kSuccess) {
    LOG(kError) << "Failed to inform contacts: " << absolute_path.string();
    std::for_each(contacts.begin(),
                  contacts.end(),
                  [&](const StringIntMap::value_type& contact) {
                    contacts_to_remove.push_back(contact.first);
                  });
    result = RemoveShareUsers(sender_public_id, absolute_path, contacts_to_remove);
    if (result != kSuccess) {
      LOG(kError) << "Failed to remove contacts.";
    }
    return result;
  }
  if (contacts_results) {
    std::for_each(contacts_results->begin(),
                  contacts_results->end(),
                  [&](const StringIntMap::value_type& contact_result) {
                    if (contact_result.second != kSuccess)
                      contacts_to_remove.push_back(contact_result.first);
                  });
    if (!contacts_to_remove.empty()) {
      result = RemoveShareUsers(sender_public_id, absolute_path, contacts_to_remove);
      if (result != kSuccess) {
        LOG(kError) << "Failed to remove failed contacts.";
        return result;
      }
    }
  }
  return kSuccess;
}

int UserStorage::AddOpenShareUser(const fs::path& absolute_path, const StringIntMap& contacts) {
  fs::path relative_path(drive::RelativePath(mount_dir(), absolute_path));
  int result(drive_in_user_space_->AddShareUsers(relative_path, contacts, false));
  if (result != kSuccess) {
    LOG(kError) << "Failed to add users to share: " << absolute_path.string();
    return result;
  }
  return kSuccess;
}

int UserStorage::OpenShareInvitation(const std::string& sender_public_id,
                                     const fs::path& absolute_path,
                                     const StringIntMap& contacts,
                                     StringIntMap* contacts_results) {
  fs::path relative_path(drive::RelativePath(mount_dir(), absolute_path)),
           share_name;
  int result(drive_in_user_space_->AddShareUsers(relative_path,
                                                 contacts,
                                                 false));
  if (result != kSuccess) {
    LOG(kError) << "Failed to add users to share: " << absolute_path.string();
    return result;
  }
  std::string share_id, directory_id;
  asymm::Keys key_ring;
  result = GetShareDetails(relative_path,
                           &share_name,
                           &key_ring,
                           &share_id,
                           &directory_id,
                           nullptr,
                           nullptr);
  if (result != kSuccess) {
    LOG(kError) << "Failed to get share details: " << absolute_path.string();
    return result;
  }
  std::vector<std::string> contacts_to_remove;
  result = InformContacts(kOpenShareInvitation,
                          sender_public_id,
                          contacts,
                          share_id,
                          share_name.string(),
                          directory_id,
                          key_ring,
                          "",
                          contacts_results);
  if (result != kSuccess) {
    LOG(kError) << "Failed to inform contacts for " << absolute_path;
    std::for_each(contacts.begin(),
                  contacts.end(),
                  [&](const StringIntMap::value_type& contact) {
                    contacts_to_remove.push_back(contact.first);
                  });
    result = RemoveShareUsers(sender_public_id, absolute_path, contacts_to_remove);
    if (result != kSuccess) {
      LOG(kError) << "Failed to remove contacts.";
    }
    return result;
  }
  if (contacts_results) {
    std::for_each(contacts_results->begin(),
                  contacts_results->end(),
                  [&](const StringIntMap::value_type& contact_result) {
                    if (contact_result.second != kSuccess)
                      contacts_to_remove.push_back(contact_result.first);
                  });
    if (!contacts_to_remove.empty()) {
      result = RemoveShareUsers(sender_public_id, absolute_path, contacts_to_remove);
      if (result != kSuccess) {
        LOG(kError) << "Failed to remove failed contacts.";
        return result;
      }
    }
  }
  return kSuccess;
}

int UserStorage::GetAllShareUsers(const fs::path& absolute_path,
                                  std::map<std::string, int>* all_share_users) {
  int result(GetShareDetails(drive::RelativePath(mount_dir(), absolute_path),
                             nullptr, nullptr, nullptr, nullptr, all_share_users, nullptr));
  if (result != kSuccess) {
    LOG(kError) << "Failed to get share details for " << absolute_path;
    return result;
  }
  return kSuccess;
}

void UserStorage::InvitationResponse(const std::string& user_id,
                                     const std::string& share_name,
                                     const std::string& share_id) {
  std::vector<std::string> user_ids(1, user_id);

  int result(0);
  if (share_name.empty())
    result = drive_in_user_space_->RemoveShareUsers(share_id, user_ids);
  else
    result = drive_in_user_space_->ConfirmShareUsers(share_id, user_ids);
  LOG(kInfo) << "Action on confirmation result: " << result;
}

int UserStorage::UserLeavingShare(const std::string& share_id, const std::string& user_id) {
  std::vector<std::string> user_ids;
  user_ids.push_back(user_id);
  return drive_in_user_space_->RemoveShareUsers(share_id, user_ids);
}

int UserStorage::RemoveShareUsers(const std::string& /*sender_public_id*/,
                                  const fs::path& absolute_path,
                                  const std::vector<std::string>& user_ids) {
  fs::path relative_path(drive::RelativePath(mount_dir(), absolute_path));
  std::string share_id;
  int result = drive_in_user_space_->GetShareDetails(relative_path,
                                                     nullptr,
                                                     nullptr,
                                                     &share_id,
                                                     nullptr,
                                                     nullptr,
                                                     nullptr);
  if (result != kSuccess) {
    LOG(kError) << "Failed to get share details for " << absolute_path;
    return result;
  }
  result = drive_in_user_space_->RemoveShareUsers(share_id, user_ids);
  if (result != kSuccess) {
    LOG(kError) << "Failed to remove share users for " << absolute_path;
  }
  return result;
}

int UserStorage::MoveShare(const std::string& sender_public_id,
                           const std::string& share_id,
                           const fs::path& relative_path,
                           const asymm::Keys& old_key_ring,
                           bool private_share,
                           std::string* new_share_id_return,
                           std::string* new_directory_id,
                           asymm::Keys* new_key_ring) {
  std::string new_share_id(RandomString(share_id.size()));
  asymm::Keys key_ring;
  int result(passport::CreateSignaturePacket(key_ring));
  if (result != kSuccess) {
    LOG(kError) << "Failed to create new share keys.";
    return result;
  }
  // Store packets
  std::mutex mutex;
  std::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(priv::utilities::kPendingResult);

  std::string packet_id(ComposeSignaturePacketName(key_ring.identity));
  VoidFunctionOneBool callback([&] (const bool& response) {
                                 utils::ChunkStoreOperationCallback(response,
                                                                    &mutex,
                                                                    &cond_var,
                                                                    &results[0]);
                               });
  asymm::Keys key_shared(key_ring);
  if (!chunk_store_->Store(packet_id,
                           utils::SerialisedSignedData(key_ring),
                           callback,
                           key_shared)) {
    std::unique_lock<std::mutex> lock(mutex);
    results[0] = kRemoteChunkStoreFailure;
  }

  result = utils::WaitForResults(mutex, cond_var, results);
  if (result != kSuccess) {
    LOG(kError) << "Failed to get response.";
    return result;
  }
  if (results[0] != kSuccess) {
    LOG(kError) << "Failed to store packets.  Packet 1 : " << results[0];
    return results[0];
  }

  std::string directory_id;
  result = drive_in_user_space_->SetShareDetails(relative_path,
                                                 new_share_id,
                                                 key_ring,
                                                 sender_public_id,
                                                 private_share,
                                                 &directory_id);
  if (result != kSuccess) {
    LOG(kError) << "Failed in updating share of " << Base32Substr(share_id)
                << ", with result of : " << result;
    return result;
  }

  results.clear();
  results.push_back(priv::utilities::kPendingResult);

  asymm::Keys old_key_shared(old_key_ring);
  packet_id = ComposeSignaturePacketName(old_key_ring.identity);
  if (!chunk_store_->Delete(packet_id, callback, old_key_shared)) {
    std::unique_lock<std::mutex> lock(mutex);
    results[0] = kRemoteChunkStoreFailure;
  }

  result = utils::WaitForResults(mutex, cond_var, results);
  if (result != kSuccess) {
    LOG(kError) << "Failed to get response.";
    return result;
  }
  if (results[0] != kSuccess) {
    LOG(kWarning) << "Failed to remove packet.  Packet 1 : " << results[0];
  }

  if (new_share_id_return)
    *new_share_id_return = new_share_id;
  if (new_directory_id)
    *new_directory_id = directory_id;
  if (new_key_ring)
    *new_key_ring = key_ring;
  return kSuccess;
}

int UserStorage::RemoveOpenShareUsers(const fs::path& absolute_path,
                                      const std::vector<std::string>& user_ids) {
  fs::path relative_path(drive::RelativePath(mount_dir(), absolute_path));
  std::string share_id;
  GetShareDetails(relative_path, nullptr, nullptr, &share_id, nullptr, nullptr, nullptr);
  int result(drive_in_user_space_->RemoveShareUsers(share_id, user_ids));
  if (result != kSuccess) {
    LOG(kError) << "Failed to remove share users for " << absolute_path;
    return result;
  }
  return kSuccess;
}

int UserStorage::GetShareUsersRights(const fs::path& absolute_path,
                                     const std::string& user_id,
                                     int* admin_rights) {
  return drive_in_user_space_->GetShareUsersRights(
             drive::RelativePath(mount_dir(), absolute_path),
             user_id,
             admin_rights);
}

int UserStorage::SetShareUsersRights(const std::string& sender_public_id,
                                     const fs::path& absolute_path,
                                     const std::string& user_id,
                                     int admin_rights,
                                     bool private_share) {
  fs::path relative_path(drive::RelativePath(mount_dir(), absolute_path));
  int old_admin_right;
  int result(drive_in_user_space_->GetShareUsersRights(relative_path, user_id, &old_admin_right));
  if (result != kSuccess) {
    LOG(kError) << "Failed getting access right for contact " << user_id << ", with result : "
                << result;
    return result;
  }

  if (admin_rights == old_admin_right) {
    LOG(kInfo) << "Access right for contact " << user_id << ", keeps the same ";
    return kSuccess;
  }

  result = drive_in_user_space_->SetShareUsersRights(relative_path, user_id, admin_rights);
  if (result != kSuccess) {
    LOG(kError) << "Failed setting access right for contact " << user_id << ", with result : "
                << result;
    return result;
  }

  StringIntMap contacts, share_contacts;
  contacts.insert(std::make_pair(user_id, admin_rights));
  asymm::Keys key_ring;
  std::string share_id;
  result = GetShareDetails(relative_path, nullptr, &key_ring, &share_id, nullptr,
                           &share_contacts, nullptr);
  if (result != kSuccess) {
    LOG(kError) << "Failed getting admin right for contact " << user_id << ", with result : "
                << result;
    return result;
  }

  // In case of downgrading : generate new share_id/key and inform all
  // In case of upgrading : just inform the contact of the share key_ring.
  InboxItemType rights(kPrivateShareMembershipUpgrade);
  if (old_admin_right > admin_rights) {
    rights = kPrivateShareMembershipDowngrade;
    result = MoveShare(sender_public_id,
                       share_id,
                       relative_path,
                       key_ring,
                       private_share,
                       &share_id);
    if (result != kSuccess) {
      LOG(kError) << "Failed to move share.";
      return result;
    }
  }
  return InformContactsOperation(rights, sender_public_id, contacts, share_id, "", "", key_ring);
}

int UserStorage::DowngradeShareUsersRights(const std::string& /*sender_public_id*/,
                                           const fs::path& absolute_path,
                                           const StringIntMap& contacts,
                                           StringIntMap* results) {
  fs::path relative_path(drive::RelativePath(mount_dir(), absolute_path));
  asymm::Keys old_key_ring;
  std::string share_id, new_share_id;
  StringIntMap share_contacts;
  int result = GetShareDetails(relative_path,
                               nullptr,
                               &old_key_ring,
                               &share_id,
                               nullptr,
                               &share_contacts,
                               nullptr);
  if (result != kSuccess) {
    LOG(kError) << "Failed to get share details for " << relative_path;
    return result;
  }
  for (auto it = contacts.begin(); it != contacts.end(); ++it)
    share_contacts.erase(share_contacts.find(it->first));
  for (auto it = contacts.begin(); it != contacts.end(); ++it)
    results->insert(std::make_pair(it->first,
                    drive_in_user_space_->SetShareUsersRights(relative_path,
                                                              it->first,
                                                              (it->second != 0))));
  return kSuccess;
}

int UserStorage::UpgradeShareUsersRights(const std::string& /*sender_public_id*/,
                                         const fs::path& absolute_path,
                                         const StringIntMap& contacts,
                                         StringIntMap* results) {
  fs::path relative_path(drive::RelativePath(mount_dir(), absolute_path));
  StringIntMap share_contacts;
  int result = GetShareDetails(relative_path,
                               nullptr,
                               nullptr,
                               nullptr,
                               nullptr,
                               &share_contacts,
                               nullptr);
  if (result != kSuccess) {
    LOG(kError) << "Failed to get share details for " << relative_path;
    return result;
  }
  for (auto it = contacts.begin(); it != contacts.end(); ++it)
    share_contacts.erase(share_contacts.find(it->first));
  for (auto it = contacts.begin(); it != contacts.end(); ++it)
    results->insert(std::make_pair(it->first,
                    drive_in_user_space_->SetShareUsersRights(relative_path,
                                                              it->first,
                                                              kShareReadWrite)));
  return kSuccess;
}

int UserStorage::GetShareDetails(const std::string& share_id,
                                 fs::path* relative_path,
                                 asymm::Keys* share_keyring,
                                 std::string* directory_id,
                                 StringIntMap* share_users) const {
  int result(drive_in_user_space_->GetShareDetails(share_id,
                                                   relative_path,
                                                   share_keyring,
                                                   directory_id,
                                                   share_users));
//  if (share_users) {
//    for (auto it = share_users->begin(); it != share_users->end(); ++it) {
//      if ((*it).second < kShareRemover)
//        (*it).second = kUnconfirmed;
//    }
//  }
  return result;
}

int UserStorage::GetShareDetails(const fs::path& relative_path,
                                 fs::path* share_name,
                                 asymm::Keys* share_keyring,
                                 std::string* share_id,
                                 std::string* directory_id,
                                 std::map<std::string, int>* share_users,
                                 std::string* owner_id) const {
  int result(drive_in_user_space_->GetShareDetails(relative_path,
                                                   share_name,
                                                   share_keyring,
                                                   share_id,
                                                   directory_id,
                                                   share_users,
                                                   owner_id));
//  if (share_users) {
//    std::vector<std::string> unconfirmed_users;
//    for (auto it = share_users->begin(); it != share_users->end(); ++it)
//      if ((*it).second < kShareRemover)
//        unconfirmed_users.push_back((*it).first);
//    for (auto it = unconfirmed_users.begin(); it != unconfirmed_users.end(); ++it)
//      share_users->erase(*it);
//  }
  return result;
}
std::string UserStorage::MemberAccessChange(const std::string& share_id,
                                            const std::string& directory_id,
                                            const std::string& new_share_id,
                                            const asymm::Keys& key_ring,
                                            int access_right) {
  fs::path relative_path;
  int result(GetShareDetails(share_id, &relative_path, nullptr, nullptr, nullptr));
  if (result != kSuccess) {
    LOG(kError) << "Failed to find share details: " << result;
    return "";
  }
  if (access_right <= kShareReadOnly) {
    asymm::Keys empty_key_ring;
    result = drive_in_user_space_->UpdateShare(relative_path,
                                               share_id,
                                               &new_share_id,
                                               &directory_id,
                                               &empty_key_ring,
                                               &access_right);
  } else {
    result = drive_in_user_space_->UpdateShare(relative_path,
                                               share_id,
                                               nullptr,
                                               nullptr,
                                               &key_ring,
                                               &access_right);
  }
  if (result != kSuccess) {
    LOG(kError) << "Failed to update share details: " << result;
    return "";
  }
  return relative_path.filename().string();
}

int UserStorage::GetPrivateSharesContactBeingOwner(const std::string& /*my_public_id*/,
                                                   const std::string& contact_public_id,
                                                   std::vector<std::string>* shares_names) {
  StringIntMap all_shares;
  GetAllShares(&all_shares);
  for (auto it = all_shares.begin(); it != all_shares.end(); ++it) {
    std::string owner_id;
    fs::path share_dir(fs::path("/") / kSharedStuff / (*it).first);
    GetShareDetails(share_dir, nullptr, nullptr, nullptr, nullptr, nullptr, &owner_id);
    if (owner_id == contact_public_id)
      shares_names->push_back((*it).first);
  }
  return kSuccess;
}

int UserStorage::GetNotes(const fs::path& absolute_path, std::vector<std::string>* notes) {
  return drive_in_user_space_->GetNotes(drive::RelativePath(mount_dir(), absolute_path), notes);
}

int UserStorage::AddNote(const fs::path& absolute_path, const std::string& note) {
  return drive_in_user_space_->AddNote(drive::RelativePath(mount_dir(), absolute_path), note);
}

int UserStorage::ReadHiddenFile(const fs::path& absolute_path, std::string* content) {
  return drive_in_user_space_->ReadHiddenFile(drive::RelativePath(mount_dir(), absolute_path),
                                              content);
}

int UserStorage::WriteHiddenFile(const fs::path& absolute_path,
                                 const std::string& content,
                                 bool overwrite_existing) {
  return drive_in_user_space_->WriteHiddenFile(drive::RelativePath(mount_dir(), absolute_path),
                                               content,
                                               overwrite_existing);
}

int UserStorage::DeleteHiddenFile(const fs::path& absolute_path) {
  return drive_in_user_space_->DeleteHiddenFile(drive::RelativePath(mount_dir(), absolute_path));
}

int UserStorage::SearchHiddenFiles(const fs::path& absolute_path,
                                   std::vector<std::string>* results) {
  return drive_in_user_space_->SearchHiddenFiles(drive::RelativePath(mount_dir(), absolute_path),
                                                 results);
}

int UserStorage::GetHiddenFileDataMap(const boost::filesystem::path& absolute_path,
                                      std::string* data_map) {
  return drive_in_user_space_->GetDataMapHidden(drive::RelativePath(mount_dir(), absolute_path),
                                                data_map);
}

bs2::connection UserStorage::ConnectToDriveChanged(drive::DriveChangedSlotPtr slot) const {
  return drive_in_user_space_->ConnectToDriveChanged(slot);
}

bs2::connection UserStorage::ConnectToShareRenamedSignal(const ShareRenamedFunction& function) {
  if (function) {
    share_renamed_function_ = function;
    if (mount_status_)
      return drive_in_user_space_->ConnectToShareRenamed(function);
  }
  return bs2::connection();
}

bs2::connection UserStorage::ConnectToShareChangedSignal(
    const ShareChangedFunction& function) {
  if (function) {
    share_changed_function_ = function;
    if (mount_status_)
      return drive_in_user_space_->ConnectToShareChanged(function);
  }
  return bs2::connection();
}

int UserStorage::InformContactsOperation(InboxItemType item_type,
                                         const std::string& sender_public_id,
                                         const StringIntMap& contacts,
                                         const std::string& share_id,
                                         const std::string& absolute_path,
                                         const std::string& directory_id,
                                         const asymm::Keys& key_ring,
                                         const std::string& new_share_id,
                                         StringIntMap* contacts_results) {
  InboxItem admin_message(item_type), non_admin_message(item_type);
  std::string public_key, private_key, empty_string;

  admin_message.sender_public_id = sender_public_id;
  admin_message.content.push_back(share_id);
  non_admin_message.sender_public_id = sender_public_id;
  non_admin_message.content.push_back(share_id);
  if (!absolute_path.empty()) {
    admin_message.content.push_back(fs::path(absolute_path).filename().string());
    non_admin_message.content.push_back(fs::path(absolute_path).filename().string());
  } else {
    admin_message.content.push_back(empty_string);
    non_admin_message.content.push_back(empty_string);
  }
  if (!directory_id.empty()) {
    admin_message.content.push_back(directory_id);
    non_admin_message.content.push_back(directory_id);
  } else {
    admin_message.content.push_back(empty_string);
    non_admin_message.content.push_back(empty_string);
  }
  if (!new_share_id.empty()) {
    admin_message.content.push_back(new_share_id);
    non_admin_message.content.push_back(new_share_id);
  } else {
    admin_message.content.push_back(empty_string);
    non_admin_message.content.push_back(empty_string);
  }
  if (!key_ring.identity.empty() &&
      !key_ring.validation_token.empty() &&
      asymm::ValidateKey(key_ring.public_key) &&
      asymm::ValidateKey(key_ring.private_key)) {
    admin_message.content.push_back(key_ring.identity);
    admin_message.content.push_back(key_ring.validation_token);
    asymm::EncodePrivateKey(key_ring.private_key, &private_key);
    admin_message.content.push_back(private_key);
    asymm::EncodePublicKey(key_ring.public_key, &public_key);
    admin_message.content.push_back(public_key);
  } else {
    admin_message.content.push_back(empty_string);
    admin_message.content.push_back(empty_string);
    admin_message.content.push_back(empty_string);
    admin_message.content.push_back(empty_string);
  }
  non_admin_message.content.push_back(empty_string);
  non_admin_message.content.push_back(empty_string);
  non_admin_message.content.push_back(empty_string);
  non_admin_message.content.push_back(empty_string);

  int result, aggregate(0);
  if (contacts_results)
    contacts_results->clear();
  for (auto it = contacts.begin(); it != contacts.end(); ++it) {
  // do nothing if trying to send a msg to itself
    if ((*it).first != sender_public_id) {
      if ((*it).second >= kShareReadWrite) {
        admin_message.receiver_public_id = (*it).first;
        result = message_handler_.Send(admin_message);
      } else {
        non_admin_message.receiver_public_id = (*it).first;
        result = message_handler_.Send(non_admin_message);
      }
      if (result != kSuccess) {
        LOG(kError) << "Failed in inform contact " << (*it).first << "  of operation "
                    << ", with result of : " << result;
        ++aggregate;
      }
      if (contacts_results)
        contacts_results->insert(std::make_pair((*it).first, result));
    }
  }

  return aggregate == static_cast<int>(contacts.size()) ? aggregate : 0;
}

int UserStorage::InformContacts(InboxItemType item_type,
                                const std::string& sender_public_id,
                                const std::map<std::string, int>& contacts,
                                const std::string& share_id,
                                const std::string& share_name,
                                const std::string& directory_id,
                                const asymm::Keys& key_ring,
                                const std::string& /*new_share_id*/,
                                StringIntMap* contacts_results) {
  InboxItem message(item_type);
  std::string public_key, private_key;
  message.sender_public_id = sender_public_id;
  message.content.push_back(share_id);
  switch (item_type) {
    case kOpenShareInvitation:
      message.content.push_back(share_name);
      message.content.push_back(directory_id);
      break;
    default:
      LOG(kError) << "Unknown constant";
  }
  message.content.push_back(std::string());
  if (!key_ring.identity.empty() &&
      !key_ring.validation_token.empty() &&
      asymm::ValidateKey(key_ring.public_key) &&
      asymm::ValidateKey(key_ring.private_key)) {
    message.content.push_back(key_ring.identity);
    message.content.push_back(key_ring.validation_token);
    asymm::EncodePrivateKey(key_ring.private_key, &private_key);
    message.content.push_back(private_key);
    asymm::EncodePublicKey(key_ring.public_key, &public_key);
    message.content.push_back(public_key);
  } else {
    LOG(kError) << "Invalid keyring for open share";
    return kInvalidKeyringForOpenShare;
  }

  int result, aggregate(0);
  if (contacts_results)
    contacts_results->clear();
  for (auto it = contacts.begin(); it != contacts.end(); ++it) {
    if (it->first != sender_public_id) {
      message.receiver_public_id = it->first;
      result = message_handler_.Send(message);
      if (result != kSuccess) {
        LOG(kError) << "Failed to inform contact " << it->first << " of operation " << item_type
                    << ", with result " << result;
        ++aggregate;
      }
      if (contacts_results)
        contacts_results->insert(std::make_pair(it->first, result));
    }
  }
  return aggregate == static_cast<int>(contacts.size()) ? aggregate : 0;
}

std::string UserStorage::ConstructFile(const std::string& serialised_data_map) {
  encrypt::DataMapPtr data_map(ParseSerialisedDataMap(serialised_data_map));
  if (!data_map) {
    LOG(kError) << "Data map didn't parse.";
    return "";
  }

  uint32_t file_size(data_map->chunks.empty() ?
                     static_cast<uint32_t>(data_map->content.size()) : 0);
  auto it(data_map->chunks.begin());
  while (it != data_map->chunks.end()) {
    if (kFileRecontructionLimit < (file_size + (*it).size)) {
      LOG(kError) << "File too large to read.";
      return "";
    }
    file_size += (*it).size;
    ++it;
  }

  // TODO(Team): decide based on the size whether to go ahead.
  // Update: It's now only possible to read a file up to uint32_t size.
  // if (file_size > 'some limit')
  //   return "";

  encrypt::SelfEncryptor self_encryptor(data_map, *chunk_store_);
  std::unique_ptr<char[]> contents(new char[file_size]);
  if (!self_encryptor.Read(contents.get(), file_size, 0)) {
    LOG(kError) << "Failure to read contents from SE: " << file_size;
    return "";
  }
  std::string file_content(contents.get(), file_size);

  return file_content;
}

}  // namespace lifestuff

}  // namespace maidsafe
