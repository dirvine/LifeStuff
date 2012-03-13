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

#include <list>

#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/message_handler.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/utils.h"
#include "maidsafe/lifestuff/version.h"
#include "maidsafe/lifestuff/ye_olde_signal_to_callback_converter.h"

namespace args = std::placeholders;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

namespace {

struct InsertShareTag;
struct StopShareTag;
struct RemoveShareTag;
struct UpdateShareTag;
struct UpgradeShareTag;

template<typename Operation>
struct AddMessageDetails {};

template<>
struct AddMessageDetails<InsertShareTag> {
  void operator()(const fs::path& path,
                  const std::string& directory_id,
                  const std::string&,
                  pca::Message* admin_message,
                  pca::Message* non_admin_message) {
    admin_message->set_subject("insert_share");
    admin_message->add_content(path.filename().string());
    admin_message->add_content(directory_id);
    non_admin_message->set_subject("insert_share");
    non_admin_message->add_content(path.filename().string());
    non_admin_message->add_content(directory_id);
  }
};

template<>
struct AddMessageDetails<StopShareTag> {
  void operator()(const fs::path&,
                  const std::string&,
                  const std::string&,
                  pca::Message* admin_message,
                  pca::Message* non_admin_message) {
    admin_message->set_subject("stop_share");
    non_admin_message->set_subject("stop_share");
  }
};

template<>
struct AddMessageDetails<RemoveShareTag> {
  void operator()(const fs::path&,
                  const std::string&,
                  const std::string&,
                  pca::Message* admin_message,
                  pca::Message* non_admin_message) {
    admin_message->set_subject("remove_share");
    non_admin_message->set_subject("remove_share");
  }
};

template<>
struct AddMessageDetails<UpdateShareTag> {
  void operator()(const fs::path&,
                  const std::string& directory_id,
                  const std::string& new_share_id,
                  pca::Message* admin_message,
                  pca::Message* non_admin_message) {
    admin_message->set_subject("update_share");
    admin_message->add_content(directory_id);
    admin_message->add_content(new_share_id);
    non_admin_message->set_subject("update_share");
    non_admin_message->add_content(directory_id);
    non_admin_message->add_content(new_share_id);
  }
};

template<>
struct AddMessageDetails<UpgradeShareTag> {
  void operator()(const fs::path&,
                  const std::string&,
                  const std::string&,
                  pca::Message* admin_message,
                  pca::Message* non_admin_message) {
    admin_message->set_subject("upgrade_share");
    non_admin_message->set_subject("upgrade_share");
  }
};

}  // namespace

UserStorage::UserStorage(
    std::shared_ptr<pcs::RemoteChunkStore> chunk_store,
    std::shared_ptr<YeOldeSignalToCallbackConverter> converter,
    std::shared_ptr<MessageHandler> message_handler)
    : mount_status_(false),
      chunk_store_(chunk_store),
      drive_in_user_space_(),
      session_(),
      converter_(converter),
      message_handler_(message_handler),
      mount_dir_() {}

void UserStorage::MountDrive(const fs::path &mount_dir_path,
                             const std::string &session_name,
                             std::shared_ptr<Session> session,
                             bool creation,
                             const std::string &drive_logo) {
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
  mount_dir_ = drive_name;
  drive_in_user_space_->Mount(mount_dir_, drive_logo);
#else
  mount_dir_ = mount_dir_path / session_name;
  boost::system::error_code ec;
  if (fs::exists(mount_dir_, ec))
    fs::remove_all(mount_dir_, ec);
  fs::create_directories(mount_dir_, ec);
  boost::thread(std::bind(&MaidDriveInUserSpace::Mount,
                          drive_in_user_space_,
                          mount_dir_,
                          drive_logo,
                          false));
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
  fs::remove_all(mount_dir_, error_code);
#endif
  mount_status_ = false;
}

fs::path UserStorage::mount_dir() {
  return mount_dir_;
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

int UserStorage::CreateShare(const std::string &sender_public_username,
                             const fs::path &absolute_path,
                             const std::map<std::string, bool> &contacts,
                             std::string *share_id_result) {
  std::string share_id(crypto::Hash<crypto::SHA512>(absolute_path.string()));
  if (share_id_result)
    *share_id_result = share_id;

  std::vector<pki::SignaturePacketPtr> signature_packets;
  pki::CreateChainedId(&signature_packets, 1);
  asymm::Keys key_ring;
  key_ring.identity = signature_packets[0]->name();
  key_ring.public_key = signature_packets[0]->value();
  key_ring.private_key = signature_packets[0]->private_key();
  key_ring.validation_token = signature_packets[0]->signature();

  // Store packets
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);

  pcs::RemoteChunkStore::ValidationData validation_data(
      PopulateValidationData(key_ring));
  std::string packet_id(ComposeSignaturePacketName(key_ring.identity));
  VoidFuncOneInt callback(std::bind(&SendContactInfoCallback,
                                    args::_1,
                                    &mutex,
                                    &cond_var,
                                    &results[0]));
  if (converter_->AddOperation(packet_id, callback) != kSuccess) {
    DLOG(ERROR) << "Failed to add operation to converter";
    return kAuthenticationError;
  }

  chunk_store_->Store(packet_id,
                      ComposeSignaturePacketValue(*signature_packets[0]),
                      validation_data);
  int result(AwaitingResponse(&mutex, &cond_var, &results));
  if (result != kSuccess) {
    DLOG(ERROR) << "Timed out waiting for the response";
    return result;
  }

  if (results[0] != kSuccess) {
    DLOG(ERROR) << "Failed to store packet.  Packet 1 : " << results[0];
    return kStorePacketFailure;
  }
  std::string directory_id;
  result = drive_in_user_space_->SetShareDetails(
               drive_in_user_space_->RelativePath(absolute_path),
               share_id,
               key_ring,
               sender_public_username,
               &directory_id);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed in creating share of " << absolute_path.string()
                << ", with result of : " << result;
    return result;
  }

  // AddShareUser will send out the informing msg to contacts
  result = AddShareUsers(sender_public_username, absolute_path, contacts);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to add users to share at " << absolute_path;
    return result;
  }
  return kSuccess;
}

int UserStorage::InsertShare(const fs::path &absolute_path,
                             const std::string &share_id,
                             const std::string &directory_id,
                             const asymm::Keys &share_keyring) {
  return drive_in_user_space_->InsertShare(
             drive_in_user_space_->RelativePath(absolute_path),
             directory_id,
             share_id,
             share_keyring);
}

int UserStorage::StopShare(const std::string &sender_public_username,
                           const fs::path &absolute_path) {
  fs::path relative_path(drive_in_user_space_->RelativePath(absolute_path));
  std::map<std::string, bool> contacts;
  asymm::Keys key_ring;
  std::string share_id;
  maidsafe::drive::DirectoryId directory_id;
  int result(drive_in_user_space_->GetShareDetails(relative_path,
                                                   nullptr,
                                                   &key_ring,
                                                   &share_id,
                                                   nullptr,
                                                   &contacts));
  if (result != kSuccess)
    return result;
  result = drive_in_user_space_->SetShareDetails(relative_path,
                                                 "",
                                                 key_ring,
                                                 sender_public_username,
                                                 &directory_id);
  if (result != kSuccess)
    return result;

  InformContactsOperation<RemoveShareTag>(sender_public_username,
                                          contacts,
                                          share_id);
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);
  pcs::RemoteChunkStore::ValidationData
      validation_data(PopulateValidationData(key_ring));
  std::string packet_id(ComposeSignaturePacketName(key_ring.identity));

  VoidFuncOneInt callback(std::bind(&SendContactInfoCallback,
                                    args::_1,
                                    &mutex,
                                    &cond_var,
                                    &results[0]));
  if (converter_->AddOperation(packet_id, callback) != kSuccess) {
    DLOG(ERROR) << "Failed to add operation to converter";
    return kAuthenticationError;
  }
  chunk_store_->Delete(packet_id, validation_data);

  result = AwaitingResponse(&mutex, &cond_var, &results);
  if (result != kSuccess)
    return result;
  if (results[0] != kSuccess) {
    DLOG(ERROR) << "Failed to remove packet. Packet 1 : " << results[0];
    return kDeletePacketFailure;
  }

  return kSuccess;
}

int UserStorage::RemoveShare(const fs::path& absolute_path) {
  return drive_in_user_space_->RemoveShare(
             drive_in_user_space_->RelativePath(absolute_path));
}

int UserStorage::UpdateShare(const fs::path &absolute_path,
                             const std::string &share_id,
                             const std::string *new_share_id,
                             const std::string *new_directory_id,
                             const asymm::Keys *new_key_ring) {
  return drive_in_user_space_->UpdateShare(
             drive_in_user_space_->RelativePath(absolute_path),
             share_id,
             new_share_id,
             new_directory_id,
             new_key_ring);
}

int UserStorage::AddShareUsers(const std::string &sender_public_username,
                               const fs::path &absolute_path,
                               const std::map<std::string, bool> &contacts) {
  fs::path relative_path(drive_in_user_space_->RelativePath(absolute_path));
  int result(drive_in_user_space_->AddShareUsers(relative_path, contacts));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to add users to share: " << absolute_path.string();
    return result;
  }

  std::string share_id;
  std::string directory_id;
  asymm::Keys key_ring;

  result = drive_in_user_space_->GetShareDetails(relative_path,
                                                 nullptr,
                                                 &key_ring,
                                                 &share_id,
                                                 &directory_id,
                                                 nullptr);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get share details: " << absolute_path.string();
    return result;
  }

  result =
      InformContactsOperation<InsertShareTag>(sender_public_username,
                                              contacts,
                                              share_id,
                                              absolute_path.filename().string(),
                                              directory_id,
                                              key_ring);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get share details: " << absolute_path.string();
    return result;
  }

  return kSuccess;
}

int UserStorage::GetAllShareUsers(
    const fs::path &absolute_path,
    std::map<std::string, bool> *all_share_users) const {
  int result(drive_in_user_space_->GetShareDetails(
                 drive_in_user_space_->RelativePath(absolute_path),
                 nullptr,
                 nullptr,
                 nullptr,
                 nullptr,
                 all_share_users));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get share details for " << absolute_path;
    return result;
  }
  return kSuccess;
}

int UserStorage::RemoveShareUsers(const std::string &sender_public_username,
                                  const fs::path &absolute_path,
                                  const std::vector<std::string> &user_ids) {
  fs::path relative_path(drive_in_user_space_->RelativePath(absolute_path));
  std::string share_id;
  asymm::Keys old_key_ring;
  drive_in_user_space_->GetShareDetails(relative_path,
                                        nullptr,
                                        &old_key_ring,
                                        &share_id,
                                        nullptr,
                                        nullptr);
  int result(drive_in_user_space_->RemoveShareUsers(share_id, user_ids));
  if (result != kSuccess)
    return result;

  std::map<std::string, bool> removed_contacts;
  for (auto it = user_ids.begin(); it != user_ids.end(); ++it) {
    removed_contacts.insert(std::make_pair(*it, false));
  }
  InformContactsOperation<RemoveShareTag>(sender_public_username,
                                          removed_contacts,
                                          share_id);

  std::string new_share_id(RandomString(share_id.size()));
  std::vector<pki::SignaturePacketPtr> signature_packets;
  pki::CreateChainedId(&signature_packets, 1);
  asymm::Keys key_ring;
  key_ring.identity = signature_packets[0]->name();
  key_ring.public_key = signature_packets[0]->value();
  key_ring.private_key = signature_packets[0]->private_key();
  key_ring.validation_token = signature_packets[0]->signature();

  // Store packets
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);

  pcs::RemoteChunkStore::ValidationData validation_data(
      PopulateValidationData(key_ring));
  std::string packet_id(ComposeSignaturePacketName(key_ring.identity));
  VoidFuncOneInt callback(std::bind(&SendContactInfoCallback, args::_1,
                                    &mutex, &cond_var, &results[0]));
  if (converter_->AddOperation(packet_id, callback) != kSuccess) {
    DLOG(ERROR) << "Failed to add operation to converter";
    return kAuthenticationError;
  }
  chunk_store_->Store(packet_id,
                      ComposeSignaturePacketValue(*signature_packets[0]),
                      validation_data);

  result = AwaitingResponse(&mutex, &cond_var, &results);
  if (result != kSuccess)
    return result;
  if (results[0] != kSuccess) {
    DLOG(ERROR) << "Failed to store packets.  Packet 1 : " << results[0];
    return kStorePacketFailure;
  }

  std::string directory_id;
  result = drive_in_user_space_->SetShareDetails(relative_path,
                                                 new_share_id,
                                                 key_ring,
                                                 sender_public_username,
                                                 &directory_id);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed in updating share of " << Base32Substr(share_id)
                << ", with result of : " << result;
    return result;
  }

  results.clear();
  results.push_back(kPendingResult);

  validation_data = PopulateValidationData(old_key_ring);
  packet_id = ComposeSignaturePacketName(old_key_ring.identity);
  if (converter_->AddOperation(packet_id, callback) != kSuccess) {
    DLOG(ERROR) << "Failed to add operation to converter";
    return kAuthenticationError;
  }
  chunk_store_->Delete(packet_id, validation_data);

  result = AwaitingResponse(&mutex, &cond_var, &results);
  if (result != kSuccess)
    return result;
  if (results[0] != kSuccess) {
    DLOG(ERROR) << "Failed to remove packet.  Packet 1 : " << results[0];
//     return kDeletePacketFailure;
  }

  std::map<std::string, bool> contacts;
  result = drive_in_user_space_->GetShareDetails(relative_path,
                                                 nullptr,
                                                 nullptr,
                                                 &new_share_id,
                                                 nullptr,
                                                 &contacts);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed in getting share deatils of "
                << Base32Substr(share_id) << ", with result of : " << result;
    return result;
  }

  result = InformContactsOperation<UpdateShareTag>(sender_public_username,
                                                   contacts,
                                                   share_id,
                                                   "",
                                                   directory_id,
                                                   key_ring,
                                                   new_share_id);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed in informing contacts in share: "
                << Base32Substr(share_id) << ", with result of : " << result;
    return result;
  }

  return kSuccess;
}

int UserStorage::GetShareUsersRights(const fs::path &absolute_path,
                                     const std::string &user_id,
                                     bool *admin_rights) const {
  return drive_in_user_space_->GetShareUsersRights(
             drive_in_user_space_->RelativePath(absolute_path),
             user_id,
             admin_rights);
}

int UserStorage::SetShareUsersRights(const std::string &sender_public_username,
                                     const fs::path &absolute_path,
                                     const std::string &user_id,
                                     bool admin_rights) {
  fs::path relative_path(drive_in_user_space_->RelativePath(absolute_path));
  bool old_admin_right;
  int result(drive_in_user_space_->GetShareUsersRights(relative_path,
                                                       user_id,
                                                       &old_admin_right));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed getting admin right for contact " << user_id
                << ", with result : " << result;
    return result;
  }

  result = drive_in_user_space_->SetShareUsersRights(relative_path,
                                                     user_id,
                                                     admin_rights);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed setting admin right for contact " << user_id
                << ", with result : " << result;
    return result;
  }

  std::map<std::string, bool> contacts;
  contacts.insert(std::make_pair(user_id, admin_rights));

  if ((!old_admin_right) && admin_rights) {
    asymm::Keys key_ring;
    std::string share_id;
    result = drive_in_user_space_->GetShareDetails(relative_path,
                                                   nullptr,
                                                   &key_ring,
                                                   &share_id,
                                                   nullptr,
                                                   nullptr);
     if (result != kSuccess) {
      DLOG(ERROR) << "Failed getting admin right for contact " << user_id
                  << ", with result : " << result;
      return result;
    }

    // In case of upgrading : just inform the contact of the share key_ring.
    result = InformContactsOperation<UpgradeShareTag>(sender_public_username,
                                                      contacts,
                                                      share_id,
                                                      "",
                                                      "",
                                                      key_ring);
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed informing " << user_id
                  << ", with result : " << result;
      return result;
    }
  } else if (old_admin_right && (!admin_rights)) {
    // In case of downgrading : generate new share_id/key and inform all
    // i.e. remove that contact at first then add it back
    // however this may cause the receiver's path to be changed when re-added.
    std::vector<std::string> user;
    user.push_back(user_id);
    int result(RemoveShareUsers(sender_public_username, absolute_path, user));
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed in remove contact " << user_id
                  << "  during the downgrading "
                  << ", with result of : " << result;
      return result;
    }
    result = AddShareUsers(sender_public_username, absolute_path, contacts);
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
  return drive_in_user_space_->GetNotes(
             drive_in_user_space_->RelativePath(absolute_path),
             notes);
}

int UserStorage::AddNote(const fs::path &absolute_path,
                         const std::string &note) {
  return drive_in_user_space_->AddNote(
             drive_in_user_space_->RelativePath(absolute_path),
             note);
}

int UserStorage::ReadHiddenFile(const fs::path &absolute_path,
                                std::string *content) const {
  return drive_in_user_space_->ReadHiddenFile(
             drive_in_user_space_->RelativePath(absolute_path),
             content);
}

int UserStorage::WriteHiddenFile(const fs::path &absolute_path,
                                 const std::string &content,
                                 bool overwrite_existing) {
  return drive_in_user_space_->WriteHiddenFile(
             drive_in_user_space_->RelativePath(absolute_path),
             content,
             overwrite_existing);
}

int UserStorage::DeleteHiddenFile(const fs::path &absolute_path) {
  return drive_in_user_space_->DeleteHiddenFile(
             drive_in_user_space_->RelativePath(absolute_path));
}

int UserStorage::SearchHiddenFiles(const fs::path &absolute_path,
                                   const std::string &regex,
                                   std::list<std::string> *results) {
  return drive_in_user_space_->SearchHiddenFiles(
             drive_in_user_space_->RelativePath(absolute_path),
             regex,
             results);
}

bs2::connection UserStorage::ConnectToDriveChanged(
    drive::DriveChangedSlotPtr slot) const {
  return drive_in_user_space_->ConnectToDriveChanged(slot);
}

bs2::connection UserStorage::ConnectToShareChanged(
    drive::ShareChangedSlotPtr slot) const {
  return drive_in_user_space_->ConnectToShareChanged(slot);
}

pcs::RemoteChunkStore::ValidationData UserStorage::PopulateValidationData(
    const asymm::Keys &key_ring) {
  pcs::RemoteChunkStore::ValidationData validation_data;
  validation_data.key_pair = key_ring;
  pca::SignedData signed_data;
  signed_data.set_data(RandomString(64));
  asymm::Sign(signed_data.data(),
              validation_data.key_pair.private_key,
              &validation_data.ownership_proof);
  signed_data.set_signature(validation_data.ownership_proof);
  validation_data.ownership_proof = signed_data.SerializeAsString();
  return validation_data;
}

template<typename Operation>
int UserStorage::InformContactsOperation(
    const std::string &sender_public_username,
    const std::map<std::string, bool> &contacts,
    const std::string &share_id,
    const std::string &absolute_path,
    const std::string &directory_id,
    const asymm::Keys &key_ring,
    const std::string &new_share_id) {
  pca::Message admin_message, non_admin_message;
  std::string public_key, private_key, parent_id(RandomString(64)),
              id(RandomString(64));

  admin_message.set_type(pca::Message::kSharedDirectory);
  admin_message.set_parent_id(parent_id);
  admin_message.set_id(id);
  admin_message.set_sender_public_username(sender_public_username);
  admin_message.add_content(share_id);
  non_admin_message.set_type(pca::Message::kSharedDirectory);
  non_admin_message.set_parent_id(parent_id);
  non_admin_message.set_id(id);
  non_admin_message.set_sender_public_username(sender_public_username);
  non_admin_message.add_content(share_id);
  AddMessageDetails<Operation>()(absolute_path,
                                 directory_id,
                                 new_share_id,
                                 &admin_message,
                                 &non_admin_message);
  admin_message.add_content(key_ring.identity);
  admin_message.add_content(key_ring.validation_token);
  asymm::EncodePrivateKey(key_ring.private_key, &private_key);
  admin_message.add_content(private_key);
  asymm::EncodePublicKey(key_ring.public_key, &public_key);
  admin_message.add_content(public_key);

  int result, aggregate(0);
  for (auto it = contacts.begin(); it != contacts.end(); ++it) {
    // do nothing if trying to send a msg to itself
    if ((*it).first != sender_public_username) {
      if ((*it).second) {
        result = message_handler_->Send(sender_public_username,
                                        (*it).first,
                                        admin_message);
      } else {
        result = message_handler_->Send(sender_public_username,
                                        (*it).first,
                                        non_admin_message);
      }
      if (result != kSuccess) {
        DLOG(ERROR) << "Failed in inform contact " << (*it).first
                    << "  of operation " << ", with result of : "
                    << result;
        ++aggregate;
      }
    }
  }

  return aggregate;
}

}  // namespace lifestuff

}  // namespace maidsafe
