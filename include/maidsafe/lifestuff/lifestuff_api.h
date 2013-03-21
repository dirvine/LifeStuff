/***************************************************************************************************
 *  Copyright 2013 MaidSafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use.  The use of this code is governed by the licence file licence.txt found in the root of    *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit         *
 *  written permission of the board of directors of MaidSafe.net.                                  *
 **************************************************************************************************/

#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_
#define MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_

#include <memory>

#include "maidsafe/lifestuff/lifestuff.h"

namespace maidsafe {
namespace lifestuff {

class LifeStuffImpl;

class LifeStuff {
 public:
  LifeStuff(const Slots& slots);
  ~LifeStuff();

  ReturnCode InsertUserInput(uint32_t position, char character, InputField input_field);
  ReturnCode RemoveUserInput(uint32_t position, uint32_t length, InputField input_field);
  ReturnCode ClearUserInput(InputField input_field);
  bool ConfirmUserInput(InputField input_field);

  ReturnCode CreateUser(const std::string& vault_path, ReportProgressFunction& report_progress);
  ReturnCode LogIn(ReportProgressFunction& report_progress);
  ReturnCode LogOut();

  ReturnCode MountDrive();
  ReturnCode UnMountDrive();

  ReturnCode ChangeKeyword();
  ReturnCode ChangePin();
  ReturnCode ChangePassword();

  bool logged_in() const;

  std::string mount_path();
  std::string owner_path();

 private:
  std::unique_ptr<LifeStuffImpl> lifestuff_impl_;
};

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_



//
//#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_
//#define MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_
//
//#include <string>
//#include <vector>
//
//#include "boost/filesystem/path.hpp"
//
//#include "maidsafe/common/log.h"
//
//#include "maidsafe/lifestuff/lifestuff.h"
//#include "maidsafe/lifestuff/securestring_api.h"
//
//
//namespace fs = boost::filesystem;
//
//namespace maidsafe {
//
//namespace lifestuff {
//
//class LifeStuffImpl;
//
//class LifeStuff {
// public:
//  LifeStuff();
//  ~LifeStuff();
//
//  LifeStuffReturn LogIn(const SecureString& pin,
//                        const SecureString& password,
//                        const SecureString& keyword);
//  LifeStuffReturn LogOut();
//
//  void MountDrive();
//  void UnMountDrive();
//
//  //  Creates a new lifestuff user. Requires Pin, Password & Keyword to have been successfully set
//  //  optional <vault> location of vault to be associated with user
//  LifeStuffReturn CreateUser(const fs::path& vault = fs::path());
//  // Creates a new public id. Requires Pin, Pwd & Keyword to have been successfully set
//  bool CreatePublicId(const std::string& public_id);
//  bool ChangePublicId(const std::string& old_public_id, const std::string& new_public_id);
//  std::string GetPublicId() const;
//
//  //  Credential operations
//  bool ChangeKeyword(const SecureString& old_keyword, const SecureString& new_keyword);
//  bool ChangePin(const SecureString& old_pin, const SecureString& new_pin);
//  bool ChangePassword(const SecureString& old_password, const SecureString& new_password);
//  
//
//  /// Vault Operations
//  //  registers a new vault at <vault_root> of size <vault_capacity> (kB) (TODO - check appropriate
//  //  unit for this) to account <my_public_id>
//  LifeStuffReturn AddNewVault(const std::string& my_public_id,
//                              uint64_t vault_capacity,
//                              const fs::path& vault_root);
//
//  //  shares vault <vault_id> between account <my_public_id> and <contact_public_id>
//  LifeStuffReturn ShareVault(const std::string& my_public_id,
//                             const std::string& contact_public_id,
//                             const std::string& vault_id);
//
//  //  returns vault information for all vaults registered to <my_public_id>
//  std::vector<VaultUsageInfo> GetVaultInfo(const std::string& my_public_id);
//
//  //  accept share vault request from <sender_public_id> specified by <request_id>
//  LifeStuffReturn AcceptShareVault(const std::string& sender_public_id,
//                                   const std::string& request_id);
//
//  //  reject share vault request from <sender_public_id> specified by <request_id>
//  void RejectShareVault(const std::string& sender_public_id, const std::string& request_id);
//
//
//  /// Network Info
//  uint64_t NetworkPopulation(const std::string& my_public_id);
//
//  uint64_t AverageDedupSizeInKB(const std::string& my_public_id);
//
//  float AverageDedupPercentage(const std::string& my_public_id);
//
//  uint64_t AverageDiskStoredSizeInKB(const std::string& my_public_id);
//
//
//  /// Contact operations
//  //  sends a request identified by <request_id> from <my_public_id> to add <contact_public_id>
//  //  as a contact, with optional <message>
//  LifeStuffReturn AddContact(const std::string& my_public_id,
//                             const std::string& contact_public_id,
//                             const std::string& message);
//
//  //  confirms add contact request <request_id> from <contact_public_id>
//  void ConfirmContact(const std::string& my_public_id,
//                      const std::string& contact_public_id);
//
//  //  declines add contact request <request_id> from <contact_public_id>
//  void DeclineContact(const std::string& my_public_id,
//                      const std::string& contact_public_id);
//
//  //  removes <contact_public_id> from <my_public_id> contact list, with optional <removal_message>
//  LifeStuffReturn RemoveContact(const std::string& my_public_id,
//                                const std::string& contact_public_id,
//                                const std::string& removal_message);
//
//  LifeStuffReturn RemoveContact(const std::string& my_public_id,
//                                const std::string& contact_public_id);
//
//  //  blocks <contact_public_id> from sending requests/messages/files to <my_public_id>
//  LifeStuffReturn BlockContact(const std::string& my_public_id,
//                               const std::string& contact_public_id);
//
//  //  removes any block on <contact_public_id> by <my_public_id>
//  LifeStuffReturn UnBlockContact(const std::string& my_public_id,
//                                 const std::string& contact_public_id);
//
//  //  flags <contact_public_id> as spam by <my_public_id>. Will result in a decrease of
//  //  <contact_public_id> ranking
//  LifeStuffReturn FlagContactAsSpam(const std::string& my_public_id,
//                                    const std::string& contact_public_id);
//
//  //  reverses any lowering of <contact_public_id> ranking as a result of having been marked as spam
//  //  by <my_public_id>
//  LifeStuffReturn RemoveSpamFlag(const std::string& my_public_id,
//                                 const std::string& contact_public_id);
//
//  //  returns vector of contact public ids for <my_public_id>. List returned will be made up of
//  //  confirmed contacts or requested contacts or both, depending on <bitwise_status>
//  std::vector<std::string> GetContacts(const std::string& my_public_id,
//                                       uint16_t bitwise_status = kConfirmed | kRequestSent) const;
//
//  //  returns rank of <contact_public_id>
//  ContactRank GetContactRank(const std::string& my_public_id,
//                             const std::string& contact_public_id) const;
//
//  //  returns current contact status of <contact_public_id>
//  ContactStatus GetContactStatus(const std::string& my_public_id,
//                                 const std::string& contact_public_id) const;
//
//  //  returns current online/offline status of <contact_public_id>
//  ContactPresence GetContactPresence(const std::string& my_public_id,
//                                     const std::string& contact_public_id) const;
//
//  /// Send Element
//  //  sends element at <relative_path> from <my_public_id> to <receiver_public_id> with optional
//  //  <message>
//  LifeStuffReturn SendElement(const std::string& my_public_id,
//                              const std::string& receiver_public_id,
//                              const fs::path& relative_path,
//                              const std::string& message);
//
//  //  accepts the element sent by <sender_public_id> corresponding to the <request_id>
//  LifeStuffReturn AcceptSentElement(const std::string& sender_public_id,
//                                    const std::string& request_id);
//
//  //  rejects the element sent by <sender_public_id> corresponding to the <request_id>
//  void RejectSentElement(const std::string& sender_public_id,
//                         const std::string& request_id);
//
//  /// Share File / Directory
//  //  Personal info can be created under a structured directory, allowing multi-level access rights
//  //  An <share_level> setting of kOwner = non shared data
//  //                              kGroup = privately shared data
//  //                              kWorld = globally shared data
//  LifeStuffReturn SetShareLevel(const std::string& my_public_id,
//                                const fs::path& relative_path,
//                                ShareLevel share_level);
//
//  LifeStuffReturn GetShareLevel(const std::string& my_public_id,
//                                const fs::path& relative_path,
//                                ShareLevel* share_level);
//
//  /// Public Sharing
//  //  sends an offer from <my_public_id> to share <relative_path> with <receiver_public_id>
//  //  identified by <request_id>
//  LifeStuffReturn ShareElement(const std::string& my_public_id,
//                               const std::string& receiver_public_id,
//                               const fs::path& relative_path);
//
//  LifeStuffReturn AcceptShareElement(const std::string& sender_public_id,
//                                     const std::string& request_id,
//                                     const fs::path& relative_path,
//                                     std::string* file_name = nullptr);
//
//  //  rejects offer of share from <sender_public_id>, identified by <request_id>
//  void RejectShareElement(const std::string& sender_public_id,
//                          const std::string& request_id);
//
//  /// Subscribe
//  //  subscribes <my_public_id> to any updates of <relative_path> belonging to <receiver_public_id>
//  LifeStuffReturn Subscribe(const std::string& my_public_id,
//                            const std::string& receiver_public_id,
//                            const fs::path& relative_path);
//
//  //  unsubscribes <my_public_id> from any subsequent updates of <relative_path> belonging to
//  //  <receiver_public_id>
//  LifeStuffReturn UnSubscribe(const std::string& my_public_id,
//                              const std::string& receiver_public_id,
//                              const fs::path& relative_path);
//
//  /// For both Share and Subscribe
//  //  returns list of who are following (by sharing or subscribe) <relative_path>
//  std::vector<std::string> GetFollowers(const std::string& my_public_id,
//                                        const fs::path& relative_path);
//
//  /// Messaging / Notification / Email
//  //  sends message with content <message> from <sender_public_id> to <receiver_public_id>,
//  LifeStuffReturn SendMessage(const std::string& sender_public_id,
//                              const std::string& receiver_public_id,
//                              const std::string& message);
//
//  /// Filesystem
//  LifeStuffReturn ReadHiddenFile(const fs::path& relative_path, std::string* content) const;
//
//  LifeStuffReturn WriteHiddenFile(const fs::path& relative_path,
//                                  const std::string& content,
//                                  bool overwrite_existing);
//
//  LifeStuffReturn DeleteHiddenFile(const fs::path& relative_path);
//
//  LifeStuffReturn SearchHiddenFiles(const fs::path& relative_path,
//                                    std::vector<std::string>* results);
//
//
//  LifeStuffState state() const;
//  LoggedInState logged_in_state() const;
//  bool ReadyForLogOut() const;
//
////  /// legacy - establish if required
////  fs::path mount_path() const;
//
// private:
//  std::unique_ptr<LifeStuffImpl> lifestuff_impl_;
//};
//
//}  // namespace lifestuff
//
//}  // namespace maidsafe
//
//#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_
