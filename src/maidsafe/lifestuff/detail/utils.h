/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_UTILS_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_UTILS_H_

#include <memory>
#include <string>
#include <vector>

#include "boost/lexical_cast.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/filesystem/path.hpp"

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt { struct DataMap; }

namespace lifestuff {

enum InboxItemType {
  kChat,
  kFileTransfer,
  kContactPresence,
  kContactProfilePicture,
  kContactDeletion,
  kRespondToShareInvitation,
  kPrivateShareInvitation,
  kPrivateShareDeletion,
  kPrivateShareMembershipUpgrade,
  kPrivateShareMembershipDowngrade,
  kPrivateShareKeysUpdate,
  kPrivateShareMemberLeft,
  kOpenShareInvitation,

  // Max
  kMaxInboxItemType = kOpenShareInvitation
};

struct InboxItem {
  explicit InboxItem(InboxItemType inbox_item_type = kChat);

  InboxItemType item_type;
  std::string sender_public_id;
  std::string receiver_public_id;
  std::vector<std::string> content;
  std::string timestamp;
};

enum MessageContentIndexes {
  kShareId = 0,
  kShareName,
  kDirectoryId,
  kNewShareId,
  kKeysIdentity,
  kKeysValidationToken,
  kKeysPrivateKey,
  kKeysPublicKey,
  // Max
  kMaxMessageContentIndexes = kKeysPublicKey
};

enum ShareType {
  kOpenOwner = 0,
  kOpenMember = 1,
  kPrivateOwner = 2,
  kPrivateMember = 3,

  // Max
  kMaxShareType = kPrivateMember
};

struct OperationResults {
  OperationResults(boost::mutex &mutex_in,
                   boost::condition_variable &conditional_variable_in,
                   std::vector<int> &individual_results_in)
      : mutex(mutex_in),
        conditional_variable(conditional_variable_in),
        individual_results(individual_results_in) {}
  boost::mutex &mutex;
  boost::condition_variable &conditional_variable;
  std::vector<int> &individual_results;
};

std::string CreatePin();

int CheckKeywordValidity(const std::string &keyword);
int CheckPinValidity(const std::string &pin);
int CheckPasswordValidity(const std::string &password);

int CheckPublicIdValidity(const std::string &public_id);

fs::path CreateTestDirectory(fs::path const& parent, std::string *tail);
int CreateTestFile(fs::path const& parent, int size_in_mb, std::string *file_name);
int CreateSmallTestFile(fs::path const& parent, int size_in_kb, std::string *file_name);

void ChunkStoreOperationCallback(const bool &response,
                                 boost::mutex *mutex,
                                 boost::condition_variable *cond_var,
                                 int *result);

int WaitForResults(boost::mutex &mutex,
                   boost::condition_variable &cond_var,
                   std::vector<int> &results);

int AssessJointResult(const std::vector<int> &results);
void OperationCallback(bool result, OperationResults &results, int index);

std::string ComposeSignaturePacketName(const std::string &name);

std::string ComposeSignaturePacketValue(const asymm::Keys &packet);

std::shared_ptr<encrypt::DataMap> ParseSerialisedDataMap(const std::string &serialised_data_map);

std::string PutFilenameData(const std::string &file_name);
void GetFilenameData(const std::string &content,
                     std::string *file_name,
                     std::string *serialised_data_map);
std::string GetNameInPath(const fs::path &save_path, const std::string &file_name);
bool CheckCorrectKeys(const std::vector<std::string> &content, asymm::Keys *keys);
int CopyDir(const fs::path& source, const fs::path& dest);
int CopyDirectoryContent(const fs::path& from, const fs::path& to);
bool VerifyOrCreatePath(const fs::path& path);

std::string IsoTimeWithMicroSeconds();

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_UTILS_H_
