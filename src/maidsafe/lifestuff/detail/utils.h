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

//#include <condition_variable>
//#include <memory>
//#include <mutex>
//#include <string>
//#include <vector>
//
//#include "boost/lexical_cast.hpp"
//#include "boost/filesystem/path.hpp"
//
//#include "maidsafe/common/rsa.h"
//#include "maidsafe/common/utils.h"
//
//#include "maidsafe/private/utils/fob.h"
//
//namespace fs = boost::filesystem;
//

#include "maidsafe/nfs/client_utils.h"

namespace maidsafe {
namespace lifestuff {

typedef std::function<void(maidsafe::nfs::Reply)> ReplyFunction;

struct Free;
struct Paid;

namespace detail {
  template <typename Duty>
  struct PutFobs {
    typedef maidsafe::nfs::ClientMaidNfs ClientNfs;
    typedef passport::Passport Passport;

    void operator()(ClientNfs&, Passport&, ReplyFunction&) {}
  };

  template <>
  struct PutFobs<Free> {
    typedef maidsafe::nfs::ClientMaidNfs ClientNfs;
    typedef passport::Passport Passport;
    typedef passport::Anmaid Anmaid;
    typedef passport::PublicAnmaid PublicAnmaid;
    typedef passport::Maid Maid;
    typedef passport::PublicMaid PublicMaid;
    typedef passport::Pmid Pmid;
    typedef passport::PublicPmid PublicPmid;

    void operator()(ClientNfs& client_nfs, Passport& passport, ReplyFunction& reply) {
      Pmid::name_type pmid_name(passport.Get<Pmid>(false).name());
      PublicAnmaid public_anmaid(passport.Get<Anmaid>(false));
      PublicMaid public_maid(passport.Get<Maid>(false));
      PublicPmid public_pmid(passport.Get<Pmid>(false));

      maidsafe::nfs::Put<PublicAnmaid>(client_nfs, public_anmaid, pmid_name, 3, reply);
      maidsafe::nfs::Put<PublicMaid>(client_nfs, public_maid, pmid_name, 3, reply);
      maidsafe::nfs::Put<PublicPmid>(client_nfs, public_pmid, pmid_name, 3, reply);
    }
  };

  template <>
  struct PutFobs<Paid> {
    typedef maidsafe::nfs::ClientMaidNfs ClientNfs;
    typedef passport::Passport Passport;
    typedef passport::Anmid Anmid;
    typedef passport::PublicAnmid PublicAnmid;
    typedef passport::Ansmid Ansmid;
    typedef passport::PublicAnsmid PublicAnsmid;
    typedef passport::Antmid Antmid;
    typedef passport::PublicAntmid PublicAntmid;
    typedef passport::Pmid Pmid;

    void operator()(ClientNfs& client_nfs, Passport& passport, ReplyFunction& reply) {
      Pmid::name_type pmid_name(passport.Get<Pmid>(true).name());
      PublicAnmid public_anmid(passport.Get<Anmid>(true));
      PublicAnsmid public_ansmid(passport.Get<Ansmid>(true));
      PublicAntmid public_antmid(passport.Get<Antmid>(true));

      maidsafe::nfs::Put<PublicAnmid>(client_nfs, public_anmid, pmid_name, 3, reply);
      maidsafe::nfs::Put<PublicAnsmid>(client_nfs, public_ansmid, pmid_name, 3, reply);
      maidsafe::nfs::Put<PublicAntmid>(client_nfs, public_antmid, pmid_name, 3, reply);
    }
  };
}  // namespace detail

//
//enum InboxItemType {
//  kChat,
//  kFileTransfer,
//  kContactPresence,
//  kContactProfilePicture,
//
//  // Max
//  kMaxInboxItemType = kContactProfilePicture
//};
//
//struct InboxItem {
//  explicit InboxItem(InboxItemType inbox_item_type = kChat);
//
//  InboxItemType item_type;
//  NonEmptyString sender_public_id;
//  NonEmptyString receiver_public_id;
//  std::vector<NonEmptyString> content;
//  NonEmptyString timestamp;
//};
//
//struct OperationResults {
//  OperationResults(std::mutex& mutex_in,
//                   std::condition_variable& conditional_variable_in,
//                   std::vector<int>& individual_results_in)
//      : mutex(mutex_in),
//        conditional_variable(conditional_variable_in),
//        individual_results(individual_results_in) {}
//  std::mutex& mutex;
//  std::condition_variable& conditional_variable;
//  std::vector<int>& individual_results;
//};
//
//NonEmptyString CreatePin();
//
//int CheckKeywordValidity(const NonEmptyString& keyword);
//int CheckPinValidity(const NonEmptyString& pin);
//int CheckPasswordValidity(const NonEmptyString& password);
//
//int CheckPublicIdValidity(const NonEmptyString& public_id);
//
//fs::path CreateTestDirectory(fs::path const& parent, std::string* tail);
//int CreateTestFile(fs::path const& parent, int size_in_mb, std::string* file_name);
//int CreateSmallTestFile(fs::path const& parent, int size_in_kb, std::string* file_name);
//
//int AssessJointResult(const std::vector<int>& results);
//void OperationCallback(bool result, OperationResults& results, int index);
//
//NonEmptyString ComposeModifyAppendableByAll(const asymm::PrivateKey& signing_key,
//                                            const bool appendability);
//NonEmptyString AppendableIdValue(const Fob& data, bool accepts_new_contacts);
//NonEmptyString SignaturePacketValue(const Fob& keys);
//
//priv::ChunkId ComposeSignaturePacketName(const Identity& name);
//priv::ChunkId MaidsafeContactIdName(const NonEmptyString& public_id);
//priv::ChunkId SignaturePacketName(const Identity& name);
//priv::ChunkId AppendableByAllName(const Identity& name);
//priv::ChunkId ModifiableName(const Identity& name);
//
//encrypt::DataMap ParseSerialisedDataMap(const NonEmptyString& serialised_data_map);
//
//std::string PutFilenameData(const std::string& file_name);
//void GetFilenameData(const std::string& content,
//                     std::string& file_name,
//                     std::string& serialised_data_map);
//std::string GetNameInPath(const fs::path& save_path, const std::string& file_name);
//int CopyDir(const fs::path& source, const fs::path& dest);
//int CopyDirectoryContent(const fs::path& from, const fs::path& to);
//bool VerifyOrCreatePath(const fs::path& path);
//
//std::string IsoTimeWithMicroSeconds();
//
//NonEmptyString MessagePointToPoint(const NonEmptyString& unwrapped_message,
//                                   const asymm::PublicKey& recipient_public_key,
//                                   const asymm::PrivateKey& sender_private_key);
//bool PointToPointMessageValid(const NonEmptyString& wrapped_message,
//                              const asymm::PublicKey& sender_public_key,
//                              const asymm::PrivateKey& receiver_private_key,
//                              std::string& final_message);

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_UTILS_H_
