/* Copyright 2013 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_
#define MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_

#include "boost/filesystem/path.hpp"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/detail/client_maid.h"
#include "maidsafe/lifestuff/detail/client_mpid.h"

namespace maidsafe {
namespace lifestuff {

class LifeStuffImpl {
 public:
  explicit LifeStuffImpl(const Slots& slots);
  ~LifeStuffImpl();

  void InsertUserInput(uint32_t position, const std::string& characters, InputField input_field);
  void RemoveUserInput(uint32_t position, uint32_t length, InputField input_field);
  void ClearUserInput(InputField input_field);
  bool ConfirmUserInput(InputField input_field);

  void CreateUser(const boost::filesystem::path& vault_path, ReportProgressFunction& report_progress);
  void LogIn(ReportProgressFunction& report_progress);
  void LogOut();
  void MountDrive();
  void UnMountDrive();

  void ChangeKeyword(ReportProgressFunction& report_progress);
  void ChangePin(ReportProgressFunction& report_progress);
  void ChangePassword(ReportProgressFunction& report_progress);

  bool logged_in() const;

  boost::filesystem::path mount_path();
  boost::filesystem::path owner_path();

  void CreatePublicId(const NonEmptyString& public_id);

 private:
  void FinaliseUserInput();
  void ResetInput();
  void ResetConfirmationInput();

  bool logged_in_;
  std::unique_ptr<Keyword> keyword_, confirmation_keyword_;
  std::unique_ptr<Pin> pin_, confirmation_pin_;
  std::unique_ptr<Password> password_, confirmation_password_, current_password_;
  Session session_;
  ClientMaid client_maid_;
  ClientMpid client_mpid_;
};

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_
