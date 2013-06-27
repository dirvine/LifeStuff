/* Copyright 2011 MaidSafe.net limited

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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_UTILS_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_UTILS_H_

#include "maidsafe/passport/passport.h"
#include "maidsafe/nfs/client_utils.h"
#include "maidsafe/lifestuff/detail/session.h"

namespace maidsafe {
namespace lifestuff {

typedef std::function<void(maidsafe::nfs::Reply)> ReplyFunction;

struct Free;
struct Paid;

const char kCharRegex[] = ".*";
const char kDigitRegex[] = "\\d";

namespace detail {

  template <typename Duty>
  struct PutFobs {
    typedef maidsafe::nfs::ClientMaidNfs ClientNfs;
    typedef passport::Passport Passport;

    void operator()(ClientNfs&, Passport&, ReplyFunction&) {}
  };

  template <typename Input>
  struct InsertUserInput {
    typedef std::unique_ptr<Input> InputPtr;

    void operator()(InputPtr& input, uint32_t position, const std::string& characters) {
      if (!input)
        input.reset(new Input());
      input->Insert(position, characters);
      return;
    }
  };

  template <typename Input>
  struct RemoveUserInput {
    typedef std::unique_ptr<Input> InputPtr;

    void operator()(InputPtr& input, uint32_t position, uint32_t length) {
      if (!input)
        ThrowError(CommonErrors::uninitialised);
      input->Remove(position, length);
      return;
    }
  };

  template <typename Input>
  struct ClearUserInput {
    typedef std::unique_ptr<Input> InputPtr;

    void operator()(InputPtr& input) {
      if (input)
        input->Clear();
      return;
    }
  };

  template <typename Input>
  struct ConfirmUserInput {
    typedef std::unique_ptr<Input> InputPtr;

     bool operator()(InputPtr& input) {
      if (!input)
        return false;
      return input->IsValid(boost::regex(kCharRegex));
    }

    bool operator()(InputPtr& input, InputPtr& confirmation_input) {
      if (!input || !confirmation_input)
        return false;
      if (!input->IsFinalised())
        input->Finalise();
      if (!confirmation_input->IsFinalised())
        confirmation_input->Finalise();
      if (input->string() != confirmation_input->string()) {
        return false;
      }
      return true;
    }

    bool operator()(InputPtr& input, InputPtr& confirmation_input, InputPtr& current_input, const Session& session) {
      if (!current_input)
        return false;
      if (!current_input->IsFinalised())
        current_input->Finalise();
      if (input) {
        input->Finalise();
        if (!confirmation_input)
          return false;
        confirmation_input->Finalise();
        if (input->string() != confirmation_input->string()
            || session.password().string() != current_input->string())
          return false;
      } else {
        if (session.password().string() != current_input->string())
          return false;
      }
      return true;
    }
  };

}  // namespace detail

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_UTILS_H_
