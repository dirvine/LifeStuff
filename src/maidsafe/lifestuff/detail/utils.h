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
