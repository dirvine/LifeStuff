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

#ifndef MAIDSAFE_LIFESTUFF_MESSAGE_H_
#define MAIDSAFE_LIFESTUFF_MESSAGE_H_


#include <string>

#include "maidsafe/lifestuff/version.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 110
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif


namespace maidsafe {

namespace lifestuff {

struct Message {
  Message()
      : message_id(),
        parent_id(),
        sender_public_username(),
        subject(),
        content() {}
  Message(const std::string &message_id_in,
          const std::string &parent_id_in,
          const std::string &sender_public_username_in,
          const std::string &subject_in,
          const std::string &content_in)
      : message_id(message_id_in),
        parent_id(parent_id_in),
        sender_public_username(sender_public_username_in),
        subject(subject_in),
        content(content_in) {}
  std::string message_id, parent_id, sender_public_username, subject, content;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_MESSAGE_H_
