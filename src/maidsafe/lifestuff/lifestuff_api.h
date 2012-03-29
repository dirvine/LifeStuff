/*
* ============================================================================
*
* Copyright [2012] maidsafe.net limited
*
* Description:  Definition of system-wide constants/enums/structs
* Version:      1.0
* Created:      2012-03-27
* Revision:     none
* Compiler:     gcc
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

#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_
#define MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_

#include <string>

#include "boost/filesystem/path.hpp"

#include "maidsafe/drive/drive_api.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/version.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 400
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif


namespace maidsafe {

namespace lifestuff {

class LifeStuff {
 public:
  int Initialise(const boost::filesystem::path &base_directory);

  int ConnectToSignals(
      drive::DriveChangedSlotPtr drive_change_slot,
      drive::ShareChangedSlotPtr share_change_slot,
      const ChatFunction &chat_slot,
      const FileTransferFunction &file_slot,
      const ShareFunction &share_slot,
      const NewContactFunction &new_contact_slot,
      const ContactConfirmationFunction &confirmed_contact_slot,
      const ContactProfilePictureFunction &profile_picture_slot,
      const ContactPresenceFunction &contact_presence_slot);

  int CreateUser(const std::string &username,
                 const std::string &pin,
                 const std::string &password);

  int CreatePublicId(const std::string &public_id);

  int LogIn(const std::string &username,
            const std::string &pin,
            const std::string &password);

  int LogOut();

  int Finalise();

  int SendChatMessage(const std::string &sender_public_id,
                      const std::string &receiver_public_id,
                      const std::string &message);

  int ChangeProfilePicture(const std::string &sender_public_id,
                           const fs::path &path_to_profile_picture);

 private:
  struct Elements;
  std::shared_ptr<Elements> lifestuff_elements;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_
