/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Definition of system-wide constants/enums/structs
* Version:      1.0
* Created:      2009-01-29-00.15.50
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#include "maidsafe/lifestuff/lifestuff.h"

namespace maidsafe {

namespace lifestuff {

const size_t kMaxChatMessageSize(1 * 1024 * 1024);
const uint32_t kFileRecontructionLimit(20 * 1024 * 1024);
const uint8_t kThreads(10);
const uint8_t kSecondsInterval(5);
const size_t kMinWordSize(5);
const size_t kMaxWordSize(30);
const size_t kPinSize(4);
const std::string kLiteralOnline("kOnline");
const std::string kLiteralOffline("kOffline");
const std::string kBlankProfilePicture("BlankPicture");
const std::string kAppHomeDirectory(".lifestuff");
const std::string kMyStuff("My Stuff");
const std::string kDownloadStuff("Accepted Files");

const std::string kSharedStuff("Shared Stuff");
const std::string kHiddenFileExtension(".ms_hidden");

}  // namespace lifestuff

}  // namespace maidsafe
