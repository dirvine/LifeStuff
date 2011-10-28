/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Created:      2011-10-27
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

#include "maidsafe/lifestuff/data_handler.h"

#include "maidsafe/common/chunk_store.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/returncodes.h"

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4244)
#endif
#include "maidsafe/lifestuff/lifestuff_messages.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

namespace maidsafe {

namespace lifestuff {

DataHandler::DataHandler() {}

DataHandler::~DataHandler() {}

int DataHandler::ProcessData(const std::string data,
                             std::shared_ptr<ChunkStore> chunk_store) {
  DataWrapper data_wrapper;
  if (!data_wrapper.ParseFromString(data)) {
    DLOG(WARNING) << "Failed to parse data. Could be chunk.";
    return -1;  // k
  }

  switch (data_wrapper.data_type()) {
    case DataWrapper::HASHABLE_SIGNED:
    case DataWrapper::NON_HASHABLE_SIGNED:
  }
}


}  // namespace lifestuff

}  // namespace maidsafe

