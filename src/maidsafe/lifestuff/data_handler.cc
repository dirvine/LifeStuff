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
#include "maidsafe/common/crypto.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/lifestuff_messages_pb.h"

namespace maidsafe {

namespace lifestuff {

DataHandler::DataHandler()
    : get_data_signal_(new GetDataSignalPtr::element_type) {}

DataHandler::~DataHandler() {}

DataHandler::GetDataSignalPtr DataHandler::get_data_signal() {
  return get_data_signal_;
}

int DataHandler::ProcessData(const OperationType &op_type,
                             const std::string &name,
                             const std::string &data,
                             const std::string &public_key,
                             std::shared_ptr<ChunkStore> chunk_store) {
  if (op_type == DataHandler::kHas) {
    if (chunk_store->Has(name))
      return kKeyNotUnique;
    else
      return kKeyUnique;
  }

  DataWrapper data_wrapper;
  if (op_type != DataHandler::kGet) {
    if (!data_wrapper.ParseFromString(data)) {
      DLOG(WARNING) << "Failed to parse data. Could be chunk.";
      return -1;
    }
  }

  switch (data_wrapper.data_type()) {
    case DataWrapper::kHashableSigned:
        return ProcessSignedData(op_type, name, data_wrapper, public_key, true,
                                 chunk_store);
    case DataWrapper::kNonHashableSigned:
        return ProcessSignedData(op_type, name, data_wrapper, public_key, false,
                                 chunk_store);
    default: return -1;
  }
}

int DataHandler::ProcessSignedData(const OperationType &op_type,
                                   const std::string &name,
                                   const DataWrapper &data_wrapper,
                                   const std::string &public_key,
                                   const bool &hashable,
                                   std::shared_ptr<ChunkStore> chunk_store) {
  if (PreOperationChecks(op_type, name, data_wrapper, public_key, hashable) !=
      kSuccess) {
    DLOG(ERROR) << "ProcessSignedData - PreOperationChecks failure.";
    return -1;
  }

  std::string current_data;
  switch (op_type) {
    case kStore: {
        if (chunk_store->Has(name)) {
          DLOG(ERROR) << "ProcessSignedData - Name of data exists. Use update.";
          return -1;
        }
        if (!chunk_store->Store(name, data_wrapper.SerializeAsString())) {
          DLOG(ERROR) << "ProcessSignedData - ChunkStore Store failure.";
          return -1;
        }
        break;
    }
    case kDelete: {
        if (VerifyCurrentData(name, public_key, chunk_store, &current_data) !=
            kSuccess) {
          DLOG(ERROR) << "ProcessSignedData - VerifyCurrentData failure.";
          return -1;
        }

        if (!chunk_store->Delete(name)) {
          DLOG(ERROR) << "ProcessSignedData - Error deleting packet";
          return -1;
        }

        break;
    }
    case kUpdate: {
        if (VerifyCurrentData(name, public_key, chunk_store, &current_data) !=
            kSuccess) {
          DLOG(ERROR) << "ProcessSignedData - VerifyCurrentData failure.";
          return -1;
        }

        if (!chunk_store->Delete(name)) {
          DLOG(ERROR) << "ProcessSignedData - Error deleting packet";
          return -1;
        }

        if (!chunk_store->Store(name, data_wrapper.SerializeAsString())) {
          DLOG(ERROR) << "ProcessSignedData - Error deleting packet";
          return -1;
        }

        break;
    }
    case kGet: {
        if (VerifyCurrentData(name, public_key, chunk_store, &current_data) !=
            kSuccess) {
          DLOG(ERROR) << "ProcessSignedData - VerifyCurrentData failure.";
          return -1;
        }

        (*get_data_signal_)(current_data);
        break;
    }
    case kHas: DLOG(INFO) << "At this moment, code should not reach here.";
  }

  return kSuccess;
}

int DataHandler::PreOperationChecks(const OperationType &op_type,
                                    const std::string &name,
                                    const DataWrapper &data_wrapper,
                                    const std::string &public_key,
                                    const bool &hashable) {
  if (op_type == kGet)
    return kSuccess;

  if (!data_wrapper.has_signed_data()) {
    DLOG(ERROR) << "ProcessSignedData - No signed data passed";
    return -1;
  }

  if (hashable && op_type == kUpdate) {
    DLOG(ERROR) << "ProcessSignedData - No update of hashable data allowed";
    return -1;
  }


  if (!crypto::AsymCheckSig(data_wrapper.signed_data().data(),
                            data_wrapper.signed_data().signature(),
                            public_key)) {
    DLOG(ERROR) << "ProcessSignedData - Signature verification failed";
    return -1;
  }

  if (hashable &&
      crypto::Hash<crypto::SHA512>(data_wrapper.signed_data().data() +
                                   data_wrapper.signed_data().signature()) !=
      name) {
    DLOG(ERROR) << "ProcessSignedData - Marked hashable, doesn't hash";
    return -1;
  }

  return kSuccess;
}

int DataHandler::VerifyCurrentData(const std::string &name,
                                   const std::string &public_key,
                                   std::shared_ptr<ChunkStore> chunk_store,
                                   std::string *current_data) {
  *current_data = chunk_store->Get(name);
  if (current_data->empty()) {
    DLOG(ERROR) << "VerifyCurrentData - Failure to get data";
    return -1;
  }

  DataWrapper dw;
  if (!dw.ParseFromString(*current_data)) {
    DLOG(ERROR) << "VerifyCurrentData - Error parsing packet";
    return -1;
  }

  if (!public_key.empty() &&
      dw.has_signed_data() &&
      !crypto::AsymCheckSig(dw.signed_data().data(),
                            dw.signed_data().signature(),
                            public_key)) {
    DLOG(ERROR) << "VerifyCurrentData - Not owner of packet";
    return -1;
  }

  *current_data = dw.signed_data().SerializeAsString();

  return kSuccess;
}

}  // namespace lifestuff

}  // namespace maidsafe

