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

#include "maidsafe/lifestuff/data_types_pb.h"
#include "maidsafe/lifestuff/lifestuff_messages_pb.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/return_codes.h"

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
                             const rsa::PublicKey &public_key,
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
      return kParseFailure;
    }
  }

  switch (data_wrapper.data_type()) {
    case DataWrapper::kAnmpid:
    case DataWrapper::kMpid:
    case DataWrapper::kHashableSigned:
        return ProcessSignedData(op_type, name, data_wrapper, public_key, true,
                                 chunk_store);
    case DataWrapper::kNonHashableSigned:
        return ProcessSignedData(op_type, name, data_wrapper, public_key, false,
                                 chunk_store);
    case DataWrapper::kMsid:
        return ProcessMsidData(op_type, name, data_wrapper, public_key,
                               chunk_store);
    case DataWrapper::kMmid:
        return ProcessMmidData(op_type, name, data_wrapper, public_key,
                               chunk_store);
    default: return kUnknownFailure;
  }
}

int DataHandler::ProcessSignedData(const OperationType &op_type,
                                   const std::string &name,
                                   const DataWrapper &data_wrapper,
                                   const rsa::PublicKey &public_key,
                                   const bool &hashable,
                                   std::shared_ptr<ChunkStore> chunk_store) {
  if (PreOperationChecks(op_type, name, data_wrapper, public_key, hashable) !=
      kSuccess) {
    DLOG(ERROR) << "ProcessSignedData - PreOperationChecks failure.";
    return kPreOperationCheckFailure;
  }

  std::string current_data;
  switch (op_type) {
    case kStore: {
        if (chunk_store->Has(name)) {
          DLOG(ERROR) << "ProcessSignedData - Name of data exists. Use update.";
          return kDuplicateNameFailure;
        }
        if (!chunk_store->Store(name, data_wrapper.SerializeAsString())) {
          DLOG(ERROR) << "ProcessSignedData - ChunkStore Store failure.";
          return kStoreFailure;
        }
        break;
    }
    case kDelete: {
        if (VerifyCurrentData(name, public_key, chunk_store, &current_data) !=
            kSuccess) {
          DLOG(ERROR) << "ProcessSignedData - VerifyCurrentData failure.";
          return kVerifyDataFailure;
        }

        if (!chunk_store->Delete(name)) {
          DLOG(ERROR) << "ProcessSignedData - Error deleting packet";
          return kDeleteFailure;
        }

        break;
    }
    case kUpdate: {
        if (VerifyCurrentData(name, public_key, chunk_store, &current_data) !=
            kSuccess) {
          DLOG(ERROR) << "ProcessSignedData - VerifyCurrentData failure.";
          return kVerifyDataFailure;
        }
        if (!chunk_store->Modify(name, data_wrapper.SerializeAsString())) {
          DLOG(ERROR) << "ProcessSignedData - Error Modifying packet";
          return kModifyFailure;
        }
        break;
    }
    case kGet: {
        if (VerifyCurrentData(name, public_key, chunk_store, &current_data) !=
            kSuccess) {
          DLOG(ERROR) << "ProcessSignedData - VerifyCurrentData failure.";
          return kVerifyDataFailure;
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
                                    const rsa::PublicKey &public_key,
                                    const bool &hashable) {
  if (op_type == kGet)
    return kSuccess;

  if (!data_wrapper.has_signed_data()) {
    DLOG(ERROR) << "ProcessSignedData - No signed data passed";
    return kMissingSignedData;
  }

  if (hashable && op_type == kUpdate) {
    DLOG(ERROR) << "ProcessSignedData - No update of hashable data allowed";
    return kInvalidUpdate;
  }


  if (rsa::CheckSignature(data_wrapper.signed_data().data(),
                          data_wrapper.signed_data().signature(),
                          public_key) != 0) {
    DLOG(ERROR) << "ProcessSignedData - Signature verification failed";
    return kSignatureVerificationFailure;
  }

  if (hashable &&
      crypto::Hash<crypto::SHA512>(data_wrapper.signed_data().data() +
                                   data_wrapper.signed_data().signature()) !=
      name) {
    DLOG(ERROR) << "ProcessSignedData - Marked hashable, doesn't hash";
    return kNotHashable;
  }

  return kSuccess;
}

int DataHandler::VerifyCurrentData(const std::string &name,
                                   const rsa::PublicKey &public_key,
                                   std::shared_ptr<ChunkStore> chunk_store,
                                   std::string *current_data) {
  *current_data = chunk_store->Get(name);
  if (current_data->empty()) {
    DLOG(ERROR) << "VerifyCurrentData - Failure to get data";
    return kVerifyDataFailure;
  }

  DataWrapper dw;
  if (!dw.ParseFromString(*current_data)) {
    DLOG(ERROR) << "VerifyCurrentData - Error parsing packet";
    return kParseFailure;
  }

  if (rsa::ValidateKey(public_key) &&
      dw.has_signed_data() &&
      rsa::CheckSignature(dw.signed_data().data(),
                          dw.signed_data().signature(),
                          public_key) != 0) {
    DLOG(ERROR) << "VerifyCurrentData - Not owner of packet";
    return kNotOwner;
  }

  *current_data = dw.signed_data().SerializeAsString();

  return kSuccess;
}

int DataHandler::ProcessMsidData(const OperationType &op_type,
                                 const std::string &name,
                                 const DataWrapper &data,
                                 const rsa::PublicKey &public_key,
                                 std::shared_ptr<ChunkStore> chunk_store) {
  std::string current_data(chunk_store->Get(name));
  bool already_exists(true);
  if (current_data.empty()) {
    DLOG(INFO) << "No such MSID";
    already_exists = false;
  }

  if (already_exists) {
    MSID current_msid;
    if (!current_msid.ParseFromString(current_data)) {
      DLOG(ERROR) << "current MSID corrupted";
      return kParseFailure;
    }

    if (asymm::CheckSignature(current_msid.public_key(),
                              current_msid.signature(),
                              public_key) != 0) {
      DLOG(INFO) << "Not owner, can only store MCID or get keys from MSID";
      if (op_type == kStore) {
        if (current_msid.accepts_new_contacts()) {
          current_msid.add_encrypted_mcid(data.signed_data().data());
          if (!chunk_store->Modify(name, current_msid.SerializeAsString())) {
            DLOG(ERROR) << "Failed to add MCID";
            return kModifyFailure;
          }
        }
      } else if (op_type == kGet) {
        GenericPacket gp;
        gp.set_data(current_msid.public_key());
        gp.set_signature(current_msid.signature());
        (*get_data_signal_)(gp.SerializeAsString());
      } else {
        DLOG(ERROR) << "Forbidden operation";
        return kUnknownFailure;
      }
    } else {
      switch (op_type) {
        case kGet:
            if (current_msid.encrypted_mcid_size() > 0)
              (*get_data_signal_)(current_data);
            break;
        case kUpdate:
            /***
             * If owner, change the allowance of storage.
             * Other ops in the future?
             ***/
             break;
        case kDelete:
            // Delete the whole thing
            if (!chunk_store->Delete(name)) {
              DLOG(ERROR) << "Failure to delete value";
              return kDeleteFailure;
            }
            /************** or all messages
            MSID mmid;
            msid.Parse(current_data);
            msid.clear_encrypted_mcid();
            ******************************/
        default: return kUnknownFailure;
      }
    }
  } else {
    // Storing the whole thing
    MSID wrapper_msid;
    if (!wrapper_msid.ParseFromString(data.signed_data().data())) {
      DLOG(ERROR) << "Data doesn't parse";
      return kStoreFailure;
    }

    if (asymm::CheckSignature(wrapper_msid.public_key(),
                              wrapper_msid.signature(),
                              public_key) != 0) {
      DLOG(ERROR) << "Failed validation of data";
      return kStoreFailure;
    }

    if (!chunk_store->Store(name, data.signed_data().data())) {
      DLOG(ERROR) << "Failed committing to chunk store";
      return kStoreFailure;
    }
  }


  return kSuccess;
}

int DataHandler::ProcessMmidData(const OperationType &op_type,
                                 const std::string &name,
                                 const DataWrapper &data,
                                 const rsa::PublicKey &public_key,
                                 std::shared_ptr<ChunkStore> chunk_store) {
  // Check existance
  std::string current_data(chunk_store->Get(name));
  bool already_exists(true);
  if (current_data.empty()) {
    DLOG(INFO) << "No such MMID";
    already_exists = false;
  }

  // Check ownership
    // not owner, store message, no checks
    // owner, get messages, delete, store initially
  if (already_exists) {
    MMID current_mmid;
    if (!current_mmid.ParseFromString(current_data)) {
      DLOG(ERROR) << "current MSID corrupted";
      return kParseFailure;
    }

    if (asymm::CheckSignature(current_mmid.public_key(),
                              current_mmid.signature(),
                              public_key) != 0) {
      DLOG(INFO) << "Not owner, can only store MCID or get keys from MSID";
      if (op_type == kStore) {
        current_mmid.add_encrypted_message(data.signed_data().data());
        if (!chunk_store->Modify(name, current_mmid.SerializeAsString())) {
          DLOG(ERROR) << "Failed to add MCID";
          return kModifyFailure;
        }
      } else {
        DLOG(ERROR) << "Forbidden operation";
        return kUnknownFailure;
      }
    } else {
      switch (op_type) {
        case kGet:
            (*get_data_signal_)(current_data);
            break;
        case kDelete:
            // Delete the whole thing
            if (!chunk_store->Delete(name)) {
              DLOG(ERROR) << "Failure to delete value";
              return kDeleteFailure;
            }
            /************** or all messages
            MMID mmid;
            mmid.Parse(current_data);
            mmid.clear_encrypted_message();
            ******************************/
        default: return kUnknownFailure;
      }
    }
  }

  return kSuccess;
}

}  // namespace lifestuff

}  // namespace maidsafe

