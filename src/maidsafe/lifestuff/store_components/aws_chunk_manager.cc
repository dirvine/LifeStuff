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


#include "maidsafe/lifestuff/store_components/aws_chunk_manager.h"

#include "maidsafe/common/buffered_chunk_store.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/log.h"


namespace maidsafe {

namespace lifestuff {

AWSChunkManager::AWSChunkManager(std::shared_ptr<ChunkStore> chunk_store)
    : ChunkManager(chunk_store),
      amazon_web_service_(new aws_transporter::AWSTransporter) {}

void AWSChunkManager::GetChunk(const std::string &name) {
  if (chunk_store_->Has(name)) {
    (*sig_chunk_got_)(name, pd::kSuccess);
    return;
  }

  std::string content;
  if (amazon_web_service_->Download(EncodeToBase32(name), &content) !=
      aws_transporter::AWSTransporter::kSuccess) {
    DLOG(ERROR) << "Failed to get chunk " << HexSubstr(name) << " from AWS";
    (*sig_chunk_got_)(name, pd::kGeneralError);
    return;
  }

  if (chunk_store_->Store(name, content)) {
    if (chunk_store_->Validate(name)) {
      (*sig_chunk_got_)(name, pd::kSuccess);
    } else {
      chunk_store_->Delete(name);
      DLOG(ERROR) << "Failed to validate " << HexSubstr(name);
    }
  } else {
    DLOG(ERROR) << "Failed to store locally " << HexSubstr(name);
    (*sig_chunk_got_)(name, pd::kGeneralError);
  }
}

void AWSChunkManager::StoreChunk(const std::string &name) {
  std::string content(chunk_store_->Get(name));
  if (content.empty()) {
    (*sig_chunk_stored_)(name, pd::kGeneralError);
    return;
  }

  std::string encoded_name(EncodeToBase32(name));
  uintmax_t instance_count(0);
  if (amazon_web_service_->GetInstanceCount(encoded_name, &instance_count) !=
      aws_transporter::AWSTransporter::kSuccess) {
    DLOG(ERROR) << "Failed to get instance count while storing chunk "
                << HexSubstr(name) << " in AWS";
    (*sig_chunk_stored_)(name, pd::kGeneralError);
    return;
  }

  if (instance_count == 0) {
    if (amazon_web_service_->Upload(encoded_name, content) !=
        aws_transporter::AWSTransporter::kSuccess) {
      DLOG(ERROR) << "Failed to put chunk " << HexSubstr(name) << " to AWS";
      (*sig_chunk_stored_)(name, pd::kGeneralError);
      return;
    }
  } else {
    if (amazon_web_service_->SetInstanceCount(encoded_name, ++instance_count) !=
        aws_transporter::AWSTransporter::kSuccess) {
      DLOG(ERROR) << "Failed to increase instance count of chunk "
                  << HexSubstr(name) << " to " << instance_count << " in AWS";
      (*sig_chunk_stored_)(name, pd::kGeneralError);
      return;
    }
  }
  (*sig_chunk_stored_)(name, pd::kSuccess);
}

void AWSChunkManager::DeleteChunk(const std::string &name) {
  uintmax_t instance_count(0);
  std::string encoded_name(EncodeToBase32(name));
  if (amazon_web_service_->GetInstanceCount(encoded_name, &instance_count) !=
      aws_transporter::AWSTransporter::kSuccess) {
    DLOG(ERROR) << "Failed to get instance count while deleting chunk "
                << HexSubstr(name) << " in AWS";
    (*sig_chunk_deleted_)(name, pd::kGeneralError);
    return;
  }

  if (instance_count == 1) {
    if (amazon_web_service_->Delete(encoded_name) !=
        aws_transporter::AWSTransporter::kSuccess) {
      DLOG(ERROR) << "Failed to del chunk " << HexSubstr(name) << " from AWS";
      (*sig_chunk_deleted_)(name, pd::kGeneralError);
      return;
    }
  } else if (instance_count != 0) {
    if (amazon_web_service_->SetInstanceCount(encoded_name, --instance_count) !=
        aws_transporter::AWSTransporter::kSuccess) {
      DLOG(ERROR) << "Failed to decrease instance count of chunk "
                  << HexSubstr(name) << " to " << instance_count << " in AWS";
      (*sig_chunk_deleted_)(name, pd::kGeneralError);
      return;
    }
  }
  (*sig_chunk_deleted_)(name, pd::kSuccess);
}

}  // namespace pd

}  // namespace maidsafe
