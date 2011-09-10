/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Interface allowing storage of data to network or local database
* Version:      1.0
* Created:      2011-05-16-00.49.17
* Revision:     none
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

#include "maidsafe/lifestuff/networkstoremanager.h"

#include <functional>
#include <memory>

#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/node-api.h"
#include "maidsafe/dht/kademlia/securifier.h"
#include "maidsafe/dht/transport/transport.h"

#include "maidsafe/lifestuff/clientutils.h"
#include "maidsafe/lifestuff/sessionsingleton.h"

namespace arg = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace lifestuff {

enum FindOperation { kUnique, kValues, kDelete };
struct FindValueParameters {
  FindValueParameters()
      : cb(),
        functor(),
        operation(kUnique),
        key(),
        securifier() {}
  FindValueParameters(VoidFuncOneInt one_int,
                      FindOperation fo,
                      dht::kademlia::Key k,
                      dht::kademlia::SecurifierPtr sec)
      : cb(one_int),
        functor(),
        operation(fo),
        key(k),
        securifier(sec) {}
  FindValueParameters(GetPacketFunctor gpf,
                      FindOperation fo,
                      dht::kademlia::Key k)
      : cb(),
        functor(gpf),
        operation(fo),
        key(k),
        securifier() {}
  VoidFuncOneInt cb;
  GetPacketFunctor functor;
  FindOperation operation;
  dht::kademlia::Key key;
  dht::kademlia::SecurifierPtr securifier;
};

NetworkStoreManager::NetworkStoreManager(
    const std::vector<dht::kademlia::Contact> &bootstrap_contacts,
    const boost::uint16_t &k,
    const boost::uint16_t &alpha,
    const boost::uint16_t beta,
    const bptime::seconds &mean_refresh_interval,
    std::shared_ptr<SessionSingleton> ss)
    : bootstrap_contacts_(bootstrap_contacts),
      k_(k),
      alpha_(alpha),
      beta_(beta),
      asio_service_(ss->io_service()),
      work_(),
      securifier_(),
      node_(),
      node_id_(dht::kademlia::NodeId::kRandomId),
      mean_refresh_interval_(mean_refresh_interval),
      delete_results_(),
      session_singleton_(ss) {}

void NetworkStoreManager::Init(const dht::kademlia::JoinFunctor callback,
                               const boost::uint16_t& /*port*/) {
  dht::kademlia::AlternativeStorePtr alternative_store;
  dht::kademlia::MessageHandlerPtr message_handler;
  dht::kademlia::TransportPtr transport;
  node_.reset(new dht::kademlia::Node(asio_service_,
                                      transport,
                                      message_handler,
                                      securifier_,
                                      alternative_store,
                                      true,  // client node
                                      k_,
                                      alpha_,
                                      beta_,
                                      mean_refresh_interval_));
  node_->Join(node_id_, bootstrap_contacts_, callback);
}

int NetworkStoreManager::Close(bool /*cancel_pending_ops*/) {
  node_->Leave(&bootstrap_contacts_);
  return kSuccess;
}

bool NetworkStoreManager::KeyUnique(const std::string &key,
                                    bool check_local) {
  boost::mutex mutex;
  boost::condition_variable cv;
  int expected_result(kPendingResult);
  VoidFuncOneInt cb(std::bind(&NetworkStoreManager::KeyUniqueBlockCallback,
                              this, arg::_1, &mutex, &cv, &expected_result));
  KeyUnique(key, check_local, cb);
  {
    boost::mutex::scoped_lock loch_migdale(mutex);
    while (expected_result == kPendingResult)
      cv.wait(loch_migdale);
  }

  return (expected_result == dht::kademlia::kFailedToFindValue);
}

void NetworkStoreManager::KeyUniqueBlockCallback(
    int result,
    boost::mutex *mutex,
    boost::condition_variable *cv,
    int *expected_result) {
  boost::mutex::scoped_lock loch_migdale(*mutex);
  *expected_result = result;
  (*cv).notify_one();
}

void NetworkStoreManager::KeyUnique(const std::string &key,
                                    bool /*check_local*/,
                                    const VoidFuncOneInt &cb) {
  dht::kademlia::Key node_id(key);
  FindValueParameters fvp(cb, kUnique, node_id, securifier_);
  dht::kademlia::FindValueFunctor fvf(
      std::bind(&NetworkStoreManager::FindValueCallback, this, arg::_1, fvp));
  node_->FindValue(node_id, securifier_, fvf);
}

int NetworkStoreManager::GetPacket(const std::string &packet_name,
                                   std::vector<std::string> *results) {
  boost::mutex mutex;
  boost::condition_variable cv;
  int expected_result(kPendingResult);
  GetPacketFunctor cb(std::bind(&NetworkStoreManager::GetPacketBlockCallback,
                                this, arg::_1, arg::_2, &mutex, &cv,
                                &expected_result, results));
  GetPacket(packet_name, cb);
  {
    boost::mutex::scoped_lock loch_migdale(mutex);
    while (expected_result == kPendingResult)
      cv.wait(loch_migdale);
  }
  return 0;
}

void NetworkStoreManager::GetPacketBlockCallback(
    const std::vector<std::string> &values,
    int result,
    boost::mutex *mutex,
    boost::condition_variable *cv,
    int *expected_result,
    std::vector<std::string> *expected_values) {
  boost::mutex::scoped_lock loch_migdale(*mutex);
  *expected_result = result;
  *expected_values = values;
  (*cv).notify_one();
}

void NetworkStoreManager::GetPacket(const std::string &packet_name,
                                    const GetPacketFunctor &cb) {
  dht::kademlia::Key key(packet_name);
  FindValueParameters fvp(cb, kValues, key);
  dht::kademlia::FindValueFunctor fvf(
      std::bind(&NetworkStoreManager::FindValueCallback, this, arg::_1, fvp));
  node_->FindValue(key, securifier_, fvf);
}

void NetworkStoreManager::StorePacket(
    const std::string &packet_name,
    const std::string &value,
    passport::PacketType system_packet_type,
    DirType dir_type,
    const std::string &msid,
    const VoidFuncOneInt &cb) {
  boost::posix_time::seconds ttl(boost::posix_time::pos_infin);
  dht::kademlia::SecurifierPtr securifier;
  dht::kademlia::Key key(packet_name);
  std::string key_id, public_key, public_key_signature, private_key;
  maidsafe::lifestuff::ClientUtils client_utils(session_singleton_);
  client_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid,
                                      &key_id, &public_key,
                                      &public_key_signature, &private_key);
  securifier.reset(new dht::Securifier(key_id, public_key, private_key));
  node_->Store(key, value, "", ttl, securifier, cb);
}

void NetworkStoreManager::DeletePacket(
    const std::string &packet_name,
    std::vector<std::string> values,
    passport::PacketType system_packet_type,
    DirType dir_type,
    const std::string &msid,
    const VoidFuncOneInt &cb) {
  dht::kademlia::Key key(packet_name);
  std::string key_id, public_key, public_key_signature, private_key;
  maidsafe::lifestuff::ClientUtils client_utils(session_singleton_);
  client_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid,
                                      &key_id, &public_key,
                                      &public_key_signature, &private_key);
  dht::kademlia::SecurifierPtr securifier;
  securifier.reset(new dht::Securifier(key_id, public_key, private_key));
  if (values.empty())
    PopulateValues(key, securifier, cb);
  else
    DeletePacketImpl(key, values, securifier, cb);
}

// TODO(Team): Decide on multiple value result
void NetworkStoreManager::DeletePacketImpl(
    const dht::kademlia::Key &key,
    const std::vector<std::string> values,
    const dht::kademlia::SecurifierPtr securifier,
    const VoidFuncOneInt &/*cb*/) {
  std::shared_ptr<std::vector<int>> delete_results;
  delete_results->resize(values.size());
  std::shared_ptr<boost::mutex> mutex;
  mutex.reset(new boost::mutex);
  dht::kademlia::DeleteFunctor delete_functor;
  for (int index = 0; index != static_cast<int>(values.size()); ++index) {
    delete_functor = std::bind(&NetworkStoreManager::DeletePacketCallback, this,
                               arg::_1, index, delete_results, mutex);
    node_->Delete(key, values[index], "", securifier, delete_functor);
  }
}

void NetworkStoreManager::PopulateValues(
    const dht::kademlia::Key &key,
    const dht::kademlia::SecurifierPtr securifier,
    const VoidFuncOneInt &cb) {
  FindValueParameters fvp(cb, kDelete, key, securifier);
  node_->FindValue(key,
                   securifier,
                   std::bind(&NetworkStoreManager::FindValueCallback,
                             this, arg::_1, fvp));
}

void NetworkStoreManager::FindValueCallback(dht::kademlia::FindValueReturns fvr,
                                            FindValueParameters parameters) {
  switch (parameters.operation) {
    case kUnique:
        parameters.cb(fvr.return_code);
        return;
    case kValues:
        parameters.functor(fvr.values, kSuccess);  // fvr.return_code);
        return;
    case kDelete:
        if (fvr.return_code == 0)
          DeletePacketImpl(parameters.key,
                           fvr.values,
                           parameters.securifier,
                           parameters.cb);
  }
}

void NetworkStoreManager::DeletePacketCallback(
    int result,
    int index,
    std::shared_ptr<std::vector<int>> delete_results,
    std::shared_ptr<boost::mutex> mutex) {
  boost::mutex::scoped_lock lock(*mutex.get());
  delete_results->at(index) = (result == dht::transport::kSuccess);
}

void NetworkStoreManager::UpdatePacket(
    const std::string &packet_name,
    const std::string &old_value,
    const std::string &new_value,
    passport::PacketType system_packet_type,
    DirType dir_type,
    const std::string &msid,
    const VoidFuncOneInt &cb) {
  dht::kademlia::Key key(packet_name);
  std::string key_id, public_key, public_key_signature, private_key;
  maidsafe::lifestuff::ClientUtils client_utils(session_singleton_);
  client_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid,
                                      &key_id, &public_key,
                                      &public_key_signature, &private_key);
  boost::posix_time::seconds ttl(boost::posix_time::pos_infin);
  dht::kademlia::SecurifierPtr securifier;
  securifier.reset(new dht::Securifier(key_id, public_key, private_key));
  node_->Update(key, new_value, "", old_value, "", ttl, securifier, cb);
}

}  // namespace lifestuff

}  // namespace maidsafe
