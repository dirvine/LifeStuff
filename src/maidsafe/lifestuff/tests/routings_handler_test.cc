/*
* ============================================================================
*
* Copyright [2012] maidsafe.net limited
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

#include <chrono>
#include <map>
#include <thread>

#include "maidsafe/routing/tests/routing_network.h"

#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/routings_handler.h"
#include "maidsafe/lifestuff/detail/session.h"

namespace maidsafe {

namespace lifestuff {

namespace test {

class RoutingsHandlerTest : public routing::test::GenericNetwork {
 public:
  RoutingsHandlerTest()
      : routing::test::GenericNetwork(),
        public_key_map_(),
        message_arrived_(false),
        messages_expected_(0),
        messages_(),
        mutex_(),
        test_dir_(maidsafe::test::CreateTestPath()),
        session_(),
        asio_service_(1),
        remote_chunkstore_() {}

 protected:
  virtual void SetUp() {
    LOG(kInfo) << "STARTING SETUP\n\n\n\n";
    EXPECT_EQ(kSuccess, session_.passport().CreateSigningPackets());
    EXPECT_EQ(kSuccess, session_.passport().ConfirmSigningPackets());
    asio_service_.Start();
    remote_chunkstore_ = priv::chunk_store::CreateLocalChunkStore(*test_dir_ / "buffered",
                                                                  *test_dir_ / "local",
                                                                  *test_dir_ / "lock",
                                                                  asio_service_.service());
    routing::test::GenericNetwork::SetUp();
    SetUpNetwork(10);
  }

  virtual void TearDown() {
    LOG(kInfo) << "STARTING TEARDOWN\n\n\n\n";
    asio_service_.Stop();
    routing::test::GenericNetwork::TearDown();
    Sleep(boost::posix_time::seconds(10));
  }

  virtual void SetNodeValidationFunctor(std::shared_ptr<routing::test::GenericNode> node) {
    node->functors_.request_public_key =
        [&] (NodeId node_id, routing::GivePublicKeyFunctor give_key_functor) {
          this->RequestPublicKeySlot(node_id, give_key_functor);
        };
  }

  bool ValidatedMessageSlot(const std::string& message, std::string& response, bool reply) {
    LOG(kInfo) << "ValidatedMessageSlot message: " << message << ", response: " << response;
    std::lock_guard<std::mutex> loch(mutex_);
    messages_.push_back(message);
    if (messages_.size() == messages_expected_)
      message_arrived_ = true;
    if (reply) {
      response = message + message;
//      std::reverse_copy(std::begin(message), std::end(message), std::begin(response));
      LOG(kInfo) << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ Reversing with response: " << response;
    }
    return reply;
  }

  void RequestPublicKeySlot(NodeId node_id, routing::GivePublicKeyFunctor give_key_functor) {
    // Check pre-established network nodes
    auto itr(std::find_if(nodes_.begin(),
                          nodes_.end(),
                          [&node_id] (const std::shared_ptr<routing::test::GenericNode>& element) {
                            return element->node_id() == node_id;
                          }));
    if (itr != nodes_.end()) {
      give_key_functor((*itr)->node_info().public_key);
      return;
    }

    // Might be a local node created in this test. Check those.
    auto local_itr(public_key_map_.find(node_id));
    if (local_itr != public_key_map_.end())
      give_key_functor((*local_itr).second);
  }

  std::shared_ptr<RoutingsHandler> CreateAndAddRoutingObject(bool reply) {
    ValidatedMessageFunction validated_message_functor =
        [&, reply] (const std::string& message, std::string& response) {
          return this->ValidatedMessageSlot(message, response, reply);
        };
    return std::make_shared<RoutingsHandler>(*remote_chunkstore_,
                                             session_,
                                             validated_message_functor);
  }

  void set_messages_expected(size_t messages_expected) { messages_expected_ = messages_expected; }

  std::map<NodeId, asymm::PublicKey> public_key_map_;
  bool message_arrived_;
  size_t messages_expected_;
  std::vector<std::string> messages_;
  std::mutex mutex_;
  maidsafe::test::TestPath test_dir_;
  Session session_;
  AsioService asio_service_;
  std::shared_ptr<priv::chunk_store::RemoteChunkStore> remote_chunkstore_;
};

TEST_F(RoutingsHandlerTest, FUNC_SendOneMessageToSelfTwoInstances) {
  {
    LOG(kInfo) << "STARTING TEST\n\n\n\n";
    set_messages_expected(2);
    asymm::Keys maid(session_.passport().SignaturePacketDetails(passport::kMaid, true));
    public_key_map_.insert(std::make_pair(NodeId(maid.identity), maid.public_key));
    std::vector<std::pair<std::string, uint16_t> > bootstrap_endpoints;
    bootstrap_endpoints.push_back(std::make_pair(nodes_[0]->endpoint().address().to_string(),
                                                 nodes_[0]->endpoint().port()));

    routing::RequestPublicKeyFunctor request_key_functor =
        [&] (NodeId node_id, routing::GivePublicKeyFunctor give_key_functor) {
          this->RequestPublicKeySlot(node_id, give_key_functor);
        };

    // RoutingsHandler origin
    std::shared_ptr<RoutingsHandler> origin_routings_handler(CreateAndAddRoutingObject(false));
    EXPECT_TRUE(origin_routings_handler->AddRoutingObject(maid,
                                                          bootstrap_endpoints,
                                                          maid.identity,
                                                          request_key_functor));


    // RoutingsHandler destination
    std::shared_ptr<RoutingsHandler> destination_routings_handler(CreateAndAddRoutingObject(false));
    EXPECT_TRUE(destination_routings_handler->AddRoutingObject(maid,
                                                               bootstrap_endpoints,
                                                               maid.identity,
                                                               request_key_functor));

    // Sending message
    std::string message("hello world");
    EXPECT_TRUE(origin_routings_handler->Send(maid.identity,
                                              maid.identity,
                                              maid.public_key,
                                              message,
                                              nullptr));
    std::mutex mutex;
    std::unique_lock<std::mutex> loch(mutex);
    std::condition_variable condition_variable;
    EXPECT_TRUE(condition_variable.wait_for(loch,
                                            std::chrono::seconds(5),
                                            [this] () { return message_arrived_; }));
    EXPECT_EQ(2U, messages_.size());
    for (const auto& element : messages_)
      EXPECT_EQ(message, element);
  }
}

TEST_F(RoutingsHandlerTest, FUNC_TwoInstancesWithReply) {
  asymm::Keys maid(session_.passport().SignaturePacketDetails(passport::kMaid, true));
  public_key_map_.insert(std::make_pair(NodeId(maid.identity), maid.public_key));
  std::vector<std::pair<std::string, uint16_t> > bootstrap_endpoints;
  bootstrap_endpoints.push_back(std::make_pair(nodes_[0]->endpoint().address().to_string(),
                                               nodes_[0]->endpoint().port()));

  routing::RequestPublicKeyFunctor request_key_functor =
      [&] (NodeId node_id, routing::GivePublicKeyFunctor give_key_functor) {
        this->RequestPublicKeySlot(node_id, give_key_functor);
      };

  // RoutingsHandler origin
  std::shared_ptr<RoutingsHandler> origin_routings_handler(CreateAndAddRoutingObject(false));
  EXPECT_TRUE(origin_routings_handler->AddRoutingObject(maid,
                                                        bootstrap_endpoints,
                                                        maid.identity,
                                                        request_key_functor));


  // RoutingsHandler destination
  std::shared_ptr<RoutingsHandler> destination_routings_handler(CreateAndAddRoutingObject(true));
  EXPECT_TRUE(destination_routings_handler->AddRoutingObject(maid,
                                                             bootstrap_endpoints,
                                                             maid.identity,
                                                             request_key_functor));

  // Send the message and wait for the response
  std::string request_message("hello world"),
              reversed_message(request_message + request_message),
              reply_message;
//  std::reverse_copy(std::begin(request_message),
//                    std::end(request_message),
//                    std::begin(reversed_message));
  EXPECT_TRUE(origin_routings_handler->Send(maid.identity,
                                            maid.identity,
                                            maid.public_key,
                                            request_message,
                                            &reply_message));
  EXPECT_EQ(reversed_message, reply_message);
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
