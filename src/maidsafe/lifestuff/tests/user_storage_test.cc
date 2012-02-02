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

#include "maidsafe/lifestuff/message_handler.h"

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/public_id.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/authentication.h"
#include "maidsafe/lifestuff/client_controller.h"
#include "maidsafe/lifestuff/user_storage.h"
#include "maidsafe/lifestuff/tests/test_callback.h"
#if defined AMAZON_WEB_SERVICE_STORE
#  include "maidsafe/lifestuff/store_components/aws_store_manager.h"
#else
#  include "maidsafe/lifestuff/store_components/local_store_manager.h"
#endif

namespace args = std::placeholders;
namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

namespace test {

fs::path CreateTestDirectory(fs::path const& parent) {
  fs::path directory(parent / RandomAlphaNumericString(5));
  boost::system::error_code error_code;
  EXPECT_TRUE(fs::create_directories(directory, error_code))
              << directory  << ": " << error_code.message();
  EXPECT_EQ(0, error_code.value()) << directory << ": "
                                   << error_code.message();
  EXPECT_TRUE(fs::exists(directory, error_code)) << directory << ": "
                                                 << error_code.message();
  return directory;
}

class UserStorageTest : public testing::Test {
 public:
  UserStorageTest()
      : username_("aaaaaaaaaaa"),
        pin_("111111"),
        password_("ccccccccccc"),
        test_dir_(*(maidsafe::test::CreateTestPath())),
        g_mount_dir_(fs::initial_path() / "LifeStuff"),
        session_(new maidsafe::lifestuff::Session),
        cc_(new maidsafe::lifestuff::ClientController(session_)),
        user_storage_(),
#if defined AMAZON_WEB_SERVICE_STORE
        packet_manager_(new AWSStoreManager(session_, test_dir_)) {}
#else
        packet_manager_(new LocalStoreManager(session_, test_dir_.string())) {}
#endif
 protected:
  void SetUp() {
    packet_manager_->Init(std::bind(&UserStorageTest::InitAndCloseCallback,
                                    this, args::_1));
    cc_->auth_.reset(new Authentication(session_));
    cc_->auth_->Init(packet_manager_);
    cc_->packet_manager_ = packet_manager_;
    cc_->initialised_ = true;

    user_storage_.reset(new UserStorage(cc_->client_chunk_store(),
                                        cc_->packet_manager()));

    ASSERT_TRUE(cc_->CreateUser(username_, pin_, password_));

    user_storage_->MountDrive(g_mount_dir_,
                              cc_->SessionName(),
                              session_,
                              true);
    Sleep(bptime::seconds(5));
    g_mount_dir_ = user_storage_->g_mount_dir();
  }

  void TearDown() {
    user_storage_->UnMountDrive();
  }

  void InitAndCloseCallback(int /*i*/) {}

  std::string username_;
  std::string pin_;
  std::string password_;
  fs::path test_dir_;
  fs::path g_mount_dir_;
  std::shared_ptr<maidsafe::lifestuff::Session> session_;
  std::shared_ptr<maidsafe::lifestuff::ClientController> cc_;
  std::shared_ptr<maidsafe::lifestuff::UserStorage> user_storage_;
  std::shared_ptr<PacketManager> packet_manager_;
};

TEST_F(UserStorageTest, FUNC_FirstTest) {
  std::map<std::string, bool> users;
  fs::path dir0(CreateTestDirectory(g_mount_dir_));
  ASSERT_EQ(kSuccess, user_storage_->CreateShare(dir0, users));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe