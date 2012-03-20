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

#include <sstream>

#include "maidsafe/lifestuff/message_handler.h"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/pd/client/client_container.h"
#endif

#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/public_id.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/authentication.h"
#include "maidsafe/lifestuff/user_credentials.h"
#include "maidsafe/lifestuff/user_storage.h"
#include "maidsafe/lifestuff/ye_olde_signal_to_callback_converter.h"

namespace args = std::placeholders;
namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

namespace test {

class ProfilePictureTest : public testing::Test {
 public:
  ProfilePictureTest()
    : test_dir_(maidsafe::test::CreateTestPath()),
      mount_dir_(fs::initial_path() / "LifeStuff"),
      asio_service_(),
      interval_(1),
      user_credentials_(),
      user_storage_(),
      session_(new Session),
      converter_(new YeOldeSignalToCallbackConverter),
      public_id_(),
      message_handler_(),
      public_username_(RandomAlphaNumericString(5)),
      username_(RandomString(6)),
      pin_(),
      password_(RandomString(6)) {}

 protected:
  void SetUp() {
    asio_service_.Start(5);
    user_credentials_.reset(new UserCredentials(asio_service_.service(),
                                                session_));
    user_credentials_->Init(*test_dir_);

    std::stringstream pin_stream;
    pin_stream << RandomUint32();
    pin_ = pin_stream.str();
    user_credentials_->CreateUser(username_, pin_, password_);

    public_id_.reset(new PublicId(user_credentials_->remote_chunk_store(),
                                  user_credentials_->converter(),
                                  session_,
                                  asio_service_.service()));

    message_handler_.reset(
        new MessageHandler(user_credentials_->remote_chunk_store(),
                           user_credentials_->converter(),
                           session_,
                           asio_service_.service()));

    user_storage_.reset(
        new UserStorage(user_credentials_->remote_chunk_store(),
                        user_credentials_->converter(),
                        message_handler_));

    public_id_->CreatePublicId(public_username_, true);
    public_id_->StartCheckingForNewContacts(interval_);

    user_storage_->MountDrive(mount_dir_, session_, true);
  }

  void TearDown() {
    Quit();
    asio_service_.Stop();
  }

  void Quit() {
    user_storage_->UnMountDrive();
    public_id_->StopCheckingForNewContacts();
    message_handler_->StopCheckingForNewMessages();
    user_credentials_->Logout();
    session_->ResetSession();
  }

  void LogIn() {
    EXPECT_EQ(-201004, user_credentials_->CheckUserExists(username_, pin_));
    EXPECT_TRUE(user_credentials_->ValidateUser(password_));
    user_storage_->MountDrive(mount_dir_, session_, false);
  }

  fs::path CreateTestDirectory(fs::path const& parent,
                               std::string *tail) {
    *tail = RandomAlphaNumericString(5);
    fs::path directory(parent / (*tail));
    boost::system::error_code error_code;
    fs::create_directories(directory, error_code);
    if (error_code)
      return fs::path();
    return directory;
  }
  
  maidsafe::test::TestPath test_dir_;
  fs::path mount_dir_;
  AsioService asio_service_;
  bptime::seconds interval_;
  std::shared_ptr<UserCredentials> user_credentials_;
  std::shared_ptr<UserStorage> user_storage_;
  std::shared_ptr<Session> session_;
  std::shared_ptr<YeOldeSignalToCallbackConverter> converter_;
  std::shared_ptr<PublicId> public_id_;
  std::shared_ptr<MessageHandler> message_handler_;
  std::string public_username_, username_, pin_, password_;
};

TEST_F(ProfilePictureTest, FUNC_ProfilePicture) {
  // Create file
  std::string tail;
  boost::system::error_code error_code;
  fs::path test(CreateTestDirectory(mount_dir_, &tail));
  EXPECT_TRUE(fs::exists(test, error_code));
  EXPECT_EQ(0, error_code.value());
  
  // Logout
  Quit();

  // Login
  LogIn();

  // Check directory exists
  EXPECT_TRUE(fs::exists(test, error_code));
  EXPECT_EQ(0, error_code.value());  
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
