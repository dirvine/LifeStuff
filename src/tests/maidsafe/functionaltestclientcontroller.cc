/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Functional tests for Client Controller operations
* Version:      1.0
* Created:      2009-01-29-02.29.46
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


#include <boost/bind.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/progress.hpp>
#include <boost/thread/thread.hpp>
#include <gtest/gtest.h>

#include <list>
#include <map>
#include <vector>

#include "tests/maidsafe/localvaults.h"
#include "maidsafe/crypto.h"
#include "maidsafe/utils.h"
#include "fs/filesystem.h"
#include "maidsafe/client/clientcontroller.h"
#include "maidsafe/client/selfencryption.h"
#include "maidsafe/vault/pdvault.h"
#include "protobuf/datamaps.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"


namespace fs = boost::filesystem;

namespace cc_test {

static std::vector< boost::shared_ptr<maidsafe_vault::PDVault> > pdvaults_;
static const int kNetworkSize_ = 17;
static const int kTestK_ = 16;
static bool initialised_ = false;

class FakeCallback {
 public:
  FakeCallback() : result_("") {}
  void CallbackFunc(const std::string &result) {
    result_ = result;
  }
  void Wait(int duration) {
    boost::posix_time::milliseconds timeout(duration);
    boost::posix_time::milliseconds count(0);
    boost::posix_time::milliseconds increment(10);
    while (result_ == "" && count < timeout) {
      count += increment;
      boost::this_thread::sleep(increment);
    }
  }
  std::string result() { return result_; }
 private:
  std::string result_;
};

}  // namespace cc_test

namespace maidsafe {

class FunctionalClientControllerTest : public testing::Test {
 protected:
  FunctionalClientControllerTest()
      : cc_(),
        authentication_(),
        ss_(),
        dir1_(""),
        dir2_(""),
        final_dir_(),
        vcp_() {}

  static void TearDownTestCase() {
    transport::CleanUp();
  }

  void SetUp() {
    ss_ = SessionSingleton::getInstance();
    ss_->ResetSession();
    cc_ = ClientController::getInstance();
    if (!cc_test::initialised_) {
      ASSERT_EQ(kSuccess, cc_->Init());
      cc_test::initialised_ = cc_->initialised();
    }
    cc_->StopRvPing();
    ss_->SetConnectionStatus(0);
  }

  void TearDown() {
    try {
      ss_->ResetSession();
      if (final_dir_ != "" && fs::exists(final_dir_))
        fs::remove_all(final_dir_);
    }
    catch(const std::exception &e) {
      printf("Error: %s\n", e.what());
    }
  }

  ClientController *cc_;
  Authentication *authentication_;
  SessionSingleton *ss_;
  std::string dir1_, dir2_, final_dir_;
  VaultConfigParameters vcp_;
 private:
  FunctionalClientControllerTest(const FunctionalClientControllerTest&);
  FunctionalClientControllerTest &operator=
      (const FunctionalClientControllerTest&);
};

TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerLoginSequence) {
  std::string username = "User1";
  std::string pin = "1234";
  std::string password = "The beagle has landed.";
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Preconditions fulfilled.\n");

  ASSERT_NE(maidsafe::kUserExists,
            cc_->CheckUserExists(username, pin, maidsafe::DEFCON3));
  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out.\n\n\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));

  ASSERT_EQ(maidsafe::kUserExists,
            cc_->CheckUserExists(username, pin, maidsafe::DEFCON3));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("Logged in.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out.\n");

  ASSERT_NE(maidsafe::kUserExists,
            cc_->CheckUserExists("juan.smer", pin, maidsafe::DEFCON3));
  printf("Can't log in with fake details.\n");
}

TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerChangeDetails) {
  std::string username = "User2";
  std::string pin = "2345";
  std::string password = "The axolotl has landed.";
  ss_ = SessionSingleton::getInstance();
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  ASSERT_NE(maidsafe::kUserExists,
            cc_->CheckUserExists(username, pin, maidsafe::DEFCON3));
  printf("Preconditions fulfilled.\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created.\n");

  ASSERT_TRUE(cc_->ChangeUsername("juan.smer"));
  ASSERT_EQ("juan.smer", ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  printf("Changed username.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));

  ASSERT_EQ(maidsafe::kUserExists,
            cc_->CheckUserExists("juan.smer", pin, maidsafe::DEFCON3));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ("juan.smer", ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("Logged in.\n");
  file_system::FileSystem fsys;
  dir1_ = fsys.MaidsafeDir();

  ASSERT_TRUE(cc_->ChangePin("2207"));
  ASSERT_EQ("juan.smer", ss_->Username());
  ASSERT_EQ("2207", ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  printf("Changed pin.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));

  ASSERT_EQ(maidsafe::kUserExists,
            cc_->CheckUserExists("juan.smer", "2207", maidsafe::DEFCON3));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ("juan.smer", ss_->Username());
  ASSERT_EQ("2207", ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("Logged in.\n");
  dir2_ = fsys.MaidsafeDir();

  ASSERT_TRUE(cc_->ChangePassword("elpasguor"));
  ASSERT_EQ("juan.smer", ss_->Username());
  ASSERT_EQ("2207", ss_->Pin());
  ASSERT_EQ("elpasguor", ss_->Password());
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  printf("Changed password.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));

  ASSERT_EQ(maidsafe::kUserExists,
            cc_->CheckUserExists("juan.smer", "2207", maidsafe::DEFCON3));
  std::string new_pwd("elpasguor");
  ASSERT_TRUE(cc_->ValidateUser(new_pwd));
  ASSERT_EQ("juan.smer", ss_->Username());
  ASSERT_EQ("2207", ss_->Pin());
  ASSERT_EQ("elpasguor", ss_->Password());
  printf("Logged in. New u/p/w.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));

  ASSERT_EQ(maidsafe::kUserExists,
            cc_->CheckUserExists("juan.smer", "2207", maidsafe::DEFCON3));
  ASSERT_FALSE(cc_->ValidateUser(password))
    << "old details still work, damn it, damn the devil to hell";
  ss_->ResetSession();
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Can't log in with old u/p/w.\n");
}

TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerCreatePubUsername) {
  std::string username = "User3";
  std::string pin = "3456";
  std::string password = "The fanjeeta has landed.";
  ss_ = SessionSingleton::getInstance();
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  ASSERT_NE(maidsafe::kUserExists,
            cc_->CheckUserExists(username, pin, maidsafe::DEFCON3));
  printf("Preconditions fulfilled.\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created.\n");

  ASSERT_TRUE(cc_->CreatePublicUsername("el.mambo.tonnnnnto"));
  ASSERT_EQ("el.mambo.tonnnnnto", ss_->PublicUsername());
  printf("Public Username created.\n");

  ASSERT_FALSE(cc_->CreatePublicUsername("el.mambo.tonnnnnto"));
  ASSERT_EQ("el.mambo.tonnnnnto", ss_->PublicUsername());
  printf("Public Username already created.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(6));

  ASSERT_TRUE(cc_->GetMessages());
  std::list<maidsafe::InstantMessage> messages;
  ASSERT_EQ(0, cc_->GetInstantMessages(&messages));
  ASSERT_EQ(size_t(0), messages.size());

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));

  ASSERT_EQ(maidsafe::kUserExists,
            cc_->CheckUserExists(username, pin, maidsafe::DEFCON3));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  ASSERT_EQ("el.mambo.tonnnnnto", ss_->PublicUsername());

  boost::this_thread::sleep(boost::posix_time::seconds(6));

  ASSERT_TRUE(cc_->GetMessages());
  messages.clear();
  ASSERT_EQ(0, cc_->GetInstantMessages(&messages));
  ASSERT_EQ(size_t(0), messages.size());

  boost::this_thread::sleep(boost::posix_time::seconds(10));

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));
}

/*
TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerLeaveNetwork) {
  std::string username = "User4";
  std::string pin = "4567";
  std::string password = "The chubster has landed.";
  ss_ = SessionSingleton::getInstance();
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Preconditions fulfilled.\n");

  ASSERT_FALSE(cc_test::CheckUserExists(cc_, username, pin, 10000));
  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out.\n");

  ASSERT_TRUE(cc_test::CheckUserExists(cc_, username, pin, 10000));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
//  ASSERT_EQ("el.mambo.tonnnnnto", ss_->PublicUsername());
  printf("Logged in.\n");

  ASSERT_TRUE(cc_->LeaveMaidsafeNetwork());
  printf("Left maidsafe ='(.\n");

  ASSERT_FALSE(cc_test::CheckUserExists(cc_, username, pin, 10000));
  printf("User no longer exists.\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created again.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out.\n");
}
*/

TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerBackupFile) {
  std::string username = "User5";
  std::string pin = "5678";
  std::string password = "The limping dog has landed.";
  ss_ = SessionSingleton::getInstance();
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  ASSERT_EQ(maidsafe::kUserDoesntExist,
            cc_->CheckUserExists(username, pin, maidsafe::DEFCON3));
  printf("Preconditions fulfilled.\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created.\n");

  file_system::FileSystem fsys;
  fs::create_directories(fsys.MaidsafeHomeDir()+kRootSubdir[0][0]);
  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "testencryption.txt";
  std::string rel_str_ = base::TidyPath(rel_path.string());

  fs::path full_path(fsys.MaidsafeHomeDir());
  full_path /= rel_path;
  fs::ofstream testfile(full_path.string().c_str());
  testfile << base::RandomString(1024*1024);
  testfile.close();
  maidsafe::SelfEncryption se(cc_->client_chunkstore_);
  std::string hash_original_file = se.SHA512(full_path);
  {
    boost::progress_timer t;
    ASSERT_EQ(0, cc_->write(rel_str_));
    printf("File backed up in ");
  }

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out user.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));

  if (fs::exists(full_path))
      fs::remove(full_path);

  ASSERT_EQ(maidsafe::kUserExists,
            cc_->CheckUserExists(username, pin, maidsafe::DEFCON3));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User logged in.\n");
  fs::create_directories(fsys.MaidsafeHomeDir() + kRootSubdir[0][0]);

  {
    boost::progress_timer t;
    ASSERT_EQ(0, cc_->read(rel_str_));
    printf("Self decrypted file in ");
  }
  std::string hash_dec_file = se.SHA512(full_path);
  ASSERT_EQ(hash_original_file, hash_dec_file);

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out user.\n");
}

TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerSaveSession) {
  // Create a user
  std::string username = "User5";
  std::string pin = "5678";
  std::string password = "The limping dog has landed.";
  ss_ = SessionSingleton::getInstance();
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  ASSERT_EQ(maidsafe::kUserDoesntExist,
            cc_->CheckUserExists(username, pin, maidsafe::DEFCON3));
  printf("Preconditions fulfilled.\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created.\n");
  std::string pmid = ss_->Id(maidsafe::PMID);
  // Create a file
  file_system::FileSystem fsys;
  fs::create_directories(fsys.MaidsafeHomeDir()+kRootSubdir[0][0]);
  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "testencryption.txt";
  std::string rel_str = base::TidyPath(rel_path.string());

  fs::path full_path(fsys.MaidsafeHomeDir());
  full_path /= rel_path;
  fs::ofstream testfile(full_path.string().c_str());
  testfile << base::RandomString(1024*1024);
  testfile.close();
  maidsafe::SelfEncryption se(cc_->client_chunkstore_);
  std::string hash_original_file = se.SHA512(full_path);
  {
    boost::progress_timer t;
    ASSERT_EQ(0, cc_->write(rel_str));
    printf("File backed up in ");
  }

  // Save the session
  ASSERT_EQ(0, cc_->SaveSession());
  printf("\n\n\nSaved the session\n\n\n");

  // Reset the client controller
  /*
  printf("Client controller address before: %d\n", cc_);
  cc_ = NULL;
  cc_ = maidsafe::ClientController::getInstance();
  printf("Client controller address after: %d\n", cc_);
  */
  cc_->client_chunkstore_->Clear();
  printf("\n\n\nCleared the chunkstore\n\n\n");
  ss_->ResetSession();
  printf("\n\n\nReset the session\n\n\n");

  // Remove the local file
  if (fs::exists(full_path))
      fs::remove(full_path);

  // Login
  ASSERT_EQ(maidsafe::kUserExists,
            cc_->CheckUserExists(username, pin, maidsafe::DEFCON3));
  printf("\n\n\nChecked for user\n\n\n");
  ASSERT_TRUE(cc_->ValidateUser(password));
  printf("\n\n\nLogged in\n\n\n");
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  ASSERT_EQ(pmid, ss_->Id(maidsafe::PMID));
//  ASSERT_EQ(pmid, ss_->PublicKey(maidsafe::PMID));
//  ASSERT_EQ(pmid, ss_->PrivateKey(maidsafe::PMID));
//  ASSERT_EQ(pmid, ss_->Signed(maidsafe::PMID));


  // Check for file
  fs::create_directories(fsys.MaidsafeHomeDir()+kRootSubdir[0][0]);
  {
    boost::progress_timer t;
    ASSERT_EQ(0, cc_->read(rel_str));
    printf("Self decrypted file in ");
  }
  std::string hash_dec_file = se.SHA512(full_path);
  ASSERT_EQ(hash_original_file, hash_dec_file);
  printf("Hashes match\n");

  // Log out
  ASSERT_TRUE(cc_->Logout());
  printf("Logged out\n");

  // Clean up
  // Delete file
  if (fs::exists(full_path))
      fs::remove(full_path);
}

TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerContactAddition) {
  std::string username("User6");
  std::string pin("6789");
  std::string password("The deleted folder has landed.");
  ss_ = SessionSingleton::getInstance();
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  ASSERT_EQ(maidsafe::kUserDoesntExist,
            cc_->CheckUserExists(username, pin, maidsafe::DEFCON3));
  printf("Preconditions fulfilled.\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created.\n");

  std::string public_username("el.mambo.nalga");
  ASSERT_TRUE(cc_->CreatePublicUsername(public_username));
  ASSERT_EQ(public_username, ss_->PublicUsername());
  printf("Public Username created.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));

  std::string username1("User61");
  std::string pin1("67891");
  std::string password1("The deleted folder has landed.1");
  std::string public_username1("el.mambo.nalga1");

  ASSERT_TRUE(cc_->CreateUser(username1, pin1, password1, vcp_));
  ASSERT_EQ(username1, ss_->Username());
  ASSERT_EQ(pin1, ss_->Pin());
  ASSERT_EQ(password1, ss_->Password());
  printf("User1 created.\n");

  ASSERT_TRUE(cc_->CreatePublicUsername(public_username1));
  ASSERT_EQ(public_username1, ss_->PublicUsername());
  printf("Public Username 1 created.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(6));

  ASSERT_EQ(0, cc_->AddContact(public_username));
  printf("Public Username 1 added Public Username.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out 1.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));

  ASSERT_EQ(maidsafe::kUserExists,
            cc_->CheckUserExists(username, pin, maidsafe::DEFCON3));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  ASSERT_EQ(public_username, ss_->PublicUsername());
  printf("Logged in.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(6));

  ASSERT_TRUE(cc_->GetMessages());
  std::list<maidsafe::InstantMessage> messages;
  ASSERT_EQ(0, cc_->GetInstantMessages(&messages));
  ASSERT_EQ(size_t(1), messages.size());
  maidsafe::InstantMessage im = messages.front();
  ASSERT_TRUE(im.has_contact_notification());
  ASSERT_EQ(public_username1, im.sender());
  ASSERT_EQ("\"" + public_username1 +
            "\" has requested to add you as a contact.", im.message());
  maidsafe::ContactNotification cn = im.contact_notification();
  ASSERT_EQ(0, cn.action());
  maidsafe::ContactInfo ci;
  if (cn.has_contact())
    ci = cn.contact();
  ASSERT_EQ(0, cc_->HandleAddContactRequest(ci, im.sender()));
  ASSERT_NE("", ss_->GetContactPublicKey(public_username1));
  printf("Public Username confirmed Public Username 1.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));

  ASSERT_EQ(maidsafe::kUserExists,
            cc_->CheckUserExists(username1, pin1, maidsafe::DEFCON3));
  ASSERT_TRUE(cc_->ValidateUser(password1));
  ASSERT_EQ(username1, ss_->Username());
  ASSERT_EQ(pin1, ss_->Pin());
  ASSERT_EQ(password1, ss_->Password());
  ASSERT_EQ(public_username1, ss_->PublicUsername());
  printf("Logged in 1.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(6));

  ASSERT_TRUE(cc_->GetMessages());
  messages.clear();
  ASSERT_EQ(0, cc_->GetInstantMessages(&messages));
  ASSERT_EQ(size_t(1), messages.size());
  maidsafe::InstantMessage im1 = messages.front();
  ASSERT_TRUE(im1.has_contact_notification());
  ASSERT_EQ(public_username, im1.sender());
  ASSERT_EQ("\"" + public_username + "\" has confirmed you as a contact.",
            im1.message());
  maidsafe::ContactNotification cn1 = im1.contact_notification();
  ASSERT_EQ(1, cn1.action());
  maidsafe::ContactInfo ci1;
  if (cn1.has_contact())
    ci1 = cn1.contact();
  ASSERT_EQ(0, cc_->HandleAddContactResponse(ci1, im1.sender()));
  printf("Public Username 1 received Public Username confirmation.\n");

  std::string text_msg("The arctic trails have their secret tales");
  std::vector<std::string> contact_names;
  contact_names.push_back(public_username);
  ASSERT_EQ(0, cc_->SendInstantMessage(text_msg, contact_names));
  printf("Public Username 1 sent txt message  to Public Username.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(6));

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out 1.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));

  ASSERT_EQ(maidsafe::kUserExists,
            cc_->CheckUserExists(username, pin, maidsafe::DEFCON3));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  ASSERT_EQ(public_username, ss_->PublicUsername());

  boost::this_thread::sleep(boost::posix_time::seconds(6));

  ASSERT_TRUE(cc_->GetMessages());
  messages.clear();
  ASSERT_EQ(0, cc_->GetInstantMessages(&messages));
  ASSERT_EQ(size_t(1), messages.size());
  maidsafe::InstantMessage im2 = messages.front();
  ASSERT_FALSE(im2.has_contact_notification());
  ASSERT_FALSE(im2.has_instantfile_notification());
  ASSERT_FALSE(im2.has_privateshare_notification());
  ASSERT_EQ(public_username1, im2.sender());
  ASSERT_EQ(text_msg, im2.message());

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));
}

/*
TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerShares) {
  ss_ = SessionSingleton::getInstance();
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Preconditions fulfilled.\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created.\n");

  ASSERT_TRUE(cc_->CreatePublicUsername("el.mambo.tonnnnnto"));
  ASSERT_EQ("el.mambo.tonnnnnto", ss_->PublicUsername());
  printf("Public Username created.\n");

  std::set<std::string> auth_users;
  std::string users[3] = {"el.dan.liiiiiisto", "es tu", "padre"};
  for (int n=0; n<3 ; n++)
    auth_users.insert(users[n]);

  ASSERT_TRUE(cc_->AuthoriseUsers(auth_users));
  std::set<std::string> local_set = ss_->AuthorisedUsers();
  for (std::set<std::string>::iterator p = local_set.begin();
       p != local_set.end();
       ++p)
    ASSERT_TRUE(*p==users[0] || *p==users[1] || *p==users[2])
      << "User missing";
  printf("Authorised 3 users.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out.\n");

  ASSERT_TRUE(cc_->CreateUser("smer","7777","palofeo", vcp_));
  ASSERT_TRUE(ss_->Username() == "smer");
  ASSERT_TRUE(ss_->Pin() == "7777");
  ASSERT_TRUE(ss_->Password() == "palofeo");
  printf("User created.\n");

  ASSERT_TRUE(cc_->CreatePublicUsername("el.dan.liiiiiisto"));
  ASSERT_TRUE(ss_->PublicUsername() == "el.dan.liiiiiisto");
  printf("Public Username created.\n");

  std::string path = file_system::FileSystem::getInstance()->HomeDir() +
                     "/testencryption.txt";
  fs::path path_(path);
  fs::ofstream testfile(path.c_str());
  testfile << base::RandomString(1024*1024);
  testfile.close();
  std::string hash_original_file = se.SHA512(path_);
  ASSERT_TRUE(cc_->BackupElement(path));
  while(ss_->SelfEncrypting())
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  OutputProcessedJobs(cc);
  printf("File backed up.\n");

  std::vector<std::string> paths, share_users;
  std::string ms_path = path;
  ms_path.erase(0,
                file_system::FileSystem::getInstance()->HomeDir().size());
  paths.push_back(ms_path);
  share_users.push_back("el.mambo.tonnnnnto");
  ASSERT_TRUE(cc_->CreateShare(paths,share_users,"fotos puercas"));
  printf("Created share.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out.\n");

  ASSERT_TRUE(cc_->Start(username, pin, password));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User logged in.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out.\n");

  if (fs::exists(path))
    fs::remove(fs::path(path));
}
*/

TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerFuseFunctions) {
  std::string username = "User7";
  std::string pin = "7890";
  std::string password = "The pint of lager has landed on the floor.";
  ss_ = SessionSingleton::getInstance();
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  ASSERT_EQ(maidsafe::kUserDoesntExist,
            cc_->CheckUserExists(username, pin, maidsafe::DEFCON3));
  printf("Preconditions fulfilled.\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created.\n");

  file_system::FileSystem fsys;
  fs::create_directories(fsys.MaidsafeHomeDir() + kRootSubdir[0][0]);
  fs::path rel_path(kRootSubdir[0][0]);
  fs::path testfile[15];
  fs::path homedir(fsys.HomeDir());
  fs::path mshomedir(fsys.MaidsafeHomeDir());
  // fs::path newdir = homedir / "NewDir";
  // fs::path msnewdir = mshomedir / "NewDir";
  fs::path my_files(base::TidyPath(kRootSubdir[0][0]));
  fs::path startdir = my_files / "NewDir";

  testfile[0] = startdir;
  testfile[1] = startdir / "file0";
  testfile[2] = startdir / "file1";
  testfile[3] = startdir / "file2";
  testfile[4] = startdir / "file3";

  fs::path insidenewdir = startdir / "insidenewdir";
  testfile[5] = insidenewdir;
  testfile[6] = insidenewdir / "file4";
  testfile[7] = insidenewdir / "file5";
  testfile[8] = insidenewdir / "file6";

  fs::path quitedeepinsidenewdir = insidenewdir / "quitedeepinsidenewdir";
  testfile[9] = quitedeepinsidenewdir;
  fs::path deepinsidenewdir = quitedeepinsidenewdir / "deepinsidenewdir";
  testfile[10] = deepinsidenewdir;
  testfile[11] = deepinsidenewdir / "file7";
  testfile[12] = deepinsidenewdir / "file8";

  fs::path reallydeepinsidenewdir = deepinsidenewdir / "reallydeepinsidenewdir";
  testfile[13] = reallydeepinsidenewdir;
  testfile[14] = reallydeepinsidenewdir / "file9";

  std::string temp_path, temp_path1;

  printf("Creating directories and files.\n");
  for (int n = 0; n < 15; ++n) {
    temp_path = testfile[n].string();
    if (n == 0 || n == 5 || n == 9 || n == 10 || n == 13) {
      fs::create_directory(mshomedir.string()+"/"+temp_path);
      ASSERT_EQ(0, cc_->mkdir(temp_path));
    } else {
      std::string full_ = mshomedir.string()+"/"+temp_path;
      fs::ofstream testfile(full_.c_str());
      testfile.close();
      ASSERT_EQ(0, cc_->mknod(temp_path));
    }
    // printf("Creating element [%i]: %s\n", i, temp_path);
  }

  fs::path newdirtest2_ = insidenewdir / "testdir1/dansdir";
  temp_path = newdirtest2_.string();
  ASSERT_NE(0, cc_->mkdir(temp_path)) << "making impossible dir failed";
  printf("Doesn't create impossible directory.\n");
  fs::path newfiletest3_ = insidenewdir / "testdir/lapuercota.jpg";
  temp_path = newfiletest3_.string();
  ASSERT_NE(0, cc_->mknod(temp_path)) << "making impossible dir failed";
  printf("Doesn't create impossible file.\n");

  temp_path = testfile[1].string();
  fs::path temp_b_path = insidenewdir / "renamedfile0";
  temp_path1 = temp_b_path.string();
  ASSERT_EQ(0, cc_->rename(temp_path, temp_path1)) << "file rename failed";
  // printf("Renamed file " << temp_path << " to " << temp_path1 << std::endl;
  printf("Renamed file.\n");

  temp_path = testfile[10].string();
  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir";
  temp_path1 = temp_b_path.string();
  ASSERT_EQ(0, cc_->rename(temp_path, temp_path1)) << "directory rename failed";
  // printf("Renamed dir %s to %s\n", temp_path.c_str(), temp_path1.c_str());
  printf("Renamed directory.\n");
  testfile[10] = temp_b_path.string();

  temp_path = testfile[2].string();
  temp_b_path = insidenewdir / "nonexistent" / "renamedfile0";
  temp_path1 = temp_b_path.string();
  ASSERT_NE(0, cc_->rename(temp_path, temp_path1))
    << "impossible file rename failed";
  printf("Didn't rename existent file to impossible one.\n");

  temp_path = testfile[13].string();
  temp_b_path = deepinsidenewdir /
                "nonexistent" /
                "renamed_reallydeepinsidenewdir";
  temp_path1 = temp_b_path.string();
  ASSERT_NE(0, cc_->rename(temp_path, temp_path1))
    << "impossible directory rename failed";
  printf("Didn't rename existent directory to impossible one.\n");

  temp_path = testfile[13].string();
  ASSERT_NE(0, cc_->rmdir(temp_path)) << "remove non-empty directory failed";
  printf("Doesn't remove non-empty directory.\n");

  temp_b_path = quitedeepinsidenewdir /
                "renamed_deepinsidenewdir" /
                "reallydeepinsidenewdir" /
                "file9";
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc_->unlink(temp_path)) << "remove file failed";
  // printf("Removed file " << temp_path << std::endl;
  printf("Removed file.\n");

  temp_b_path = temp_b_path.parent_path();
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc_->rmdir(temp_path)) << "remove directory failed";
  // printf("Removed directory " << temp_path << std::endl;
  printf("Removed directory.\n");

  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir" / "file8";
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc_->unlink(temp_path)) << "remove file failed";
  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir" / "file7";
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc_->unlink(temp_path)) << "remove file failed";
  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir";
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc_->unlink(temp_path)) << "remove stupid dir failed";
  // printf("Recursively removed directory %s and its content.\n",
  //        temp_path.c_str());
  printf("Recursively removed directory and its content.\n");

  std::string o_path = testfile[8].string();
  fs::path ppp = startdir / "file6";
  std::string n_path = ppp.string();
  ASSERT_EQ(0, cc_->link(o_path, n_path));
  printf("\nCopied file %s to %s\n", o_path.c_str(), n_path.c_str());
  o_path = testfile[9].string();
  fs::path ppp1 = startdir / "dirA";
  n_path = ppp1.string();
  ASSERT_EQ(0, cc_->cpdir(o_path, n_path));
  // printf("Copied directory %s to %s\n", o_path, n_path);
  printf("Copied directory.\n");

  temp_b_path = startdir;
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc_->utime(temp_path));
  // printf("\nChanged the last modification time to directory %s\n",
  //        temp_path);
  printf("Changed the last modification time to directory.\n");

  // ASSERT_EQ(0, cc_->statfs());
  // printf("Got the FS stats.\n\n");

  final_dir_ = fsys.MaidsafeDir();

  ASSERT_TRUE(cc_->Logout());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  printf("Logged out user.\n");

  boost::this_thread::sleep(boost::posix_time::seconds(10));
}

}  // namespace maidsafe

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  testing::AddGlobalTestEnvironment(new localvaults::Env(cc_test::kNetworkSize_,
      cc_test::kTestK_, &cc_test::pdvaults_));
  return RUN_ALL_TESTS();
}
