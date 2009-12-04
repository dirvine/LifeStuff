/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Tests functionality of Self Encryption Handler
* Version:      1.0
* Created:      2009-07-08-03.06.29
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

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/scoped_ptr.hpp>

#include <gtest/gtest.h>

#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/client/packetfactory.h"
#include "maidsafe/client/sehandler.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/maidsafe.h"
#include "protobuf/maidsafe_messages.pb.h"

namespace fs = boost::filesystem;

std::string CreateRandomFile(const std::string &filename,
                             int size = (1024)) {
  std::string file_content = base::RandomString(size);
  file_system::FileSystem fsys;
  fs::path file_path(fsys.MaidsafeHomeDir());
  file_path = file_path / filename;
  fs::ofstream ofs;
  ofs.open(file_path);
  ofs << file_content;
  ofs.close();
  return file_path.string();
};

class FakeCallback {
 public:
  FakeCallback() : result("") {}
  void CallbackFunc(const std::string &res) {
    result = res;
  }
  void Reset() {
    result = "";
  }
  std::string result;
};

void wait_for_result_seh(const FakeCallback &cb, boost::mutex *mutex) {
  while (true) {
    {
      boost::mutex::scoped_lock guard(*mutex);
      if (cb.result != "")
        return;
    }
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
};

namespace maidsafe {

class SEHandlerTest : public testing::Test {
 protected:
  SEHandlerTest() : test_root_dir_(file_system::FileSystem::TempDir() +
                                   "/maidsafe_TestSEH"),
                    client_chunkstore_(),
                    cb(),
                    db_str1_(""),
                    db_str2_("")  {}
  ~SEHandlerTest() {}
  void SetUp() {
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
      if (fs::exists(file_system::FileSystem::LocalStoreManagerDir()))
        fs::remove_all(file_system::FileSystem::LocalStoreManagerDir());
      file_system::FileSystem fsys;
      if (fs::exists(fsys.MaidsafeDir()))
        fs::remove_all(fsys.MaidsafeDir());
    }
    catch(const std::exception& e) {
      printf("%s\n", e.what());
    }
    client_chunkstore_ =
        boost::shared_ptr<ChunkStore>(new ChunkStore(test_root_dir_, 0, 0));
    int count(0);
    while (!client_chunkstore_->is_initialised() && count < 10000) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
    boost::shared_ptr<LocalStoreManager>
        sm(new LocalStoreManager(client_chunkstore_));
    cb.Reset();
    sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
    boost::mutex mutex;
    wait_for_result_seh(cb, &mutex);
    GenericResponse result;
    if ((!result.ParseFromString(cb.result)) ||
        (result.result() == kNack)) {
      FAIL();
      return;
    }
    SessionSingleton::getInstance()->SetUsername("user1");
    SessionSingleton::getInstance()->SetPin("1234");
    SessionSingleton::getInstance()->SetPassword("password1");
    SessionSingleton::getInstance()->SetSessionName(false);
    SessionSingleton::getInstance()->SetRootDbKey("whatever");
    crypto::RsaKeyPair rsa_kp;
    rsa_kp.GenerateKeys(kRsaKeySize);
    SessionSingleton::getInstance()->AddKey(PMID, "PMID", rsa_kp.private_key(),
                                            rsa_kp.public_key(), "");
    rsa_kp.GenerateKeys(kRsaKeySize);
    SessionSingleton::getInstance()->AddKey(MAID, "MAID", rsa_kp.private_key(),
                                            rsa_kp.public_key(), "");
    rsa_kp.GenerateKeys(kRsaKeySize);
    SessionSingleton::getInstance()->AddKey(MPID, "Me", rsa_kp.private_key(),
        rsa_kp.public_key(), "");
    file_system::FileSystem fsys;
    fsys.Mount();
    boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
    boost::scoped_ptr<SEHandler> seh(new SEHandler());
    seh->Init(sm, client_chunkstore_);
    if (dah->Init(true) )
      FAIL();

     //  set up default root subdirs
    for (int i = 0; i < kRootSubdirSize; i++) {
      MetaDataMap mdm;
      std::string ser_mdm, key;
      mdm.set_id(-2);
      mdm.set_display_name(base::TidyPath(kRootSubdir[i][0]));
      mdm.set_type(EMPTY_DIRECTORY);
      mdm.set_stats("");
      mdm.set_tag("");
      mdm.set_file_size_high(0);
      mdm.set_file_size_low(0);
      boost::uint32_t current_time = base::get_epoch_time();
      mdm.set_creation_time(current_time);
      mdm.SerializeToString(&ser_mdm);
      if (kRootSubdir[i][1] == "")
        seh->GenerateUniqueKey(PRIVATE, "", 0, &key);
      else
        key = kRootSubdir[i][1];
      fs::create_directories(fsys.MaidsafeHomeDir() + kRootSubdir[i][0]);
      dah->AddElement(base::TidyPath(kRootSubdir[i][0]),
        ser_mdm, "", key, true);
    }

// *********************************************
// Anonymous Shares are disabled at the moment *
// *********************************************
//    //set up Anon share subdir
//    fs::path subdir_(kSharesSubdir[1][0], fs::native);
//    std::string subdir_name_ = subdir_.filename();
//    MetaDataMap mdm_;
//    std::string ser_mdm_, key_;
//    mdm_.set_id(-2);
//    mdm_.set_display_name(subdir_name_);
//    mdm_.set_type(EMPTY_DIRECTORY);
//    mdm_.set_stats("");
//    mdm_.set_tag("");
//    mdm_.set_file_size_high(0);
//    mdm_.set_file_size_low(0);
//    boost::uint32_t current_time_ = base::get_epoch_time();
//    mdm_.set_creation_time(current_time_);
//    mdm_.SerializeToString(&ser_mdm_);
//    key_ = kSharesSubdir[1][1];
//    dah->AddElement(base::TidyPath(kSharesSubdir[1][0]),
//      ser_mdm_, "", key_, true);
//
    dah->GetDbPath(base::TidyPath(kRootSubdir[0][0]), CREATE, &db_str1_);
// *********************************************
// Anonymous Shares are disabled at the moment *
// *********************************************
//    dah->GetDbPath(base::TidyPath(kSharesSubdir[1][0]), CREATE, &db_str2_);
    cb.Reset();
  }
  void TearDown() {
    cb.Reset();
    boost::this_thread::sleep(boost::posix_time::seconds(1));
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
      if (fs::exists(file_system::FileSystem::LocalStoreManagerDir()))
        fs::remove_all(file_system::FileSystem::LocalStoreManagerDir());
      file_system::FileSystem fsys;
      if (fs::exists(fsys.MaidsafeDir()))
        fs::remove_all(fsys.MaidsafeDir());
    }
    catch(const std::exception& e) {
      printf("%s\n", e.what());
    }
  }
  std::string test_root_dir_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  FakeCallback cb;
  std::string db_str1_;
  std::string db_str2_;
 private:
  SEHandlerTest(const SEHandlerTest&);
  SEHandlerTest &operator=(const SEHandlerTest&);
};


TEST_F(SEHandlerTest, BEH_MAID_Check_Entry) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);

  fs::path rel_path(kRootSubdir[0][0], fs::native);
  fs::path rel_path1 = rel_path / "file1";
  fs::path rel_path2 = rel_path / "file2";
  fs::path rel_path3 = rel_path / "file3";
  fs::path rel_path4 = rel_path / "file4.LNK";
  fs::path rel_path5 = rel_path / "file5";
  fs::path rel_path6 = rel_path / "Dir";
  fs::path rel_path7 = rel_path6 / "EmptyDir";
  std::string name_too_long = "";
  for (int i = 0; i < 20; i++)
    name_too_long += "NameTooLong";
  fs::path rel_path8 = rel_path / name_too_long;
  std::string rel_str1 = base::TidyPath(rel_path1.string());
  std::string rel_str2 = base::TidyPath(rel_path2.string());
  std::string rel_str3 = base::TidyPath(rel_path3.string());
  std::string rel_str4 = base::TidyPath(rel_path4.string());
  std::string rel_str5 = base::TidyPath(rel_path5.string());
  std::string rel_str6 = base::TidyPath(rel_path6.string());
  std::string rel_str7 = base::TidyPath(rel_path7.string());
  std::string rel_str8 = base::TidyPath(rel_path8.string());
  int size1 = 0;
  int size2 = kMinRegularFileSize - 1;
  int size3 = kMinRegularFileSize;
  int size4 = 5;
  int size5 = 5;
  int size6 = 0;
  int size7 = 0;
  int size8 = 5;
  std::string full_str1 = CreateRandomFile(rel_str1, size1);
  std::string full_str2 = CreateRandomFile(rel_str2, size2);
  std::string full_str3 = CreateRandomFile(rel_str3, size3);
  std::string full_str4 = CreateRandomFile(rel_str4, size4);
  std::string full_str5 = CreateRandomFile(rel_str5, size5);
  file_system::FileSystem fsys;
  fs::path full_path6(fsys.MaidsafeHomeDir(), fs::native);
  full_path6 /= rel_str6;
  fs::path full_path7(fsys.MaidsafeHomeDir(), fs::native);
  full_path7 /= rel_str7;
  fs::create_directories(full_path7);
  std::string full_str6 = full_path6.string();
  std::string full_str7 = full_path7.string();
  std::string full_str8 = CreateRandomFile(rel_str8, size8);
  uint64_t returned_size1, returned_size2, returned_size3;
  uint64_t returned_size6, returned_size7, returned_size8;
  ASSERT_TRUE(EMPTY_FILE == seh->CheckEntry(full_str1, &returned_size1));
  ASSERT_EQ(size1, static_cast<int>(returned_size1));
  ASSERT_TRUE(SMALL_FILE == seh->CheckEntry(full_str2, &returned_size2));
  ASSERT_EQ(size2, static_cast<int>(returned_size2));
  ASSERT_TRUE(REGULAR_FILE == seh->CheckEntry(full_str3, &returned_size3));
  ASSERT_EQ(size3, static_cast<int>(returned_size3));
  ASSERT_TRUE(EMPTY_DIRECTORY == seh->CheckEntry(full_str6, &returned_size6));
  ASSERT_EQ(size6, static_cast<int>(returned_size6));
  ASSERT_TRUE(EMPTY_DIRECTORY == seh->CheckEntry(full_str7, &returned_size7));
  ASSERT_EQ(size7, static_cast<int>(returned_size7));
  ASSERT_TRUE(NOT_FOR_PROCESSING == seh->CheckEntry(full_str8,
                                                    &returned_size8));
}

TEST_F(SEHandlerTest, BEH_MAID_EncryptFile) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);

  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "file1";
  std::string rel_str = base::TidyPath(rel_path.string());

  std::string full_str = CreateRandomFile(rel_str);
  int result = seh->EncryptFile(rel_str, PRIVATE, "");
  ASSERT_EQ(0, result);

  // Check the chunks are stored
  std::string ser_dm;
  ASSERT_EQ(0, dah->GetDataMap(rel_str, &ser_dm));
  DataMap dm;
  ASSERT_TRUE(dm.ParseFromString(ser_dm));

  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i)
    ASSERT_FALSE(sm->KeyUnique(dm.encrypted_chunk_name(i), false));
  sm->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

TEST_F(SEHandlerTest, BEH_MAID_EncryptString) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);


  std::string data(base::RandomString(1024)), ser_dm;
  int result = seh->EncryptString(data, &ser_dm);
  ASSERT_EQ(0, result);

  // Check the chunks are stored
  maidsafe::DataMap dm;
  ASSERT_TRUE(dm.ParseFromString(ser_dm));

  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i)
    ASSERT_FALSE(sm->KeyUnique(dm.encrypted_chunk_name(i), false));
  sm->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

TEST_F(SEHandlerTest, FUNC_MAID_DecryptStringWithChunksPrevLoaded) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);


  std::string data(base::RandomString(19891/*1024*/)), ser_dm;

  SelfEncryption se(client_chunkstore_);
  int result = seh->EncryptString(data, &ser_dm);
  ASSERT_EQ(0, result);

  boost::this_thread::sleep(boost::posix_time::seconds(1));
  std::string dec_string;
  result = seh->DecryptString(ser_dm, &dec_string);
  ASSERT_EQ(0, result);
  ASSERT_EQ(data, dec_string);
  sm->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

TEST_F(SEHandlerTest, FUNC_MAID_DecryptStringWithLoadChunks) {
  SessionSingleton::getInstance()->SetDefConLevel(DEFCON2);
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);

  std::string data(base::RandomString(1024)), ser_dm;

  SelfEncryption se(client_chunkstore_);
  int result = seh->EncryptString(data, &ser_dm);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(0, result);
  file_system::FileSystem fsys;
  // All dirs are removed on fsys_.Mount() below.  We need to temporarily rename
  // DbDir (which contains dir's db files) to avoid deletion.
  std::string db_dir_original = fsys.DbDir();
  std::string db_dir_new = "./W";
  try {
    fs::remove_all(db_dir_new);
    fs::rename(db_dir_original, db_dir_new);
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  fsys.Mount();

  fs::create_directories(fsys.MaidsafeHomeDir() + kRootSubdir[0][0]);
  try {
    fs::remove_all(db_dir_original);
    fs::rename(db_dir_new, db_dir_original);
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  std::string dec_string;
  result = seh->DecryptString(ser_dm, &dec_string);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(0, result);

  ASSERT_EQ(data, dec_string);
  sm->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

TEST_F(SEHandlerTest, FUNC_MAID_DecryptWithChunksPrevLoaded) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);

  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "file1";
  std::string rel_str = base::TidyPath(rel_path.string());

  std::string full_str = CreateRandomFile(rel_str);
  std::string hash_before, hash_after;
  SelfEncryption se(client_chunkstore_);
  hash_before = se.SHA512(fs::path(full_str));
  int result = seh->EncryptFile(rel_str, PRIVATE, "");
  ASSERT_EQ(0, result);
  fs::remove(full_str);
  ASSERT_FALSE(fs::exists(full_str));

  boost::this_thread::sleep(boost::posix_time::seconds(1));
//  printf("1 - trying to decrypt: %s\n", rel_str.c_str());
  result = seh->DecryptFile(rel_str);
//  printf("2\n");
  ASSERT_EQ(0, result);
//  printf("3 - trying to assert exists: %s\n", full_str.c_str());
  ASSERT_TRUE(fs::exists(full_str));
  hash_after = se.SHA512(fs::path(full_str));
  ASSERT_EQ(hash_before, hash_after);
  sm->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

TEST_F(SEHandlerTest, FUNC_MAID_DecryptWithLoadChunks) {
  SessionSingleton::getInstance()->SetDefConLevel(DEFCON2);
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);

  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "file1";
  std::string rel_str = base::TidyPath(rel_path.string());

  std::string full_str = CreateRandomFile(rel_str);
  std::string hash_before, hash_after;
  SelfEncryption se(client_chunkstore_);
  fs::path full_path(full_str, fs::native);
  hash_before = se.SHA512(full_path);
  int result = seh->EncryptFile(rel_str, PRIVATE, "");
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(0, result);
  file_system::FileSystem fsys;
  // All dirs are removed on fsys.Mount() below.  We need to temporarily rename
  // DbDir (which contains dir's db files) to avoid deletion.
  std::string db_dir_original = fsys.DbDir();
  std::string db_dir_new = "./W";
  try {
    fs::remove_all(db_dir_new);
    fs::rename(db_dir_original, db_dir_new);
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  fsys.Mount();
  ASSERT_FALSE(fs::exists(full_str));
  fs::create_directories(fsys.MaidsafeHomeDir() + kRootSubdir[0][0]);
  try {
    fs::remove_all(db_dir_original);
    fs::rename(db_dir_new, db_dir_original);
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  result = seh->DecryptFile(rel_str);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(0, result);
  ASSERT_TRUE(fs::exists(full_str));
  hash_after = se.SHA512(fs::path(full_str));
  ASSERT_EQ(hash_before, hash_after);
  sm->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

//  TEST_F(SEHandlerTest, FUNC_MAID_Decrypt_FailedToLoadChunk) {
//   boost::shared_ptr<LocalStoreManager> sm_(new LocalStoreManager(rec_mutex));
//    sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
//    boost::scoped_ptr<SEHandler>seh(new SEHandler(sm_.get(), rec_mutex));
//    boost::scoped_ptr<DataAtlasHandler>dah(new DataAtlasHandler());
//
//    fs::path rel_path_(kRootSubdir[0][0]);
//    rel_path /= "file1";
//    std::string rel_str = base::TidyPath(rel_path_.string());
//
//    std::string full_str = CreateRandomFile(rel_str_);
//    std::string hash_before_, hash_after_;
//    SelfEncryption se_;
//    fs::path full_path_(full_str_, fs::native);
//    hash_before = se_.SHA512(full_path_);
//    int result = seh->EncryptFile(rel_str_, PRIVATE, "");
//    boost::this_thread::sleep(boost::posix_time::seconds(1));
//    ASSERT_EQ(0, result);
//    file_system::FileSystem fsys_;
//    try {
//      fs::remove_all(fsys_.MaidsafeHomeDir());
//      //  NB we can't remove DbDir (which contains dir's db files)
//      //  unless a proper logout/login is run
//      fs::remove_all(fsys_.ProcessDir());
//      for (char c = '0'; c <= '9'; c_++) {
//        std::stringstream out_;
//        out << c_;
//        std::string f = fsys_.ApplicationDataDir() + "/client/" + out_.str();
//        fs::remove_all(f);
//        printf("Removing %s\n", f.c_str());
//      }
//      for (char c = 'a'; c <= 'f'; c_++) {
//        std::stringstream out_;
//        out << c_;
//        std::string f = fsys_.ApplicationDataDir() + "client/" + out_.str();
//        fs::remove_all(f);
//        printf("Removing %s\n", f.c_str());
//      }
//    }
//    catch(std::exception& e) {
//      printf("%s\n", e.what());
//    }
//    ASSERT_FALSE(fs::exists(full_str_));
//
//    std::string ser_dm;
//    ASSERT_EQ(0, dah->GetDataMap(rel_str_, &ser_dm));
//    DataMap dm;
//    ASSERT_TRUE(dm.ParseFromString(ser_dm));
//    fs::path chunk_path("");
//    chunk_path = se_.GetChunkPath(dm.encrypted_chunk_name(2));
//    printf("Removing %s\n", chunk_path.string().c_str());
//    fs::remove(chunk_path);
//
//    fsys_.Mount();
//    fs::create_directories(fsys_.MaidsafeHomeDir() + kRootSubdir[0][0]);
//
//    result = seh->DecryptFile(rel_str_);
//    boost::this_thread::sleep(boost::posix_time::seconds(1));
//    ASSERT_EQ(0, result);
//    ASSERT_FALSE(fs::exists(full_str_));
//    sm->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1), true);
//    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
//  }

TEST_F(SEHandlerTest, FUNC_MAID_EncryptAndDecryptPrivateDb) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);

  file_system::FileSystem fsys;
  fs::path db_path(db_str1_, fs::native);
  std::string key(seh->SHA512("somekey", false));
//  std::string key("");
//  ASSERT_EQ(0, seh->GenerateUniqueKey(PRIVATE, "", 0, &key));
//  dah->GetDirKey(kRootSubdir[0][0], &key);
  ASSERT_TRUE(fs::exists(db_path));
  std::string hash_before = seh->SHA512(db_str1_, true);
  DataMap dm;
  std::string ser_dm;
  dm.SerializeToString(&ser_dm);

  // Create the entry
  ASSERT_EQ(0, seh->EncryptDb(base::TidyPath(kRootSubdir[0][0]), PRIVATE, key,
            "", true, &dm));
//  ASSERT_EQ("", ser_dm);

  // Test decryption with the directory DB ser_dm in the map
  ASSERT_EQ(0, seh->DecryptDb(base::TidyPath(kRootSubdir[0][0]), PRIVATE,
            ser_dm, key, "", true, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, seh->SHA512(db_str1_, true));

  // Deleting the details of the DB
  fs::remove(db_path);
  ASSERT_FALSE(fs::exists(db_path));
  ASSERT_EQ(0,
    seh->RemoveKeyFromUptodateDms(base::TidyPath(kRootSubdir[0][0]))) <<
    "Didn't find the key in the map of DMs.";

  // Test decryption with no record of the directory DB ser_dm
  ASSERT_EQ(0, seh->DecryptDb(base::TidyPath(kRootSubdir[0][0]), PRIVATE,
            ser_dm, key, "", true, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, seh->SHA512(db_str1_, true));

  // Test decryption with the directory DB ser_dm in the map
  ASSERT_EQ(0, seh->DecryptDb(base::TidyPath(kRootSubdir[0][0]), PRIVATE,
            ser_dm, key, "", true, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, seh->SHA512(db_str1_, true));

  fs::path key_path(fsys.MaidsafeDir(), fs::native);
  key_path /= key;
  fs::remove(key_path);
  sm->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

TEST_F(SEHandlerTest, DISABLED_BEH_MAID_EncryptAndDecryptAnonDb) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);

  file_system::FileSystem fsys;
  fs::path db_path(db_str2_, fs::native);
  std::string key = "testkey";
  ASSERT_TRUE(fs::exists(db_path));
  std::string hash_before = seh->SHA512(db_str2_, true);
  std::string ser_dm;
// *********************************************
// Anonymous Shares are disabled at the moment *
// *********************************************
//  ASSERT_EQ(0, seh->EncryptDb(base::TidyPath(kSharesSubdir[1][0]),
//    ANONYMOUS, key, "", false, &ser_dm));
  fs::remove(db_path);
  ASSERT_FALSE(fs::exists(db_path));
//  ASSERT_EQ(0,
//    seh->RemoveKeyFromUptodateDms(base::TidyPath(kSharesSubdir[1][0]))) <<
//    "Didn't find the key in the map of DMs.";
//  ASSERT_EQ(0, seh->DecryptDb(base::TidyPath(kSharesSubdir[1][0]),
//    ANONYMOUS, ser_dm, key, "", false, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, seh->SHA512(db_str2_, true));
//  ASSERT_EQ(0, seh->DecryptDb(base::TidyPath(kSharesSubdir[1][0]),
//    ANONYMOUS, "", key, "", false, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, seh->SHA512(db_str2_, true));
  fs::path key_path(fsys.MaidsafeDir(), fs::native);
  key_path /= key;
  fs::remove(key_path);
  sm->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

}  // namespace maidsafe
