/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Version:      1.0
* Created:      2009-01-28-10.59.46
* Revision:     none
* Compiler:     gcc
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

#include <string>
#include <vector>

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4308)
#endif
#include "boost/archive/text_oarchive.hpp"
#include "boost/archive/text_iarchive.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "boost/filesystem.hpp"
#include "maidsafe/common/test.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/self_encryption.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/client/filesystem/dataatlashandler.h"
#include "maidsafe/lifestuff/client/filesystem/pddir.h"
#include "maidsafe/lifestuff/client/filesystem/sehandler.h"
#include "maidsafe/lifestuff/client/clientutils.h"
#include "maidsafe/lifestuff/client/localstoremanager.h"
#include "maidsafe/lifestuff/client/sessionsingleton.h"
#include "maidsafe/common/chunk_store.h"
#include "maidsafe/lifestuff/sharedtest/cachepassport.h"
#include "maidsafe/lifestuff/sharedtest/testcallback.h"


namespace arg = std::placeholders;
namespace fs = boost::filesystem;

namespace test_dah {
static const boost::uint8_t K(4);
}  // namespace test_dah

namespace maidsafe {

namespace lifestuff {

namespace test {

class DataAtlasHandlerTest : public testing::Test {
 protected:
  DataAtlasHandlerTest()
      : test_root_dir_(file_system::TempDir() / ("maidsafe_TestDAH_" +
                       RandomAlphaNumericString(6))) {}

  ~DataAtlasHandlerTest() { }

  void SetUp() {
    SessionSingleton *ss(SessionSingleton::getInstance());
    std::shared_ptr<passport::test::CachePassport> passport(
        new passport::test::CachePassport(kRsaKeySize, 5, 10));
    passport->Init();
    ss->passport_ = passport;
    ss->ResetSession();
    ss->CreateTestPackets("PublicName");
    ss->SetUsername("user1");
    ss->SetPin("1234");
    ss->SetPassword("password1");
    ss->SetSessionName(false);
    ss->SetRootDbKey("whatever");
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
      if (fs::exists(file_system::LocalStoreManagerDir()))
        fs::remove_all(file_system::LocalStoreManagerDir());
      std::string session_name = ss->SessionName();
      if (fs::exists(file_system::MaidsafeDir(session_name)))
        fs::remove_all(file_system::MaidsafeDir(session_name));
      fs::create_directories(test_root_dir_);
    }
    catch(const std::exception& e) {
      DLOG(WARNING) << "DataAtlasHandlerTest::Setup - " << e.what()
                    << std::endl;
    }
    std::shared_ptr<ChunkStore> client_chunkstore_;
//  (new ChunkStore(test_root_dir_.string(), 0, 0));
//    ASSERT_TRUE(client_chunkstore_->Init());
//    int count(0);
//    while (!client_chunkstore_->is_initialised() && count < 10000) {
//      Sleep(boost::posix_time::milliseconds(10));
//      count += 10;
//    }
    std::shared_ptr<LocalStoreManager>
        sm(new LocalStoreManager(test_root_dir_));
    test::CallbackObject cb;
    sm->Init(std::bind(&test::CallbackObject::ReturnCodeCallback, &cb, arg::_1),
             0);
    if (cb.WaitForReturnCodeResult() != kSuccess) {
      FAIL();
      return;
    }
    ASSERT_EQ(0, file_system::Mount(ss->SessionName(), ss->DefConLevel()));
    boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
    std::shared_ptr<SEHandler> seh(new SEHandler());
    seh->Init(sm, client_chunkstore_);
    if (dah->Init(true))
      FAIL();

    // set up default dirs
    for (int i = 0; i < kRootSubdirSize; i++) {
      MetaDataMap mdm;
      std::string ser_mdm, key;
      mdm.set_id(-2);
      mdm.set_display_name(TidyPath(kRootSubdir[i][0]));
      mdm.set_type(EMPTY_DIRECTORY);
      mdm.set_stats("");
      mdm.set_tag("");
      mdm.set_file_size_high(0);
      mdm.set_file_size_low(0);
      boost::uint32_t current_time_ = /*GetDurationSinceEpoch()*/0;
      mdm.set_creation_time(current_time_);
      mdm.SerializeToString(&ser_mdm);
      if (kRootSubdir[i][1].empty())
        seh->GenerateUniqueKey(&key);
      else
        key = kRootSubdir[i][1];
      fs::create_directories(file_system::MaidsafeHomeDir(
          ss->SessionName()) / kRootSubdir[i][0]);
      dah->AddElement(TidyPath(kRootSubdir[i][0]), ser_mdm, "", key, true);
    }
  }

  void TearDown() {
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
      if (fs::exists(file_system::LocalStoreManagerDir()))
        fs::remove_all(file_system::LocalStoreManagerDir());
      std::string session_name = SessionSingleton::getInstance()->SessionName();
      if (fs::exists(file_system::MaidsafeDir(session_name)))
        fs::remove_all(file_system::MaidsafeDir(session_name));
    }
    catch(const std::exception& e) {
      DLOG(WARNING) << "DataAtlasHandlerTest::TearDown - " << e.what()
                    << std::endl;
    }
  }

  fs::path test_root_dir_;

  bool SerializeToString(maidsafe::encrypt::DataMap *data_map,
                         std::string& serialized) {
    std::stringstream string_stream;
    boost::archive::text_oarchive oa(string_stream);
    oa << *data_map;
    serialized = string_stream.str();
    return !serialized.empty();
  }
  bool ParseFromString(maidsafe::encrypt::DataMap *data_map,
                       const std::string& serialized) {
    std::stringstream string_stream(serialized);
    boost::archive::text_iarchive ia(string_stream);
    ia >> *data_map;
    return !data_map->content.empty();
  }

 private:
  explicit DataAtlasHandlerTest(const DataAtlasHandlerTest&);
  DataAtlasHandlerTest &operator=(const DataAtlasHandlerTest&);
};

TEST_F(DataAtlasHandlerTest, BEH_MAID_AddGetDataMapDetail) {
  // Test to insert a DataMap and Retrieve it
  // also checks to retrieve metadata for a filepath
  // checks the testDataMap existance
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  fs::path kDataBaseFile(test_root_dir_ / "kdataatlas.db");
  if (fs::exists(kDataBaseFile))
    fs::remove(kDataBaseFile);
  int result_;
  PdDir data_atlas(kDataBaseFile.string().c_str(), CREATE, &result_);

  std::string ser_dm, ser_mdm;
  std::string file_name = "Doc1.doc";
  std::string file_hash = "file hash1";

  // Creating DataMap
  encrypt::DataMap dm;
  dm.content = file_hash;
  maidsafe::encrypt::ChunkDetails chunk1;
  chunk1.pre_hash = "chunk1";
  chunk1.hash = "enc_chunk1";
//  chunk1.content = "content1";
  chunk1.pre_size = 100;
  chunk1.size = 99;
  dm.chunks.push_back(chunk1);
  maidsafe::encrypt::ChunkDetails chunk2;
  chunk2.pre_hash = "chunk2";
  chunk2.hash = "enc_chunk2";
//  chunk2.content = "content2";
  chunk2.pre_size = 100;
  chunk2.size = 99;
  dm.chunks.push_back(chunk2);
  maidsafe::encrypt::ChunkDetails chunk3;
  chunk3.pre_hash = "chunk3";
  chunk3.hash = "enc_chunk3";
//  chunk3.content = "content3";
  chunk3.pre_size = 100;
  chunk3.size = 99;
  dm.chunks.push_back(chunk3);
  SerializeToString(&dm, ser_dm);

  // Creating MetaDataMap
  MetaDataMap mdm;
  mdm.set_id(-2);
  mdm.set_display_name(file_name);
  mdm.set_type(REGULAR_FILE);
  mdm.add_file_hash(file_hash);
  mdm.set_stats("STATS");
  mdm.set_tag("TAG");
  mdm.set_file_size_high(4);
  mdm.set_file_size_low(5);
  mdm.set_creation_time(6);
  mdm.set_last_modified(7);
  mdm.set_last_access(8);
  mdm.SerializeToString(&ser_mdm);

  // Adding it to the DataAtlas
  ASSERT_EQ(0, data_atlas.AddElement(ser_mdm, ser_dm, "")) <<
            "DataMap and Metadata of file were not added to DataAtlas";

  // Getting the dataMap
  ASSERT_TRUE(data_atlas.DataMapExists(file_hash)) <<
              "DataMap does not exist in DataAtlas";
  std::string data_map, meta_data_map;
  ASSERT_EQ(0, data_atlas.GetDataMapFromHash(file_hash, &data_map)) <<
            "Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, data_atlas.GetMetaDataMap(file_name, &meta_data_map)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";

  encrypt::DataMap recovered_dm;
  MetaDataMap recovered_mdm;

  // check serialised DM = original DM (mdm will have changed
  // due to access and modified times being updated)
  ASSERT_EQ(ser_dm, data_map) << "Retrieved dm is not the same as original dm";

  EXPECT_TRUE(ParseFromString(&recovered_dm, data_map));
  EXPECT_TRUE(recovered_mdm.ParseFromString(meta_data_map));

  // check recovered elements = original elements
  EXPECT_EQ(dm.content, recovered_dm.content) <<
            "Filehash in datamap recovered is not the same as original datamap";
  EXPECT_NE(mdm.id(), recovered_mdm.id()) <<
            "id in metadatamap recovered is still -2";
  EXPECT_EQ(mdm.display_name(), recovered_mdm.display_name()) <<
            "file name in metadatamap recovered is not the "
            "same as original metadatamap";
  EXPECT_EQ(mdm.type(), recovered_mdm.type()) << "type in metadatamap recovered"
            " is not the same as original metadatamap";

  EXPECT_EQ(mdm.file_hash(0), recovered_mdm.file_hash(0)) << "file hash in "
            "metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.stats(), recovered_mdm.stats()) <<
            "stats in metadatamap recovered is not the same"
            " as original metadatamap";
  EXPECT_EQ(mdm.tag(), recovered_mdm.tag()) << "tag in metadatamap recovered is"
            "not the same as original metadatamap";
  EXPECT_EQ(mdm.file_size_high(), recovered_mdm.file_size_high()) <<
            "file_size_high in metadatamap recovered is not the same as "
            "original metadatamap";
  EXPECT_EQ(mdm.file_size_low(), recovered_mdm.file_size_low()) <<
            "file_size_low in metadatamap recovered is not the same as "
            "original metadatamap";
  EXPECT_EQ(mdm.creation_time(), recovered_mdm.creation_time()) <<
            "creation_time in metadatamap recovered is not the same as "
            "original metadatamap";
  ASSERT_NE(mdm.last_modified(), recovered_mdm.last_modified()) <<
            "last_modified in metadatamap recovered is the same as "
            "original metadatamap";
  ASSERT_NE(mdm.last_access(), recovered_mdm.last_access()) <<
            "last_access in metadatamap recovered is the same as "
            "original metadatamap";

  // check recovered DM size = origional DM size
  ASSERT_EQ(dm.chunks.size(), recovered_dm.chunks.size());

  // check each recovered DM chunk name = each origional DM chunk name
  for (int i = 0; i != static_cast<int>(dm.chunks.size()); i++) {
    EXPECT_EQ(dm.chunks[i].hash, recovered_dm.chunks[i].hash);
  }

  // check recovered encrypted DM size = origional encrypted DM size
  ASSERT_EQ(dm.chunks.size(),
            recovered_dm.chunks.size());

  // check each recovered encrypted DM chunk name = each origional
  // encrypted DM chunk name
  for (int i = 0; i != static_cast<int>(dm.chunks.size()); i++) {
      EXPECT_EQ(dm.chunks[i].hash,
                recovered_dm.chunks[i].hash);
  }

  ASSERT_EQ(0, data_atlas.Disconnect());

  if (fs::exists(kDataBaseFile))
    fs::remove(kDataBaseFile);
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_AddGetDataMapDAH) {
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm, ser_mdm;
  std::string dir_name = TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name = "Doc2.doc";
  std::string element_path = dir_name+file_name;
  std::string file_hash = "file hash1";

  // Creating DataMap
  encrypt::DataMap dm;
  maidsafe::encrypt::ChunkDetails chunk1;
  chunk1.pre_hash = "chunk1";
  chunk1.hash = "enc_chunk1";
//  chunk1.content = "content1";
  chunk1.pre_size = 100;
  chunk1.size = 99;
  dm.chunks.push_back(chunk1);
  maidsafe::encrypt::ChunkDetails chunk2;
  chunk2.pre_hash = "chunk2";
  chunk2.hash = "enc_chunk2";
//  chunk2.content = "content2";
  chunk2.pre_size = 100;
  chunk2.size = 99;
  dm.chunks.push_back(chunk2);
  maidsafe::encrypt::ChunkDetails chunk3;
  chunk3.pre_hash = "chunk3";
  chunk3.hash = "enc_chunk3";
//  chunk3.content = "content3";
  chunk3.pre_size = 100;
  chunk3.size = 99;
  dm.chunks.push_back(chunk3);
  SerializeToString(&dm, ser_dm);

  // Creating MetaDataMap
  MetaDataMap mdm;
  mdm.set_id(-2);
  mdm.set_display_name(file_name);
  mdm.set_type(REGULAR_FILE);
  mdm.add_file_hash(file_hash);
  mdm.set_stats("STATS");
  mdm.set_tag("TAG");
  mdm.set_file_size_high(4);
  mdm.set_file_size_low(5);
  mdm.set_creation_time(6);
  mdm.set_last_modified(7);
  mdm.set_last_access(8);
  mdm.SerializeToString(&ser_mdm);

  // Adding it to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path, ser_mdm, ser_dm, "", true)) <<
            "DataMap and Metadata of file were not added to DataAtlas";

  // Getting the dataMap
  std::string data_map, meta_data_map;
  ASSERT_EQ(0, dah_->GetDataMap(element_path, &data_map)) <<
            "Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path, &meta_data_map)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";

  encrypt::DataMap recovered_dm;
  MetaDataMap recovered_mdm;

  // check serialised DM = original DM (mdm will have changed due
  // to access and modified times being updated)
  ASSERT_EQ(ser_dm, data_map) <<
            "Retrieved dm is not the same as original dm";

  EXPECT_TRUE(ParseFromString(&recovered_dm, data_map));
  EXPECT_TRUE(recovered_mdm.ParseFromString(meta_data_map));

  // check recovered elements = original elements
  EXPECT_EQ(dm.content, recovered_dm.content) << "Filehash in datamap "
            "recovered is not the same as original datamap";
  EXPECT_NE(mdm.id(), recovered_mdm.id()) << "id in metadatamap recovered has "
            "not been updated";
  EXPECT_EQ(mdm.display_name(), recovered_mdm.display_name()) << "file name in"
            " metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.type(), recovered_mdm.type()) << "type in metadatamap recovered"
            " is not the same as original metadatamap";

  EXPECT_EQ(mdm.file_hash(0), recovered_mdm.file_hash(0)) << "file hash in "
            "metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.stats(), recovered_mdm.stats()) << "stats in metadatamap "
            "recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.tag(), recovered_mdm.tag()) << "tag in metadatamap recovered is"
            " not the same as original metadatamap";
  EXPECT_EQ(mdm.file_size_high(), recovered_mdm.file_size_high()) <<
            "file_size_high in metadatamap recovered is not the same as "
            "original metadatamap";
  EXPECT_EQ(mdm.file_size_low(), recovered_mdm.file_size_low()) <<
            "file_size_low in metadatamap recovered is not the same as "
            "original metadatamap";
  EXPECT_EQ(mdm.creation_time(), recovered_mdm.creation_time()) <<
            "creation_time in metadatamap recovered is not the same as "
            "original metadatamap";
  ASSERT_NE(mdm.last_modified(), recovered_mdm.last_modified()) <<
            "last_modified in metadatamap recovered is the same as "
            "original metadatamap";
  ASSERT_NE(mdm.last_access(), recovered_mdm.last_access()) <<
            "last_access in metadatamap recovered is the same as "
            "original metadatamap";

  // check recovered DM size = origional DM size
  ASSERT_EQ(dm.chunks.size(), recovered_dm.chunks.size());

  // check each recovered DM chunk name = each origional DM chunk name
  for (int i = 0; i != static_cast<int>(dm.chunks.size()); i++) {
    EXPECT_EQ(dm.chunks[i].hash, recovered_dm.chunks[i].hash);
  }

  // check recovered encrypted DM size = origional encrypted DM size
  ASSERT_EQ(dm.chunks.size(),
            recovered_dm.chunks.size());

  // check each recovered encrypted DM chunk name =
  // each origional encrypted DM chunk name
  for (int i = 0; i != static_cast<int>(dm.chunks.size()); i++) {
    EXPECT_EQ(dm.chunks[i].hash, recovered_dm.chunks[i].hash);
  }
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_ObscureFilename) {
  // Test to insert a DataMap and Retrieve it
  // also checks to retrieve metadata for a filepath
  // checks the testDataMap existance

  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm, ser_mdm;
  std::string dir_name = TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name("Doc!$%^&()-_+={}[];@~#,'''.doc");
  std::string element_path = dir_name + file_name;
  std::string file_hash("file hash obscure");

  // Creating DataMap
  encrypt::DataMap dm;
  dm.content = file_hash;
  maidsafe::encrypt::ChunkDetails chunk1;
  chunk1.pre_hash = "chunk1";
  chunk1.hash = "enc_chunk1";
//  chunk1.content = "content1";
  chunk1.pre_size = 100;
  chunk1.size = 99;
  dm.chunks.push_back(chunk1);
  maidsafe::encrypt::ChunkDetails chunk2;
  chunk2.pre_hash = "chunk2";
  chunk2.hash = "enc_chunk2";
//  chunk2.content = "content2";
  chunk2.pre_size = 100;
  chunk2.size = 99;
  dm.chunks.push_back(chunk2);
  maidsafe::encrypt::ChunkDetails chunk3;
  chunk3.pre_hash = "chunk3";
  chunk3.hash = "enc_chunk3";
//  chunk3.content = "content3";
  chunk3.pre_size = 100;
  chunk3.size = 99;
  dm.chunks.push_back(chunk3);
  SerializeToString(&dm, ser_dm);

  // Creating MetaDataMap
  MetaDataMap mdm;
  mdm.set_id(-2);
  mdm.set_display_name(file_name);
  mdm.set_type(REGULAR_FILE);
  mdm.add_file_hash(file_hash);
  mdm.set_stats("STATS OBS");
  mdm.set_tag("TAG OBS");
  mdm.set_file_size_high(0);
  mdm.set_file_size_low(20);
  mdm.set_creation_time(10000000);
  mdm.set_last_modified(7);
  mdm.set_last_access(8);
  mdm.SerializeToString(&ser_mdm);

  // Adding it to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path, ser_mdm, ser_dm, "", true)) <<
            "DataMap and Metadata of file were not added to DataAtlas";

  // Getting the dataMap
  std::string data_map, meta_data_map;
  ASSERT_EQ(0, dah_->GetDataMap(element_path, &data_map)) <<
            "Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path, &meta_data_map)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";

  encrypt::DataMap recovered_dm;
  MetaDataMap recovered_mdm;

  // check serialised DM = original DM (mdm will have changed due
  // to access and modified times being updated)
  ASSERT_EQ(ser_dm, data_map) <<"Retrieved dm is not the same as original dm";

  EXPECT_TRUE(ParseFromString(&recovered_dm, data_map));
  EXPECT_TRUE(recovered_mdm.ParseFromString(meta_data_map));

  // check recovered elements = original elements
  EXPECT_EQ(dm.content, recovered_dm.content) << "Filehash in datamap "
            "recovered is not the same as original datamap";
  EXPECT_NE(mdm.id(), recovered_mdm.id()) <<"id in metadatamap recovered has "
            "not been updated";
  EXPECT_EQ(mdm.display_name(), recovered_mdm.display_name()) <<"file name in "
            "metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.type(), recovered_mdm.type()) <<"type in metadatamap recovered "
            "is not the same as original metadatamap";

  EXPECT_EQ(mdm.file_hash(0), recovered_mdm.file_hash(0)) <<"file hash in "
            "metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.stats(), recovered_mdm.stats()) <<"stats in metadatamap "
            "recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.tag(), recovered_mdm.tag()) <<"tag in metadatamap recovered is "
            "not the same as original metadatamap";
  EXPECT_EQ(mdm.file_size_high(), recovered_mdm.file_size_high()) <<
            "file_size_high in metadatamap recovered is not the same as "
            "original metadatamap";
  EXPECT_EQ(mdm.file_size_low(), recovered_mdm.file_size_low()) <<
            "file_size_low in metadatamap recovered is not the same as "
            "original metadatamap";
  EXPECT_EQ(mdm.creation_time(), recovered_mdm.creation_time()) <<
            "creation_time in metadatamap recovered is not the same as "
            "original metadatamap";
  ASSERT_NE(mdm.last_modified(), recovered_mdm.last_modified()) <<
            "last_modified in metadatamap recovered is the same as "
            "original metadatamap";
  ASSERT_NE(mdm.last_access(), recovered_mdm.last_access()) << "last_access in "
            "metadatamap recovered is the same as original metadatamap";

  // check recovered DM size = origional DM size
  ASSERT_EQ(dm.chunks.size(), recovered_dm.chunks.size());

  // check each recovered DM chunk name = each origional DM chunk name
  for (int i = 0; i != static_cast<int>(dm.chunks.size()); i++) {
    EXPECT_EQ(dm.chunks[i].hash, recovered_dm.chunks[i].hash);
  }

  // check recovered encrypted DM size = origional encrypted DM size
  ASSERT_EQ(dm.chunks.size(), recovered_dm.chunks.size());

  // check each recovered encrypted DM chunk name =
  // each origional encrypted DM chunk name
  for (int i = 0; i != static_cast<int>(dm.chunks.size()); i++) {
    EXPECT_EQ(dm.chunks[i].hash, recovered_dm.chunks[i].hash);
  }
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_RemoveMSFileAndPath) {
  // Test to check the removal of a MSFile and the removal of its ms_path

  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm, ser_mdm, ser_dm_recovered, ser_mdmrecovered;
  std::string dir_name = TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name = "Doc3.doc";
  std::string element_path = dir_name+file_name;
  std::string file_hash = "file hash1";

  // Creating DataMap
  encrypt::DataMap dm;
  dm.content = file_hash;
  maidsafe::encrypt::ChunkDetails chunk1;
  chunk1.pre_hash = "chunk1";
  chunk1.hash = "enc_chunk1";
//  chunk1.content = "content1";
  chunk1.pre_size = 100;
  chunk1.size = 99;
  dm.chunks.push_back(chunk1);
  maidsafe::encrypt::ChunkDetails chunk2;
  chunk2.pre_hash = "chunk2";
  chunk2.hash = "enc_chunk2";
//  chunk2.content = "content2";
  chunk2.pre_size = 100;
  chunk2.size = 99;
  dm.chunks.push_back(chunk2);
  maidsafe::encrypt::ChunkDetails chunk3;
  chunk3.pre_hash = "chunk3";
  chunk3.hash = "enc_chunk3";
//  chunk3.content = "content3";
  chunk3.pre_size = 100;
  chunk3.size = 99;
  dm.chunks.push_back(chunk3);
  SerializeToString(&dm, ser_dm);

  // Creating MetaDataMap
  MetaDataMap mdm;
  mdm.set_id(-2);
  mdm.set_display_name(file_name);
  mdm.set_type(REGULAR_FILE);
  mdm.add_file_hash(file_hash);
  mdm.set_stats("STATS");
  mdm.set_tag("TAG");
  mdm.set_file_size_high(4);
  mdm.set_file_size_low(5);
  mdm.set_creation_time(6);
  mdm.set_last_modified(7);
  mdm.set_last_access(8);
  mdm.SerializeToString(&ser_mdm);

  // Adding it to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path, ser_mdm, ser_dm, "", true)) <<
            "DataMap and Metadata of file were not added to DataAtlas";

  // Check the added DM exists in the DataAtlas
  ASSERT_EQ(0, dah_->GetDataMap(element_path, &ser_dm_recovered)) <<
            "Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path, &ser_mdmrecovered)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";

  encrypt::DataMap recovered_dm;
  MetaDataMap recovered_mdm;

  // Check DM is sucessfully removed from the DataAtlas
  ASSERT_EQ(0, dah_->RemoveElement(element_path));

  // Check sucessful deletion of the DM from the DataAtlas
  ASSERT_NE(0, dah_->GetDataMap(element_path, &ser_dm_recovered)) <<
            "DataMap is still in the DataAtlas";
  ASSERT_NE(0, dah_->GetMetaDataMap(element_path, &ser_mdmrecovered)) <<
            "ms_path still in DataAtlas";
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_CopyMSFile) {
  // Test to check copying a MSFile

  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm_original, ser_mdmoriginal, ser_dm_recovered_original,
      ser_mdmrecovered_original;
  std::string ser_dm_recovered_copy1, ser_mdmrecovered_copy1,
      ser_dm_recovered_copy2, ser_mdmrecovered_copy2;
  std::string ser_dm_exists, ser_mdmexists, ser_dm_recovered_exists,
      ser_mdmrecovered_exists;
  std::string dir_name = TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name_original = "Original.doc";
  std::string file_name_copy = "Copy.doc";
  std::string file_name_exists = "Exists.doc";
  std::string element_path_original = dir_name+file_name_original;
  std::string element_path_copy = dir_name+file_name_copy;
  std::string element_path_exists = dir_name+file_name_exists;
  std::string file_hash_original = "file hash original";
  std::string file_hash_copy = "file hash copy";
  std::string file_hash_exists = "file hash exists";

  // Creating DataMaps
  encrypt::DataMap dm_original, dm_exists;
  dm_original.content = file_hash_original;
  maidsafe::encrypt::ChunkDetails chunk1;
  chunk1.pre_hash = "chunk1_original";
  chunk1.hash = "enc_chunk1_original";
//  chunk1.content = "content1_original";
  chunk1.pre_size = 100;
  chunk1.size = 99;
  dm_original.chunks.push_back(chunk1);
  maidsafe::encrypt::ChunkDetails chunk2;
  chunk2.pre_hash = "chunk2_original";
  chunk2.hash = "enc_chunk2_original";
//  chunk2.content = "content2_original";
  chunk2.pre_size = 100;
  chunk2.size = 99;
  dm_original.chunks.push_back(chunk2);
  maidsafe::encrypt::ChunkDetails chunk3;
  chunk3.pre_hash = "chunk3_original";
  chunk3.hash = "enc_chunk3_original";
//  chunk3.content = "content3_original";
  chunk3.pre_size = 100;
  chunk3.size = 99;
  dm_original.chunks.push_back(chunk3);
  SerializeToString(&dm_original, ser_dm_original);

  dm_exists.content = file_hash_exists;
  maidsafe::encrypt::ChunkDetails chunk1e;
  chunk1.pre_hash = "chunk1_exists";
  chunk1.hash = "enc_chunk1_exists";
//  chunk1.content = "content1_exists";
  chunk1.pre_size = 100;
  chunk1.size = 99;
  dm_exists.chunks.push_back(chunk1e);
  maidsafe::encrypt::ChunkDetails chunk2e;
  chunk2.pre_hash = "chunk2_exists";
  chunk2.hash = "enc_chunk2_exists";
//  chunk2.content = "content2_exists";
  chunk2.pre_size = 100;
  chunk2.size = 99;
  dm_exists.chunks.push_back(chunk2e);
  maidsafe::encrypt::ChunkDetails chunk3e;
  chunk3.pre_hash = "chunk3_exists";
  chunk3.hash = "enc_chunk3_exists";
//  chunk3.content = "content3_exists";
  chunk3.pre_size = 100;
  chunk3.size = 99;
  dm_exists.chunks.push_back(chunk3e);
  SerializeToString(&dm_exists, ser_dm_exists);

  // Creating MetaDataMaps
  MetaDataMap mdmoriginal, mdmexists;
  mdmoriginal.set_id(-2);
  mdmoriginal.set_display_name(file_name_original);
  mdmoriginal.set_type(REGULAR_FILE);
  mdmoriginal.add_file_hash(file_hash_original);
  mdmoriginal.set_stats("STATS_original");
  mdmoriginal.set_tag("TAG_original");
  mdmoriginal.set_file_size_high(4);
  mdmoriginal.set_file_size_low(5);
  mdmoriginal.set_creation_time(6);
  mdmoriginal.set_last_modified(7);
  mdmoriginal.set_last_access(8);
  mdmoriginal.SerializeToString(&ser_mdmoriginal);
  mdmexists.set_id(-2);
  mdmexists.set_display_name(file_name_exists);
  mdmexists.set_type(REGULAR_FILE);
  mdmexists.add_file_hash(file_hash_exists);
  mdmexists.set_stats("STATS_exists");
  mdmexists.set_tag("TAG_exists");
  mdmexists.set_file_size_high(9);
  mdmexists.set_file_size_low(10);
  mdmexists.set_creation_time(11);
  mdmexists.set_last_modified(12);
  mdmexists.set_last_access(13);
  mdmexists.SerializeToString(&ser_mdmexists);

  // Adding them to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path_original, ser_mdmoriginal,
            ser_dm_original, "", true)) << "DataMap and Metadata of file were "
            "not added to DataAtlas";
  ASSERT_EQ(0, dah_->AddElement(element_path_exists, ser_mdmexists,
            ser_dm_exists, "", true)) << "DataMap and Metadata of file were "
            "not added to DataAtlas";

  // Check the added DMs exist in the DataAtlas
  ASSERT_EQ(0, dah_->GetDataMap(element_path_original,
            &ser_dm_recovered_original)) <<
            "Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_original,
            &ser_mdmrecovered_original)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetDataMap(element_path_exists,
            &ser_dm_recovered_exists)) <<
            "Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_exists,
            &ser_mdmrecovered_exists)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";

  encrypt::DataMap recovered_dm_copy1, recovered_dm_exists, recovered_dm_copy2;
  MetaDataMap recovered_mdmcopy1, recovered_mdmexists, recovered_mdmcopy2;

  // Check file is not copied to non-existent dir
  ASSERT_NE(0, dah_->CopyElement(element_path_original,
            "non-existent dir/non-existent file", "", false));

  // Check file is not copied to itself
  ASSERT_NE(0, dah_->CopyElement(element_path_original, element_path_original,
            "", false));

  // Check file is sucessfully copied
  ASSERT_EQ(0, dah_->CopyElement(element_path_original, element_path_copy, "",
            false));
  ASSERT_EQ(0, dah_->GetDataMap(element_path_copy, &ser_dm_recovered_copy1));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_copy,
            &ser_mdmrecovered_copy1));
  ASSERT_TRUE(ParseFromString(&recovered_dm_copy1, ser_dm_recovered_copy1));
  ASSERT_TRUE(recovered_mdmcopy1.ParseFromString(ser_mdmrecovered_copy1));
  ASSERT_EQ(dm_original.content, recovered_dm_copy1.content);
  ASSERT_EQ(mdmoriginal.stats(), recovered_mdmcopy1.stats());
  ASSERT_EQ(0, dah_->GetDataMap(element_path_original,
            &ser_dm_recovered_original));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_original,
            &ser_mdmrecovered_original));

  // Check file is not copied over existing file when force bool is set to false
  ASSERT_NE(0, dah_->CopyElement(element_path_original, element_path_exists, "",
            false));
  ASSERT_EQ(0, dah_->GetDataMap(element_path_exists, &ser_dm_recovered_exists));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_exists,
            &ser_mdmrecovered_exists));
  ASSERT_TRUE(ParseFromString(&recovered_dm_exists, ser_dm_recovered_exists));
  ASSERT_TRUE(recovered_mdmexists.ParseFromString(ser_mdmrecovered_exists));
  ASSERT_EQ(dm_exists.content, recovered_dm_exists.content);
  ASSERT_EQ(mdmexists.stats(), recovered_mdmexists.stats());

  // Check file is copied over existing file when force bool is set to true
  ASSERT_EQ(0, dah_->CopyElement(element_path_original, element_path_exists, "",
            true));
  ASSERT_EQ(0, dah_->GetDataMap(element_path_exists, &ser_dm_recovered_copy2));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_exists,
            &ser_mdmrecovered_copy2));
  ASSERT_TRUE(ParseFromString(&recovered_dm_copy2, ser_dm_recovered_copy2));
  ASSERT_TRUE(recovered_mdmcopy2.ParseFromString(ser_mdmrecovered_copy2));
  ASSERT_EQ(dm_original.content, recovered_dm_copy2.content);
  ASSERT_EQ(mdmoriginal.stats(), recovered_mdmcopy2.stats());
  ser_dm_recovered_original="";
  ser_mdmrecovered_original="";
  ASSERT_EQ(0, dah_->GetDataMap(element_path_original,
            &ser_dm_recovered_original));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_original,
            &ser_mdmrecovered_original));
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_RenameMSFile) {
  // Test to check renaming a MSFile

  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm_original, ser_mdmoriginal, ser_dm_recovered_original,
      ser_mdmrecovered_original;
  std::string ser_dm_recovered_copy1, ser_mdmrecovered_copy1,
      ser_dm_recovered_copy2, ser_mdmrecovered_copy2;
  std::string ser_dm_exists, ser_mdmexists, ser_dm_recovered_exists,
      ser_mdmrecovered_exists;
  std::string dir_name = TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name_original = "Original.doc";
  std::string file_name_copy = "Original.doc~.copy";
  std::string file_name_exists = "Exists.doc";
  std::string element_path_original = dir_name+file_name_original;
  std::string element_path_copy = dir_name+file_name_copy;
  std::string element_path_exists = dir_name+file_name_exists;
  std::string file_hash_original = "file hash original";
  std::string file_hash_copy = "file hash copy";
  std::string file_hash_exists = "file hash exists";

  // Creating DataMaps
  encrypt::DataMap dm_original, dm_exists;
  dm_original.content = file_hash_original;
  maidsafe::encrypt::ChunkDetails chunk1;
  chunk1.pre_hash = "chunk1_original";
  chunk1.hash = "enc_chunk1_original";
//  chunk1.content = "content1_original";
  chunk1.pre_size = 100;
  chunk1.size = 99;
  dm_original.chunks.push_back(chunk1);
  maidsafe::encrypt::ChunkDetails chunk2;
  chunk2.pre_hash = "chunk2_original";
  chunk2.hash = "enc_chunk2_original";
//  chunk2.content = "content2_original";
  chunk2.pre_size = 100;
  chunk2.size = 99;
  dm_original.chunks.push_back(chunk2);
  maidsafe::encrypt::ChunkDetails chunk3;
  chunk3.pre_hash = "chunk3_original";
  chunk3.hash = "enc_chunk3_original";
//  chunk3.content = "content3_original";
  chunk3.pre_size = 100;
  chunk3.size = 99;
  dm_original.chunks.push_back(chunk3);
  SerializeToString(&dm_original, ser_dm_original);

  dm_exists.content = file_hash_exists;
  maidsafe::encrypt::ChunkDetails chunk1e;
  chunk1.pre_hash = "chunk1_exists";
  chunk1.hash = "enc_chunk1_exists";
//  chunk1.content = "content1_exists";
  chunk1.pre_size = 100;
  chunk1.size = 99;
  dm_exists.chunks.push_back(chunk1e);
  maidsafe::encrypt::ChunkDetails chunk2e;
  chunk2.pre_hash = "chunk2_exists";
  chunk2.hash = "enc_chunk2_exists";
//  chunk2.content = "content2_exists";
  chunk2.pre_size = 100;
  chunk2.size = 99;
  dm_exists.chunks.push_back(chunk2e);
  maidsafe::encrypt::ChunkDetails chunk3e;
  chunk3.pre_hash = "chunk3_exists";
  chunk3.hash = "enc_chunk3_exists";
//  chunk3.content = "content3_exists";
  chunk3.pre_size = 100;
  chunk3.size = 99;
  dm_exists.chunks.push_back(chunk3e);
  SerializeToString(&dm_exists, ser_dm_exists);

  // Creating MetaDataMaps
  MetaDataMap mdmoriginal, mdmexists;
  mdmoriginal.set_id(-2);
  mdmoriginal.set_display_name(file_name_original);
  mdmoriginal.set_type(REGULAR_FILE);
  mdmoriginal.add_file_hash(file_hash_original);
  mdmoriginal.set_stats("STATS_original");
  mdmoriginal.set_tag("TAG_original");
  mdmoriginal.set_file_size_high(4);
  mdmoriginal.set_file_size_low(5);
  mdmoriginal.set_creation_time(6);
  mdmoriginal.set_last_modified(7);
  mdmoriginal.set_last_access(8);
  mdmoriginal.SerializeToString(&ser_mdmoriginal);
  mdmexists.set_id(-2);
  mdmexists.set_display_name(file_name_exists);
  mdmexists.set_type(REGULAR_FILE);
  mdmexists.add_file_hash(file_hash_exists);
  mdmexists.set_stats("STATS_exists");
  mdmexists.set_tag("TAG_exists");
  mdmexists.set_file_size_high(9);
  mdmexists.set_file_size_low(10);
  mdmexists.set_creation_time(11);
  mdmexists.set_last_modified(12);
  mdmexists.set_last_access(13);
  mdmexists.SerializeToString(&ser_mdmexists);

  // Adding them to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path_original, ser_mdmoriginal,
            ser_dm_original, "", true)) << "DataMap and Metadata of file were "
            "not added to DataAtlas";
  ASSERT_EQ(0, dah_->AddElement(element_path_exists, ser_mdmexists,
            ser_dm_exists, "", true)) << "DataMap and Metadata of file were "
            "not added to DataAtlas";

  // Check the added DMs exist in the DataAtlas
  ASSERT_EQ(0, dah_->GetDataMap(element_path_original,
            &ser_dm_recovered_original)) <<
            "Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_original,
            &ser_mdmrecovered_original)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetDataMap(element_path_exists,
            &ser_dm_recovered_exists)) <<
            "Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_exists,
            &ser_mdmrecovered_exists)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";

  encrypt::DataMap recovered_dm_copy1, recovered_dm_exists, recovered_dm_copy2;
  MetaDataMap recovered_mdmcopy1, recovered_mdmexists, recovered_mdmcopy2;

  // Check file is not renamed to non-existent dir
  ASSERT_NE(0, dah_->RenameElement(element_path_original,
            "non-existent dir/non-existent file", false));

  // Check file is not renamed to itself
  ASSERT_NE(0, dah_->RenameElement(element_path_original, element_path_original,
            false));

  // Check file is sucessfully renamed
  ASSERT_EQ(0, dah_->RenameElement(element_path_original, element_path_copy,
            false));
  ASSERT_EQ(0, dah_->GetDataMap(element_path_copy, &ser_dm_recovered_copy1));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_copy,
            &ser_mdmrecovered_copy1));
  ASSERT_TRUE(ParseFromString(&recovered_dm_copy1, ser_dm_recovered_copy1));
  ASSERT_TRUE(recovered_mdmcopy1.ParseFromString(ser_mdmrecovered_copy1));
  ASSERT_EQ(dm_original.content, recovered_dm_copy1.content);
  ASSERT_EQ(mdmoriginal.stats(), recovered_mdmcopy1.stats());
  ASSERT_NE(0, dah_->GetDataMap(element_path_original,
            &ser_dm_recovered_original));
  ASSERT_NE(0, dah_->GetMetaDataMap(element_path_original,
            &ser_mdmrecovered_original));

  // Add & check original element again to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path_original, ser_mdmoriginal,
            ser_dm_original, "", true));
  ASSERT_EQ(0, dah_->GetDataMap(element_path_original,
            &ser_dm_recovered_original));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_original,
            &ser_mdmrecovered_original));

  // Check file is not renamed over existing file
  // when force bool is set to false
  ASSERT_NE(0, dah_->RenameElement(element_path_original, element_path_exists,
            false));
  ASSERT_EQ(0, dah_->GetDataMap(element_path_exists, &ser_dm_recovered_exists));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_exists,
            &ser_mdmrecovered_exists));
  ASSERT_TRUE(ParseFromString(&recovered_dm_exists, ser_dm_recovered_exists));
  ASSERT_TRUE(recovered_mdmexists.ParseFromString(ser_mdmrecovered_exists));
  ASSERT_EQ(dm_exists.content, recovered_dm_exists.content);
  ASSERT_EQ(mdmexists.stats(), recovered_mdmexists.stats());

  // Check file is renamed over existing file when force bool is set to true
  ASSERT_EQ(0, dah_->RenameElement(element_path_original, element_path_exists,
            true));
  ASSERT_EQ(0, dah_->GetDataMap(element_path_exists, &ser_dm_recovered_copy2));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_exists,
            &ser_mdmrecovered_copy2));
  ASSERT_TRUE(ParseFromString(&recovered_dm_copy2, ser_dm_recovered_copy2));
  ASSERT_TRUE(recovered_mdmcopy2.ParseFromString(ser_mdmrecovered_copy2));
  ASSERT_EQ(dm_original.content, recovered_dm_copy2.content);
  ASSERT_EQ(mdmoriginal.stats(), recovered_mdmcopy2.stats());
  ser_dm_recovered_original="";
  ser_mdmrecovered_original="";
  ASSERT_NE(0, dah_->GetDataMap(element_path_original,
            &ser_dm_recovered_original));
  ASSERT_NE(0, dah_->GetMetaDataMap(element_path_original,
            &ser_mdmrecovered_original));
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_RenameDir) {
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
//  std::string ser_dm, recovered_ser_dm;
  std::string ser_mdm, recovered_ser_mdm;
  std::string dir_name("summat");
  std::string dir_path(TidyPath(kRootSubdir[0][0]) + "/" + dir_name);
  MetaDataMap mdm, recovered_mdm;
  mdm.set_id(-2);
  mdm.set_display_name(dir_name);
  mdm.set_type(EMPTY_DIRECTORY);
  mdm.set_stats("STATS1");
  mdm.set_tag("TAG1");
  mdm.set_creation_time(6);
  mdm.set_last_modified(7);
  mdm.set_last_access(8);
  mdm.SerializeToString(&ser_mdm);

  //  Add and retrieve data for folder
  ASSERT_EQ(0, dah->AddElement(dir_path, ser_mdm, "", "Dir Key", true))
            << "Metadata of directory was not added to DataAtlas";
  ASSERT_EQ(0, dah->GetMetaDataMap(dir_path, &recovered_ser_mdm)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";
  EXPECT_TRUE(recovered_mdm.ParseFromString(recovered_ser_mdm)) <<
              "Metadata corrupted (cannot be parsed)";
  ASSERT_EQ(mdm.display_name(), recovered_mdm.display_name()) <<
            "Display name has changed in MetaDataMap";
  ASSERT_EQ(mdm.type(), recovered_mdm.type()) <<
            "Directory type has changed in MetaDataMap";
  ASSERT_EQ(mdm.stats(), recovered_mdm.stats()) <<
            "Stats have changed in MetaDataMap";
  ASSERT_EQ(mdm.tag(), recovered_mdm.tag()) <<
            "Tag has changed in MetaDataMap";
  ASSERT_EQ(mdm.file_size_high(), recovered_mdm.file_size_high()) <<
            "file_size_high has changed in MetaDataMap";
  ASSERT_EQ(mdm.file_size_low(), recovered_mdm.file_size_low()) <<
            "file_size_low has changed in MetaDataMap";
  ASSERT_EQ(mdm.creation_time(), recovered_mdm.creation_time()) <<
            "Creation time has changed in MetaDataMap";
  ASSERT_NE(mdm.last_modified(), recovered_mdm.last_modified()) <<
            "Last modified time has not changed in MetaDataMap";
  ASSERT_NE(mdm.last_access(), recovered_mdm.last_access()) <<
            "Last access time has not changed in MetaDataMap";

  std::string new_dir_name("summat_else");
  std::string new_dir_path(TidyPath(kRootSubdir[0][0]) + "/" +
                           new_dir_name);
  mdm.set_display_name(new_dir_name);
  ASSERT_EQ(0, dah->RenameElement(dir_path, new_dir_path, true));
  ASSERT_EQ(0, dah->GetMetaDataMap(new_dir_path, &recovered_ser_mdm)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";
  EXPECT_TRUE(recovered_mdm.ParseFromString(recovered_ser_mdm)) <<
              "Metadata corrupted (cannot be parsed)";
  ASSERT_EQ(mdm.display_name(), recovered_mdm.display_name()) <<
            "Display name has changed in MetaDataMap";
  ASSERT_EQ(mdm.type(), recovered_mdm.type()) <<
            "Directory type has changed in MetaDataMap";
  ASSERT_EQ(mdm.stats(), recovered_mdm.stats()) <<
            "Stats have changed in MetaDataMap";
  ASSERT_EQ(mdm.tag(), recovered_mdm.tag()) <<
            "Tag has changed in MetaDataMap";
  ASSERT_EQ(mdm.file_size_high(), recovered_mdm.file_size_high()) <<
            "file_size_high has changed in MetaDataMap";
  ASSERT_EQ(mdm.file_size_low(), recovered_mdm.file_size_low()) <<
            "file_size_low has changed in MetaDataMap";
  ASSERT_EQ(mdm.creation_time(), recovered_mdm.creation_time()) <<
            "Creation time has changed in MetaDataMap";
  ASSERT_NE(mdm.last_modified(), recovered_mdm.last_modified()) <<
            "Last modified time has not changed in MetaDataMap";
  ASSERT_NE(mdm.last_access(), recovered_mdm.last_access()) <<
            "Last access time has not changed in MetaDataMap";
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_RemoveMSFileRepeatedDataMap) {
  // Test to check the removal of a MSFile whose DataMap is also in
  // another ms_path so the DataMap must not be removed

  // declare a serialised DataMap and serialised MetaDataMap
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  std::string ser_dm, ser_mdm, ser_mdm2, ser_dm_recovered, ser_mdmrecovered,
              ser_mdmrecovered2;
  std::string dir_name = TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name = "Doc4.doc";
  std::string file_name2 = "MyFiLe.doc";
  std::string element_path = dir_name+file_name;
  std::string element_path2 = dir_name+file_name2;
  std::string file_hash = "file hash1";

  // Creating DataMap
  encrypt::DataMap dm;
  dm.content = file_hash;
  maidsafe::encrypt::ChunkDetails chunk1;
  chunk1.pre_hash = "chunk1";
  chunk1.hash = "enc_chunk1";
//  chunk1.content = "content1";
  chunk1.pre_size = 100;
  chunk1.size = 99;
  dm.chunks.push_back(chunk1);
  maidsafe::encrypt::ChunkDetails chunk2;
  chunk2.pre_hash = "chunk2";
  chunk2.hash = "enc_chunk2";
//  chunk2.content = "content2";
  chunk2.pre_size = 100;
  chunk2.size = 99;
  dm.chunks.push_back(chunk2);
  maidsafe::encrypt::ChunkDetails chunk3;
  chunk3.pre_hash = "chunk3";
  chunk3.hash = "enc_chunk3";
//  chunk3.content = "content3";
  chunk3.pre_size = 100;
  chunk3.size = 99;
  dm.chunks.push_back(chunk3);
  SerializeToString(&dm, ser_dm);

  // Creating MetaDataMap
  MetaDataMap mdm;
  mdm.set_id(-2);
  mdm.set_display_name(file_name);
  mdm.set_type(REGULAR_FILE);
  mdm.add_file_hash(file_hash);
  mdm.set_stats("STATS");
  mdm.set_tag("TAG");
  mdm.set_file_size_high(4);
  mdm.set_file_size_low(5);
  mdm.set_creation_time(6);
  mdm.set_last_modified(7);
  mdm.set_last_access(8);
  mdm.SerializeToString(&ser_mdm);

  // Adding it to the DataAtlas
  ASSERT_EQ(0, dah->AddElement(element_path, ser_mdm, ser_dm, "", true)) <<
            "DataMap and Metadata of file were not added to DataAtlas";

  // Check the added DM exists in the DataAtlas
  ASSERT_EQ(0, dah->GetDataMap(element_path, &ser_dm_recovered)) <<
            "Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah->GetMetaDataMap(element_path, &ser_mdmrecovered)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";

  // Creating MetaDataMap
  MetaDataMap mdm2;
  mdm.set_id(-2);
  mdm.set_display_name(file_name2);
  mdm.set_type(SMALL_FILE);
  mdm.add_file_hash(file_hash);
  mdm.set_stats("STATS");
  mdm.set_tag("TAG");
  mdm.set_file_size_high(4);
  mdm.set_file_size_low(5);
  mdm.set_creation_time(6);
  mdm.set_last_modified(7);
  mdm.set_last_access(8);
  mdm.SerializeToString(&ser_mdm2);

  // Adding it to the DataAtlas
  ASSERT_EQ(0, dah->AddElement(element_path2, ser_mdm2, ser_dm, "", true)) <<
            "DataMap and Metadata of file were not added to DataAtlas";

  // Check the added DM exists in the DataAtlas
  ASSERT_EQ(0, dah->GetDataMap(element_path2, &ser_dm_recovered)) <<
            "Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah->GetMetaDataMap(element_path2, &ser_mdmrecovered2)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";

  // Check DM is sucessfully removed from the DataAtlas
  ASSERT_EQ(0, dah->RemoveElement(element_path));

  // Check sucessful deletion of the ms_path from the DataAtlas
  // and that the DM is still there
  ASSERT_EQ(0, dah->GetDataMap(element_path2, &ser_dm_recovered)) <<
            "DataMap was removed from the DataAtlas";
  ASSERT_NE(0, dah->GetMetaDataMap(element_path, &ser_mdmrecovered)) <<
            "ms_path still in DataAtlas";
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_AddRepeatedDataMap) {
  // Test to insert a DataMap and Retrieve it
  // Test to check the removal of a MSFile whose DataMap
  // is also in another ms_path
  // so the DataMap must not be removed

  // declare a serialised DataMap and serialised MetaDataMap
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm, ser_mdm1, ser_mdm2, ser_dm_recovered1,
      ser_dm_recovered2, ser_mdmrecovered1, ser_mdmrecovered2;
  std::string dir_name = TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name1 = "Doc5.doc";
  std::string file_name2 = "MyFiLe2.doc";
  std::string element_path1 = dir_name+file_name1;
  std::string element_path2 = dir_name+file_name2;
  std::string file_hash = "file hash1";

  // Creating DataMap
  encrypt::DataMap dm;
  dm.content = file_hash;
  maidsafe::encrypt::ChunkDetails chunk1;
  chunk1.pre_hash = "chunk1";
  chunk1.hash = "enc_chunk1";
//  chunk1.content = "content1";
  chunk1.pre_size = 100;
  chunk1.size = 99;
  dm.chunks.push_back(chunk1);
  maidsafe::encrypt::ChunkDetails chunk2;
  chunk2.pre_hash = "chunk2";
  chunk2.hash = "enc_chunk2";
//  chunk2.content = "content2";
  chunk2.pre_size = 100;
  chunk2.size = 99;
  dm.chunks.push_back(chunk2);
  maidsafe::encrypt::ChunkDetails chunk3;
  chunk3.pre_hash = "chunk3";
  chunk3.hash = "enc_chunk3";
//  chunk3.content = "content3";
  chunk3.pre_size = 100;
  chunk3.size = 99;
  dm.chunks.push_back(chunk3);
  SerializeToString(&dm, ser_dm);

  // Creating MetaDataMap
  MetaDataMap mdm1;
  mdm1.set_id(-2);
  mdm1.set_display_name(file_name1);
  mdm1.set_type(REGULAR_FILE);
  mdm1.add_file_hash(file_hash);
  mdm1.set_stats("STATS1");
  mdm1.set_tag("TAG1");
  mdm1.set_file_size_high(4);
  mdm1.set_file_size_low(5);
  mdm1.set_creation_time(6);
  mdm1.set_last_modified(7);
  mdm1.set_last_access(8);
  mdm1.SerializeToString(&ser_mdm1);

  // Adding it to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path1, ser_mdm1, ser_dm, "", true)) <<
            "DataMap and Metadata of file were not added to DataAtlas";

  // Creating MetaDataMap
  MetaDataMap mdm2;
  mdm2.set_id(-2);
  mdm2.set_display_name(file_name2);
  mdm2.set_type(SMALL_FILE);
  mdm2.add_file_hash(file_hash);
  mdm2.set_stats("STATS2");
  mdm2.set_tag("TAG2");
  mdm2.set_file_size_high(9);
  mdm2.set_file_size_low(10);
  mdm2.set_creation_time(11);
  mdm2.set_last_modified(12);
  mdm2.set_last_access(13);
  mdm2.SerializeToString(&ser_mdm2);

  // Adding it to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path2, ser_mdm2, ser_dm, "", true)) <<
            "DataMap and Metadata of file were not added to DataAtlas";

  MetaDataMap recovered_mdm1;
  MetaDataMap recovered_mdm2;

  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path1, &ser_mdmrecovered1)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path2, &ser_mdmrecovered2)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";
  EXPECT_TRUE(recovered_mdm1.ParseFromString(ser_mdmrecovered1));
  EXPECT_TRUE(recovered_mdm2.ParseFromString(ser_mdmrecovered2));

  ASSERT_EQ(file_name1, recovered_mdm1.display_name());
  ASSERT_EQ(file_name2, recovered_mdm2.display_name());
  ASSERT_EQ(file_hash, recovered_mdm1.file_hash(0));
  ASSERT_EQ(file_hash, recovered_mdm2.file_hash(0));

  encrypt::DataMap recovered_dm;

  ASSERT_EQ(0, dah_->GetDataMap(element_path1, &ser_dm_recovered1)) <<
            "Didn't retrieve DataMap from DataAtlas";
  EXPECT_TRUE(ParseFromString(&recovered_dm, ser_dm_recovered1));
  EXPECT_EQ(dm.content, recovered_dm.content);
  ASSERT_EQ(dm.chunks.size(), recovered_dm.chunks.size());
  for (int i = 0; i != static_cast<int>(dm.chunks.size()); i++) {
      EXPECT_EQ(dm.chunks[i].pre_hash, recovered_dm.chunks[i].pre_hash);
  }
  ASSERT_EQ(dm.chunks.size(),
            recovered_dm.chunks.size());
  for (int i = 0; i != static_cast<int>(dm.chunks.size()); i++) {
    EXPECT_EQ(dm.chunks[i].hash, recovered_dm.chunks[i].hash);
  }

  ASSERT_EQ(0, dah_->GetDataMap(element_path2, &ser_dm_recovered2)) <<
            "Didn't retrieve DataMap from DataAtlas";
  EXPECT_EQ(ser_dm_recovered1, ser_dm_recovered2) <<
            "DataMaps aren't the same";
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_AddEmptyDir) {
  // Adds an empty directory to the DataAtlas and then adds a regular file
  // to the directory
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm, ser_mdm1, ser_mdm2, ser_dm_recovered,
    ser_mdmrecovered1, ser_mdmrecovered2;
  std::string dir_name = TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name1 = "Docs";
  std::string file_name2 = "MyFiLe3.doc";
  std::string element_path1 = dir_name + file_name1;
  std::string element_path2 = element_path1 + "/" + file_name2;
  std::string file_hash = "file hash1";

  // Creating DataMap
  encrypt::DataMap dm;
  dm.content = file_hash;
  maidsafe::encrypt::ChunkDetails chunk1;
  chunk1.pre_hash = "chunk1";
  chunk1.hash = "enc_chunk1";
//  chunk1.content = "content1";
  chunk1.pre_size = 100;
  chunk1.size = 99;
  dm.chunks.push_back(chunk1);
  maidsafe::encrypt::ChunkDetails chunk2;
  chunk2.pre_hash = "chunk2";
  chunk2.hash = "enc_chunk2";
//  chunk2.content = "content2";
  chunk2.pre_size = 100;
  chunk2.size = 99;
  dm.chunks.push_back(chunk2);
  maidsafe::encrypt::ChunkDetails chunk3;
  chunk3.pre_hash = "chunk3";
  chunk3.hash = "enc_chunk3";
//  chunk3.content = "content3";
  chunk3.pre_size = 100;
  chunk3.size = 99;
  dm.chunks.push_back(chunk3);
  SerializeToString(&dm, ser_dm);

  // Creating MetaDataMaps
  MetaDataMap mdm1, mdm2;
  mdm1.set_id(-2);
  mdm1.set_display_name(file_name1);
  mdm1.set_type(EMPTY_DIRECTORY);
  mdm1.set_stats("STATS1");
  mdm1.set_tag("TAG1");
  mdm1.set_creation_time(6);
  mdm1.set_last_modified(7);
  mdm1.set_last_access(8);
  mdm1.SerializeToString(&ser_mdm1);
  mdm2.set_id(-2);
  mdm2.set_display_name(file_name2);
  mdm2.set_type(REGULAR_FILE);
  mdm2.add_file_hash(file_hash);
  mdm2.set_stats("STATS2");
  mdm2.set_tag("TAG2");
  mdm2.set_file_size_high(9);
  mdm2.set_file_size_low(10);
  mdm2.set_creation_time(11);
  mdm2.set_last_modified(12);
  mdm2.set_last_access(13);
  mdm2.SerializeToString(&ser_mdm2);

  MetaDataMap recovered_mdm1, recovered_mdm2;
  encrypt::DataMap recovered_dm;

  //  Add and retrieve data for folder
  ASSERT_EQ(0, dah_->AddElement(element_path1, ser_mdm1, "", "Dir Key", true))
            << "Metadata of directory was not added to DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path1, &ser_mdmrecovered1)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";
  EXPECT_TRUE(recovered_mdm1.ParseFromString(ser_mdmrecovered1)) <<
              "Metadata corrupted (cannot be parsed)";
  ASSERT_EQ(mdm1.display_name(), recovered_mdm1.display_name()) <<
            "Display name has changed in MetaDataMap";
  ASSERT_EQ(mdm1.type(), recovered_mdm1.type()) <<
            "Directory type has changed in MetaDataMap";
  ASSERT_EQ(mdm1.stats(), recovered_mdm1.stats()) <<
            "Stats have changed in MetaDataMap";
  ASSERT_EQ(mdm1.tag(), recovered_mdm1.tag()) <<
            "Tag has changed in MetaDataMap";
  ASSERT_EQ(mdm1.file_size_high(), recovered_mdm1.file_size_high()) <<
            "file_size_high has changed in MetaDataMap";
  ASSERT_EQ(mdm1.file_size_low(), recovered_mdm1.file_size_low()) <<
            "file_size_low has changed in MetaDataMap";
  ASSERT_EQ(mdm1.creation_time(), recovered_mdm1.creation_time()) <<
            "Creation time has changed in MetaDataMap";
  ASSERT_NE(mdm1.last_modified(), recovered_mdm1.last_modified()) <<
            "Last modified time has not changed in MetaDataMap";
  ASSERT_NE(mdm1.last_access(), recovered_mdm1.last_access()) <<
            "Last access time has not changed in MetaDataMap";

  //  Add and retrieve data for file
  ASSERT_EQ(0, dah_->AddElement(element_path2, ser_mdm2, ser_dm, "", true)) <<
            "Metadata and DataMap of file was not added to DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path2, &ser_mdmrecovered2)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetDataMap(element_path2, &ser_dm_recovered)) <<
            "Didn't retrieve DataMap from DataAtlas";
  EXPECT_TRUE(recovered_mdm2.ParseFromString(ser_mdmrecovered2)) <<
              "MetaDataMap corrupted (cannot be parsed)";
  ASSERT_EQ(mdm2.display_name(), recovered_mdm2.display_name()) <<
            "Display name has changed in MetaDataMap";
  ASSERT_EQ(mdm2.type(), recovered_mdm2.type()) <<
            "File type has changed in MetaDataMap";
  ASSERT_EQ(mdm2.file_hash(0), recovered_mdm2.file_hash(0)) <<
            "File hash has changed in MetaDataMap";
  ASSERT_EQ(mdm2.stats(), recovered_mdm2.stats()) <<
            "Stats have changed in MetaDataMap";
  ASSERT_EQ(mdm2.tag(), recovered_mdm2.tag()) <<
            "Tag has changed in MetaDataMap";
  ASSERT_EQ(mdm2.file_size_high(), recovered_mdm2.file_size_high()) <<
            "file_size_high has changed in MetaDataMap";
  ASSERT_EQ(mdm2.file_size_low(), recovered_mdm2.file_size_low()) <<
            "file_size_low has changed in MetaDataMap";
  ASSERT_EQ(mdm2.creation_time(), recovered_mdm2.creation_time()) <<
            "Creation time has changed in MetaDataMap";
  ASSERT_NE(mdm2.last_modified(), recovered_mdm2.last_modified()) <<
            "Last modified time has not changed in MetaDataMap";
  ASSERT_NE(mdm2.last_access(), recovered_mdm2.last_access()) <<
            "Last access time has not changed in MetaDataMap";
  ASSERT_EQ(ser_dm, ser_dm_recovered) << "DataMap different from original";
  EXPECT_TRUE(ParseFromString(&recovered_dm, ser_dm_recovered)) <<
              "DataMap corrupted (cannot be parsed)";
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_EmptyFileHandling) {
  // Adds an empty file to the directory, then changes the file to non-empty
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm1, ser_mdm1, ser_dm_recovered1, ser_mdmrecovered1;
  std::string ser_dm2, ser_mdm2, ser_dm_recovered2, ser_mdmrecovered2;
  std::string dir_name = TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name = "MyFiLe4.doc";
  std::string element_path = dir_name+file_name;
  std::string file_hash_empty = "empty file hash";
  std::string file_hash_regular = "regular file hash";

  // Creating DataMap
  encrypt::DataMap dm1;
  dm1.content = file_hash_empty;
  SerializeToString(&dm1, ser_dm1);

  // Creating MetaDataMap
  MetaDataMap mdm1;
  mdm1.set_id(-2);
  mdm1.set_display_name(file_name);
  mdm1.set_type(EMPTY_FILE);
  mdm1.add_file_hash(file_hash_empty);
  mdm1.set_stats("EMPTY STATS3");
  mdm1.set_tag("EMPTY TAG3");
  mdm1.set_file_size_high(0);
  mdm1.set_file_size_low(0);
  mdm1.set_creation_time(14);
  mdm1.set_last_modified(15);
  mdm1.set_last_access(16);
  mdm1.SerializeToString(&ser_mdm1);

  MetaDataMap recovered_mdm1;
  encrypt::DataMap recovered_dm1;

  //  Add and retrieve data for file
  ASSERT_EQ(0, dah_->AddElement(element_path, ser_mdm1, ser_dm1, "", true)) <<
            "Metadata and DataMap of file was not added to DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path, &ser_mdmrecovered1)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetDataMap(element_path, &ser_dm_recovered1)) <<
            "Didn't retrieve DataMap from DataAtlas";
  EXPECT_TRUE(recovered_mdm1.ParseFromString(ser_mdmrecovered1)) <<
              "MetaDataMap corrupted (cannot be parsed)";
  EXPECT_TRUE(ParseFromString(&recovered_dm1, ser_dm_recovered1)) <<
              "DataMap corrupted (cannot be parsed)";
  ASSERT_EQ(mdm1.display_name(), recovered_mdm1.display_name()) <<
            "Metadata different from original";
  ASSERT_EQ(ser_dm1, ser_dm_recovered1) << "DataMap different from original";

  //  Update DataMap
  encrypt::DataMap dm2;
  dm2.content = file_hash_regular;
  maidsafe::encrypt::ChunkDetails chunk1;
  chunk1.pre_hash = "chunk1";
  chunk1.hash = "enc_chunk1";
//  chunk1.content = "content1";
  chunk1.pre_size = 100;
  chunk1.size = 99;
  dm2.chunks.push_back(chunk1);
  maidsafe::encrypt::ChunkDetails chunk2;
  chunk2.pre_hash = "chunk2";
  chunk2.hash = "enc_chunk2";
//  chunk2.content = "content2";
  chunk2.pre_size = 100;
  chunk2.size = 99;
  dm2.chunks.push_back(chunk2);
  maidsafe::encrypt::ChunkDetails chunk3;
  chunk3.pre_hash = "chunk3";
  chunk3.hash = "enc_chunk3";
//  chunk3.content = "content3";
  chunk3.pre_size = 100;
  chunk3.size = 99;
  dm2.chunks.push_back(chunk3);
  SerializeToString(&dm2, ser_dm2);

  //  Update MetaDataMap
  MetaDataMap mdm2;
  mdm2.set_id(-2);
  mdm2.set_display_name(file_name);
  mdm2.set_type(REGULAR_FILE);
  mdm2.add_file_hash(file_hash_regular);
  mdm2.set_stats("REGULAR STATS3");
  mdm2.set_tag("REGULAR TAG3");
  mdm2.set_file_size_high(1);
  mdm2.set_file_size_low(999);
  mdm2.set_creation_time(999);
  mdm2.set_last_modified(15);
  mdm2.set_last_access(16);
  EXPECT_TRUE(mdm2.SerializeToString(&ser_mdm2)) <<
              "Didn't serialise the MetaDataMap";

  MetaDataMap recovered_mdm2;
  encrypt::DataMap recovered_dm2;

  ASSERT_EQ(0, dah_->ModifyMetaDataMap(element_path, ser_mdm2, ser_dm2)) <<
            "Didn't modify DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path, &ser_mdmrecovered2)) <<
            "Didn't retrieve MetaDataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetDataMap(element_path, &ser_dm_recovered2)) <<
            "Didn't retrieve DataMap from DataAtlas";
  EXPECT_TRUE(recovered_mdm2.ParseFromString(ser_mdmrecovered2)) <<
              "MetaDataMap corrupted (cannot be parsed)";
  EXPECT_TRUE(ParseFromString(&recovered_dm2, ser_dm_recovered2)) <<
              "DataMap corrupted (cannot be parsed)";
  ASSERT_EQ(recovered_mdm1.id(), recovered_mdm2.id()) <<
            "ID has changed in MetaDataMap";
  ASSERT_EQ(mdm1.display_name(), recovered_mdm2.display_name()) <<
            "Display name has changed in MetaDataMap";
  ASSERT_NE(mdm1.type(), recovered_mdm2.type()) <<
            "File type has not changed in MetaDataMap";
  ASSERT_NE(mdm1.file_hash(0), recovered_mdm2.file_hash(0)) <<
            "Hash has not changed in MetaDataMap";
  ASSERT_NE(mdm1.stats(), recovered_mdm2.stats()) <<
            "Stats have not changed in MetaDataMap";
  ASSERT_NE(mdm1.tag(), recovered_mdm2.tag()) <<
            "Tag has not changed in MetaDataMap";
  ASSERT_NE(mdm1.file_size_high(), recovered_mdm2.file_size_high()) <<
            "file_size_high has not changed in MetaDataMap";
  ASSERT_NE(mdm1.file_size_low(), recovered_mdm2.file_size_low()) <<
            "file_size_low has not changed in MetaDataMap";
  ASSERT_EQ(mdm1.creation_time(), recovered_mdm2.creation_time()) <<
            "Creation time has changed in MetaDataMap";
  ASSERT_NE(dm1.content, recovered_dm2.content) <<
            "Hash has not changed in DataMap";
  ASSERT_NE("", recovered_dm2.chunks[0].pre_hash) <<
            "Chunk 1 has not changed in DataMap";
  ASSERT_NE("", recovered_dm2.chunks[1].pre_hash) <<
            "Chunk 2 has not changed in DataMap";
  ASSERT_NE("", recovered_dm2.chunks[2].pre_hash) <<
            "Chunk 3 has not changed in DataMap";
  ASSERT_NE("", recovered_dm2.chunks[0].hash) <<
            "Enc Chunk 1 has not changed in DataMap";
  ASSERT_NE("", recovered_dm2.chunks[1].hash) <<
            "Enc Chunk 2 has not changed in DataMap";
  ASSERT_NE("", recovered_dm2.chunks[2].hash) <<
            "Enc Chunk 3 has not changed in DataMap";
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
