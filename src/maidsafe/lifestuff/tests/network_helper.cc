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

#include "maidsafe/lifestuff/tests/network_helper.h"

#include <algorithm>

#include "boost/asio/ip/udp.hpp"
#include "boost/filesystem/convenience.hpp"
#include "boost/lexical_cast.hpp"
#include "boost/process/create_pipe.hpp"
#include "boost/process/execute.hpp"
#include "boost/process/initializers.hpp"
#include "boost/process/pipe.hpp"
#include "boost/process/terminate.hpp"
#include "boost/process/wait_for_exit.hpp"
#include "boost/regex.hpp"

#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/tests/bootstrap_pb.h"

// keys_helper.h is automatically generated and placed in the build directory, hence no full path.
#include "keys_helper.h"  // NOLINT (Fraser)


namespace biostr = boost::iostreams;
namespace bp = boost::process;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

namespace test {

namespace {

#ifdef MAIDSAFE_WIN32
std::wstring ConstructCommandLine(bool is_vault_exe, const std::string& args) {
  // TODO(Fraser#5#): 2012-08-30 - This is copied from private/process_manager.cc.  Move to common.
  std::unique_ptr<wchar_t[]> buffer(new wchar_t[args.size()]);
  size_t num_chars = mbstowcs(buffer.get(), args.c_str(), args.size());
  return is_vault_exe ?
      pd::kVaultExecutable().wstring() + L" " + std::wstring(buffer.get(), num_chars) :
      pd::kKeysHelperExecutable().wstring() + L" " + std::wstring(buffer.get(), num_chars);
}
#else
std::string ConstructCommandLine(bool is_vault_exe, const std::string& args) {
  return is_vault_exe ?
      pd::kVaultExecutable().string() + " " + args:
      pd::kKeysHelperExecutable().string() + " " + args;
}
#endif

std::vector<std::pair<std::string, uint16_t> > ExtractEndpoints(const std::string& input) {
  std::vector<std::pair<std::string, uint16_t>> endpoints;
  boost::regex expression("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d{1,5})");
  try {
    boost::sregex_iterator itr(input.begin(), input.end(), expression);
    boost::sregex_iterator end_itr;
    std::for_each(itr, end_itr, [&](boost::match_results<std::string::const_iterator> result) {
      if (result.size() == 3)
        endpoints.push_back(std::make_pair(std::string(result[1].first, result[1].second),
                                           uint16_t(boost::lexical_cast<uint16_t>(
                                               std::string(result[2].first, result[2].second)))));
    });
  }
  catch (boost::regex_error& e) {
    std::cout << "Error: " << e.what() << std::endl;
  }
  return endpoints;
}

bool WriteBootstrap(const std::vector<std::pair<std::string, uint16_t> >& endpoints) {
  protobuf::Bootstrap protobuf_bootstrap;
  for (size_t i = 0; i < endpoints.size(); ++i) {
    protobuf::Endpoint* endpoint = protobuf_bootstrap.add_bootstrap_contacts();
    endpoint->set_ip(endpoints[i].first);
    endpoint->set_port(endpoints[i].second);
  }
  std::string serialised_bootstrap_nodes;
  if (!protobuf_bootstrap.SerializeToString(&serialised_bootstrap_nodes))
    return false;

  return maidsafe::WriteFile("bootstrap", serialised_bootstrap_nodes);
}

}  // unnamed namespace


NetworkHelper::NetworkHelper() : zero_state_processes_(), vault_processes_() {}

testing::AssertionResult NetworkHelper::StartLocalNetwork(std::shared_ptr<fs::path> test_root,
                                                          int vault_count) {
  if (vault_count > 16)
    return testing::AssertionFailure() << "Can't start " << vault_count << " vaults. Must be <= 16";

  boost::system::error_code error_code;
  fs::remove("bootstrap", error_code);

  // Invoke pd-keys-helper to create 2 zero-state vaults and all keys
  bp::pipe anon_pipe = bp::create_pipe();
  biostr::file_descriptor_sink sink(anon_pipe.sink, biostr::close_handle);
  biostr::file_descriptor_source source(anon_pipe.source, biostr::close_handle);
  biostr::stream<biostr::file_descriptor_source> input_stream(source);

  zero_state_processes_.push_back(bp::child(
      bp::execute(bp::initializers::run_exe(pd::kKeysHelperExecutable()),
                  bp::initializers::set_cmd_line(ConstructCommandLine(false, "-cpb -n " + boost::lexical_cast<std::string>(2 + vault_count))),
                  bp::initializers::set_on_error(error_code),
                  bp::initializers::inherit_env(),
                  bp::initializers::bind_stdout(sink),
                  bp::initializers::bind_stderr(sink))));
  Sleep(boost::posix_time::seconds(5));
  if (error_code)
    return testing::AssertionFailure() << "Failed to execute " << pd::kKeysHelperExecutable()
                                       << " -cpb : " << error_code.message();

  // fetch the info of generated bootstrap nodes
  std::string zero_state_log;
  std::vector<std::pair<std::string, uint16_t>> endpoints;
  while (std::getline(input_stream, zero_state_log)) {
    endpoints = ExtractEndpoints(zero_state_log);
    // TODO(Fraser#5#): 2012-08-30 - Avoid hanging here if endpoints is always empty
    if (!endpoints.empty())
      break;
  }
// std::cout << " \n\n endpoints.size() " << endpoints.size() << std::endl;
// for (auto &it : endpoints)
//   std::cout << it.first << " : " << it.second << std::endl;
// std::cout << "\n\n\n";

  // write the info of bootstrap nodes into the bootstrap file
  if (!WriteBootstrap(endpoints))
    return testing::AssertionFailure() << "Failed to write local bootstrap file.";


  // Start 2 vaults
  for (int i(2); i < 4; ++i) {
    LOG(kInfo) << "Starting Vault " << i;
    anon_pipe = bp::create_pipe();
    sink = biostr::file_descriptor_sink(anon_pipe.sink, biostr::close_handle);
    source = biostr::file_descriptor_source(anon_pipe.source, biostr::close_handle);

    std::random_shuffle(endpoints.begin(), endpoints.end());
    std::string args("--start --chunk_path ");
    std::string index(boost::lexical_cast<std::string>(i));
    fs::path chunkstore(*test_root / (std::string("ChunkStore") + index));
    if (!fs::create_directories(chunkstore, error_code) || error_code) {
      return testing::AssertionFailure() << "Failed to create chunkstore for vault " << i
                                         << ".  Error message: " << error_code.message();
    }
    args += chunkstore.string();
    args += " --identity_index " + index;
//    args += " --peer " + endpoints.front();
    vault_processes_.push_back(std::make_pair(
        bp::child(bp::execute(bp::initializers::run_exe(pd::kVaultExecutable()),
                              bp::initializers::set_cmd_line(ConstructCommandLine(true, args)),
                              bp::initializers::set_on_error(error_code),
                              bp::initializers::inherit_env(),
                              bp::initializers::bind_stdout(sink),
                              bp::initializers::bind_stderr(sink))),
        InStreamPtr(new biostr::stream<biostr::file_descriptor_source>(source))));
    if (error_code)
      return testing::AssertionFailure() << "Failed to execute " << pd::kVaultExecutable() << " "
                                         << args << ": " << error_code.message();
    Sleep(boost::posix_time::seconds(5));
  }

   // stop origin bootstrap nodes
   bp::terminate(zero_state_processes_[0]);
   Sleep(boost::posix_time::seconds(15));

   // erase bootstrap nodes from list
  {
    std::string boot_ip(endpoints[0].first);
    uint16_t boot_port1(endpoints[0].second);
    uint16_t boot_port2(endpoints[1].second);
    std::string serialised_bootstrap_nodes;
    if (!maidsafe::ReadFile("bootstrap", &serialised_bootstrap_nodes))
      return testing::AssertionFailure() << "Could not read bootstrap file.";
    protobuf::Bootstrap protobuf_bootstrap;
    if (!protobuf_bootstrap.ParseFromString(serialised_bootstrap_nodes))
      return testing::AssertionFailure() << "Could not parse bootstrap contacts.";

//     std::cout << "\n\n\n protobuf_bootstrap.bootstrap_contacts_size() : "
//               << protobuf_bootstrap.bootstrap_contacts_size() << std::endl;
//     for (int i(0); i != protobuf_bootstrap.bootstrap_contacts_size(); ++i)
//       std::cout <<protobuf_bootstrap.bootstrap_contacts(i).ip()
//       << " : " << protobuf_bootstrap.bootstrap_contacts(i).port() << std::endl;

    endpoints.clear();
    for (int i(0); i != protobuf_bootstrap.bootstrap_contacts_size(); ++i) {
      if ((boot_port1 != protobuf_bootstrap.bootstrap_contacts(i).port()) &&
          (boot_port2 != protobuf_bootstrap.bootstrap_contacts(i).port()))
        endpoints.push_back(std::make_pair(protobuf_bootstrap.bootstrap_contacts(i).ip(),
                                           protobuf_bootstrap.bootstrap_contacts(i).port()));
    }

    if (!WriteBootstrap(endpoints))
      return testing::AssertionFailure() << "Failed to write updated local bootstrap file.";
  }

// std::cout << " \n\n endpoints.size() " << endpoints.size() << std::endl;
// for (auto &it : endpoints)
//   std::cout << it.first << " : " << it.second << std::endl;
// std::cout << "\n\n\n";

  // Start other vaults
  for (int i(4); i != vault_count + 2; ++i) {
    LOG(kInfo) << "Starting Vault " << i;
    anon_pipe = bp::create_pipe();
    sink = biostr::file_descriptor_sink(anon_pipe.sink, biostr::close_handle);
    source = biostr::file_descriptor_source(anon_pipe.source, biostr::close_handle);

    std::random_shuffle(endpoints.begin(), endpoints.end());
    std::string args("--start --chunk_path ");
    std::string index(boost::lexical_cast<std::string>(i));
    fs::path chunkstore(*test_root / (std::string("ChunkStore") + index));
    if (!fs::create_directories(chunkstore, error_code) || error_code)
      return testing::AssertionFailure() << "Failed to create chunkstore for vault " << i
                                         << ".  Error message: " << error_code.message();

    args += chunkstore.string();
    args += " --identity_index " + index;
//    args += " --peer " + endpoints.front();
    vault_processes_.push_back(std::make_pair(
        bp::child(bp::execute(bp::initializers::run_exe(pd::kVaultExecutable()),
                              bp::initializers::set_cmd_line(ConstructCommandLine(true, args)),
                              bp::initializers::set_on_error(error_code),
                              bp::initializers::inherit_env(),
                              bp::initializers::bind_stdout(sink),
                              bp::initializers::bind_stderr(sink))),
        InStreamPtr(new biostr::stream<biostr::file_descriptor_source>(source))));
    if (error_code)
      return testing::AssertionFailure() << "Failed to execute " << pd::kVaultExecutable() << " "
                                         << args << ": " << error_code.message();
    Sleep(boost::posix_time::seconds(5));
  }

// {
//   std::string serialised_bootstrap_nodes;
//   if (!maidsafe::ReadFile("bootstrap", &serialised_bootstrap_nodes))
//     return testing::AssertionFailure() << "Could not read bootstrap file.";
//   protobuf::Bootstrap protobuf_bootstrap;
//   if (!protobuf_bootstrap.ParseFromString(serialised_bootstrap_nodes))
//     return testing::AssertionFailure() << "Could not parse bootstrap contacts.";
//   std::cout << "\n\n\n protobuf_bootstrap.bootstrap_contacts_size() : "
//             << protobuf_bootstrap.bootstrap_contacts_size() << std::endl;
//
//   for (int i(0); i != protobuf_bootstrap.bootstrap_contacts_size(); ++i)
//     std::cout <<protobuf_bootstrap.bootstrap_contacts(i).ip()
//               << " : " << protobuf_bootstrap.bootstrap_contacts(i).port() << std::endl;
// }


  // Invoke pd-keys-helper to store all keys
  anon_pipe = bp::create_pipe();
  sink = biostr::file_descriptor_sink(anon_pipe.sink, biostr::close_handle);
  bp::child store_key_child(
      bp::execute(bp::initializers::run_exe(pd::kKeysHelperExecutable()),
                  bp::initializers::set_cmd_line(ConstructCommandLine(false, "-ls")),
                  bp::initializers::set_on_error(error_code),
                  bp::initializers::inherit_env()/*,
                  bp::initializers::bind_stdout(sink),
                  bp::initializers::bind_stderr(sink)*/));
  if (error_code)
    return testing::AssertionFailure() << "Failed to execute " << pd::kKeysHelperExecutable()
                                       << " -ls : " << error_code.message();
// std::cout << "current time : " << boost::posix_time::microsec_clock::universal_time() << std::endl;
  auto exit_code = wait_for_exit(store_key_child, error_code);
// std::cout << "current time : " << boost::posix_time::microsec_clock::universal_time() << std::endl;
  if (exit_code)
    return testing::AssertionFailure() << "Executing " << "/home/maidsafe/Work/MyMaidSafe-SuperProject/build/pd-store-keys"
                                       << " -ls returned : " << exit_code ;

  return testing::AssertionSuccess();
}

testing::AssertionResult NetworkHelper::StopLocalNetwork() {
  LOG(kInfo) << "=============================== Stopping network ===============================";
  boost::system::error_code error_code;
  int count(2);
  for (auto& vault_process : vault_processes_) {
    LOG(kInfo) << "=============================== Dumping Vault " << count++
               << "'s ouput ===============================";
    // TODO(Fraser#5#): 2012-08-31 - Don't just terminate, send signal.
    try {
      bp::terminate(vault_process.first);
    }
    catch(const std::exception& e) {
      LOG(kError) << e.what();
    }
    vault_processes_.clear();
    zero_state_processes_.clear();
//  Sleep(boost::posix_time::seconds(2));
/*    auto exit_code = wait_for_exit(vault_process.first, error_code);
    vault_process.second->seekg(0, std::ios::end);
    size_t size(static_cast<size_t>(vault_process.second->tellg()));
    vault_process.second->seekg(0, std::ios::beg);

    std::unique_ptr<char[]> buffer(new char[size]);
    vault_process.second->read(buffer.get(), size);
    LOG(kInfo) << std::string(buffer.get(), size);
    LOG(kInfo) << pd::kKeysHelperExecutable() << " has completed with exit code " << exit_code;
 */ }
//    bp::terminate(zero_state_processes_[0]);
// Sleep(boost::posix_time::seconds(2));
  return testing::AssertionSuccess();
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
