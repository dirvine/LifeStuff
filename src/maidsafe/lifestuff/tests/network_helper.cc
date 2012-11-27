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
#include <string>

#include "boost/algorithm/string.hpp"
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
#include "maidsafe/private/lifestuff_manager/client_controller.h"

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

std::string GetUserId() {
  char user_name[64] = {0};
  int result(getlogin_r(user_name, sizeof(user_name) - 1));
  if (0 != result)
    return "";
  return std::string(user_name);
}
#endif

int GetNumRunningProcesses(const fs::path& exe_path) {
  auto file_dir = maidsafe::test::CreateTestPath("MaidSafe_Test_Misc");
  fs::path file_path(*file_dir / "process_count.txt");
  std::string exe_name = exe_path.filename().string();
  std::string command(
#ifdef MAIDSAFE_WIN32
      "tasklist /fi \"imagename eq " + exe_name + "\" /nh > " + file_path.string());
#else
      "ps --no-heading -C " + exe_name + " -o stat | grep -v Z | wc -l > " + file_path.string());
#endif
  int result(system(command.c_str()));
  if (result != 0) {
    LOG(kError) << "Failed to execute command that checks processes: " << command;
    return 0;
  }
  try {
#ifdef MAIDSAFE_WIN32
    int num_processes(0);
    char process_info[256];
    std::streamsize number_of_characters(256);
    std::ifstream file(file_path.c_str(), std::ios_base::binary);
    if (!file.good())
      return num_processes;
    while (file.getline(process_info, number_of_characters))
      ++num_processes;
    num_processes -= 1;
#else
    std::string process_string;
    ReadFile(file_path, &process_string);
    boost::trim(process_string);
    int num_processes(boost::lexical_cast<int>(process_string));
#endif
    return num_processes;
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what();
    return 0;
  }
}

bool WaitForProcesses(const fs::path& exe_path, const size_t& count) {
  int i(0);
  for (;;) {
    size_t current(GetNumRunningProcesses(exe_path));
    if (current == count)
      return true;
     if (i >= 10)  // wait 10 seconds
       return false;
    LOG(kWarning) << "Found " << current << " instances of " << exe_path.filename()
                  << ", waiting for " << count << "...";
    ++i;
    Sleep(boost::posix_time::seconds(1));
  }
}

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
  catch(boost::regex_error& e) {
    std::cout << "Error: " << e.what() << std::endl;
  }
  return endpoints;
}

bool StartBootstrappingNodes(std::vector<boost::process::child>& zero_state_processes,
                             std::vector<std::pair<std::string, uint16_t> >& endpoints,
                             int vault_count) {
  // Invoke pd-keys-helper to create 2 zero-state vaults and all keys
  boost::system::error_code error_code;
  bp::pipe anon_pipe = bp::create_pipe();
  biostr::file_descriptor_sink sink(anon_pipe.sink, biostr::close_handle);
  biostr::file_descriptor_source source(anon_pipe.source, biostr::close_handle);
  biostr::stream<biostr::file_descriptor_source> input_stream(source);

  zero_state_processes.push_back(bp::child(
      bp::execute(bp::initializers::run_exe(pd::kKeysHelperExecutable()),
                  bp::initializers::set_cmd_line(
                      ConstructCommandLine(false,
                                           "-cpb -n " +
                                           boost::lexical_cast<std::string>(2 + vault_count))),
                  bp::initializers::set_on_error(error_code),
                  bp::initializers::inherit_env(),
                  bp::initializers::bind_stdout(sink),
                  bp::initializers::bind_stderr(sink))));
  Sleep(boost::posix_time::seconds(1));
  if (error_code) {
    LOG(kError) << "Failed to execute " << pd::kKeysHelperExecutable()
                << " -cpb: " << error_code.message();
    return false;
  }

  // fetch the info of generated bootstrap nodes
  std::string zero_state_log;
  int count(0);
  while (std::getline(input_stream, zero_state_log) && count++ < 100) {
    endpoints = ExtractEndpoints(zero_state_log);
    if (!endpoints.empty())
      break;
  }

  if (endpoints.empty()) {
    LOG(kError) << "Failed to capture bootstrapping nodes";
    return false;
  }

  return true;
}

typedef std::unique_ptr<boost::iostreams::stream<boost::iostreams::file_descriptor_source> >
        InStreamPtr;
bool ReplaceBootstrappingNodesWithVaults(
    const fs::path& test_path,
    std::vector<boost::process::child>& zero_state_processes,
    std::vector<std::pair<boost::process::child, InStreamPtr> >& vault_processes,
    std::vector<std::pair<std::string, uint16_t> >& endpoints) {
  // Start 2 vaults
  boost::system::error_code error_code;
  for (int i(2); i != 4; ++i) {
    LOG(kInfo) << "Starting Vault " << i;
    bp::pipe anon_pipe = bp::create_pipe();
    biostr::file_descriptor_sink sink(anon_pipe.sink, biostr::close_handle);
    biostr::file_descriptor_source source(anon_pipe.source, biostr::close_handle);

    std::string index(boost::lexical_cast<std::string>(i));
    fs::path chunkstore(test_path / (std::string("ChunkStore") + index));
    if (!fs::create_directories(chunkstore, error_code) || error_code) {
      LOG(kError) << "Failed to create chunkstore for vault " << i << ": "
                  << error_code.message();
      return false;
    }
    std::string args("--start --chunk_path " + chunkstore.string());
    args += " --identity_index " + index;
    args += " --log_pd I --log_folder " + (test_path / "logs").string();
    args += " --peer " + endpoints.back().first + ":" +
            boost::lexical_cast<std::string>(endpoints.back().second);
#ifndef MAIDSAFE_WIN32
    args += " --usr_id " + GetUserId();
#endif
    vault_processes.push_back(std::make_pair(
        bp::child(bp::execute(bp::initializers::run_exe(pd::kVaultExecutable()),
                              bp::initializers::set_cmd_line(ConstructCommandLine(true, args)),
                              bp::initializers::set_on_error(error_code),
                              bp::initializers::inherit_env(),
                              bp::initializers::bind_stdout(sink),
                              bp::initializers::bind_stderr(sink))),
        InStreamPtr(new biostr::stream<biostr::file_descriptor_source>(source))));
    if (error_code) {
      LOG(kError) << "Failed to execute " << pd::kVaultExecutable() << " " << args << ": "
                  << error_code.message();
      return false;
    }
    Sleep(boost::posix_time::seconds(3));
  }

  WaitForProcesses(pd::kVaultExecutable(), 2);

  // stop origin bootstrap nodes
  bp::terminate(zero_state_processes[0]);
  if (!WaitForProcesses(pd::kKeysHelperExecutable(), 0)) {
    LOG(kError) << "The bootstrapping process did not terminate correctly.";
    return false;
  }
  Sleep(boost::posix_time::seconds(5));

  return true;
}

bool StartRemaningVaults(
    const fs::path& test_path,
    const std::string& local_ip,
    std::vector<std::pair<boost::process::child, InStreamPtr> >& vault_processes,
    int vault_count) {
  boost::system::error_code error_code;
  for (int i(4); i != vault_count + 2; ++i) {
    LOG(kInfo) << "Starting Vault " << i;
    bp::pipe anon_pipe = bp::create_pipe();
    biostr::file_descriptor_sink sink(anon_pipe.sink, biostr::close_handle);
    biostr::file_descriptor_source source(anon_pipe.source, biostr::close_handle);

    std::string index(boost::lexical_cast<std::string>(i));
    fs::path chunkstore(test_path / (std::string("ChunkStore") + index));
    if (!fs::create_directories(chunkstore, error_code) || error_code) {
      LOG(kError) << "Failed to create chunkstore for vault " << i << ": " << error_code.message();
      return false;
    }

    std::string args("--start --chunk_path " + chunkstore.string());
    args += " --identity_index " + index;
    args += " --peer " + local_ip + ":5483";
    args += " --log_pd I --log_folder " + (test_path / "logs").string();
#ifndef MAIDSAFE_WIN32
    args += " --usr_id " + GetUserId();
#endif
    vault_processes.push_back(std::make_pair(
        bp::child(bp::execute(bp::initializers::run_exe(pd::kVaultExecutable()),
                              bp::initializers::set_cmd_line(ConstructCommandLine(true, args)),
                              bp::initializers::set_on_error(error_code),
                              bp::initializers::inherit_env(),
                              bp::initializers::bind_stdout(sink),
                              bp::initializers::bind_stderr(sink))),
        InStreamPtr(new biostr::stream<biostr::file_descriptor_source>(source))));
    if (error_code) {
      LOG(kError) << "#" << i <<  " - Failed to execute " << pd::kVaultExecutable() << " " << args
                  << ": " << error_code.message();
      return false;
    }
    Sleep(boost::posix_time::seconds(2));
  }

  if (!WaitForProcesses(pd::kVaultExecutable(), vault_count)) {
    LOG(kError) << "Failed waiting for vaults setup";
    return false;
    testing::AssertionFailure();
  }

  Sleep(boost::posix_time::seconds(5));

  return true;
}

bool StoreKeysOfVaultNodes(const std::string& local_ip) {
  // Invoke pd-keys-helper to store all keys
  boost::system::error_code error_code;
  bp::pipe anon_pipe = bp::create_pipe();
  biostr::file_descriptor_sink sink(anon_pipe.sink, biostr::close_handle);
  bp::child store_key_child(
      bp::execute(bp::initializers::run_exe(pd::kKeysHelperExecutable()),
                  bp::initializers::set_cmd_line(
                      ConstructCommandLine(false, "-ls --peer " + local_ip + ":5483")),
                  bp::initializers::set_on_error(error_code),
                  bp::initializers::inherit_env()));
  if (error_code) {
    LOG(kError) << "Failed to execute " << pd::kKeysHelperExecutable() << " -ls: "
                << error_code.message();
    return false;
  }

  auto exit_code = wait_for_exit(store_key_child, error_code);
  if (exit_code) {
    LOG(kError) << "Executing pd_key_helper -ls returned : " << exit_code;
    return false;
  }

  return true;
}

bool StartLifestuffManager(const fs::path& test_path,
                           std::vector<boost::process::child>& lifestuff_manager_processes) {
  // Startup LifeStuffManager
  boost::system::error_code error_code;
  uint16_t port(maidsafe::test::GetRandomPort());
  priv::lifestuff_manager::ClientController::SetTestEnvironmentVariables(port,
                                                                         test_path,
                                                                         pd::kVaultExecutable());
  std::string args("--log_private I");
  args += " --port " + boost::lexical_cast<std::string>(port);
  args += " --root_dir " + (test_path / "lifestuff_manager").string();
  args += " --vault_path " + pd::kVaultExecutable().parent_path().string();
  args += " --log_folder " + (test_path / "logs").string();
  lifestuff_manager_processes.push_back(
      bp::child(bp::execute(bp::initializers::run_exe(priv::kLifeStuffManagerExecutable()),
                            bp::initializers::set_cmd_line(ConstructCommandLine(true, args)),
                            bp::initializers::set_on_error(error_code),
                            bp::initializers::inherit_env())));
  if (error_code) {
    LOG(kError) << "Failed to start LifeStuffManager: " << error_code.message();
    return false;
  }

  if (!WaitForProcesses(priv::kLifeStuffManagerExecutable(), 1)) {
    LOG(kError) << "Failed to start LifeStuffManager after waiting";
    return false;
  }

  return true;
}

}  // unnamed namespace


NetworkHelper::NetworkHelper() : zero_state_processes_(),
                                 vault_processes_(),
                                 lifestuff_manager_processes_() {}

testing::AssertionResult NetworkHelper::StartLocalNetwork(std::shared_ptr<fs::path> test_root,
                                                          int vault_count) {
  if (vault_count > 16 || vault_count < 10)
    return testing::AssertionFailure() << "Can't start " << vault_count
                                       << " vaults: Must be 9 < vault_count < 16";

  std::vector<std::pair<std::string, uint16_t> > endpoints;
  if (!StartBootstrappingNodes(zero_state_processes_, endpoints, vault_count))
    return testing::AssertionFailure() << "Failed to start bootstrap nodes.";

  if (!ReplaceBootstrappingNodesWithVaults(*test_root,
                                           zero_state_processes_,
                                           vault_processes_,
                                           endpoints)) {
    return testing::AssertionFailure() << "Failed to replace bootstrap nodes.";
  }

  std::string local_ip(GetLocalIp().to_string());
  if (!StartRemaningVaults(*test_root, local_ip, vault_processes_, vault_count))
    return testing::AssertionFailure() << "Failed to start remaining vaults.";


  if (!StoreKeysOfVaultNodes(local_ip))
    return testing::AssertionFailure() << "Failed to store vault keys.";

  if (!StartLifestuffManager(*test_root, lifestuff_manager_processes_))
    return testing::AssertionFailure() << "Failed to start lifestuff_mgr.";

  return testing::AssertionSuccess();
}

void NetworkHelper::StopLocalNetwork() {
  LOG(kInfo) << "=============================== Stopping network ===============================";

  for (auto& lifestuff_manager_process : lifestuff_manager_processes_) {
    try {
#ifdef MAIDSAFE_WIN32
      TerminateProcess(lifestuff_manager_process.process_handle(), 0);
      lifestuff_manager_process.discard();
#else
      if (kill(lifestuff_manager_process.pid, SIGTERM) != 0)
        kill(lifestuff_manager_process.pid, SIGKILL);
#endif
    }
    catch(const std::exception& e) {
      LOG(kError) << e.what();
    }
  }
  lifestuff_manager_processes_.clear();
  WaitForProcesses(priv::kLifeStuffManagerExecutable(), 0);

  for (auto& vault_process : vault_processes_) {
    try {
#ifdef MAIDSAFE_WIN32
      bp::terminate(vault_process.first);
#else
      if (kill(vault_process.first.pid, SIGINT) != 0)
        kill(vault_process.first.pid, SIGKILL);
#endif
    }
    catch(const std::exception& e) {
      LOG(kError) << e.what();
    }
  }
  vault_processes_.clear();
  zero_state_processes_.clear();
  WaitForProcesses(pd::kVaultExecutable(), 0);
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
