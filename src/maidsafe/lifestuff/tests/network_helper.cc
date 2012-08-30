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

#include "boost/filesystem/convenience.hpp"
#include "boost/iostreams/stream.hpp"
#include "boost/lexical_cast.hpp"
#include "boost/process/create_pipe.hpp"
#include "boost/process/execute.hpp"
#include "boost/process/initializers.hpp"
#include "boost/process/pipe.hpp"
#include "boost/process/wait_for_exit.hpp"
#include "boost/regex.hpp"

#include "keys_helper.h"


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

std::vector<std::string> ExtractEndpoints(const std::string& input) {
  std::vector<std::string> endpoints;
  boost::regex expression("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d{1,5})");
  boost::smatch matches;
  try {
    boost::sregex_iterator itr(input.begin(), input.end(), expression);
    boost::sregex_iterator end_itr;
    std::for_each(itr, end_itr, [&](boost::match_results<std::string::const_iterator> result) {
      if (result.size() == 3)
        endpoints.push_back(std::string(result[0].first, result[0].second));
    });
  } 
  catch (boost::regex_error& e) {
    std::cout << "Error: " << e.what() << std::endl;
  }
  return endpoints;
}

}  // unnamed namespace


NetworkHelper::NetworkHelper() : vault_processes_() {}

testing::AssertionResult NetworkHelper::StartLocalNetwork(std::shared_ptr<fs::path> test_root,
                                                          int vault_count) {
  if (vault_count > 10)
    return testing::AssertionFailure() << "Can't start " << vault_count << " vaults. Must be <= 10";

  bp::pipe anon_pipe = bp::create_pipe();

  biostr::file_descriptor_sink sink(anon_pipe.sink, biostr::close_handle);

  boost::system::error_code error_code;
  bp::child zero_state_child(
      bp::execute(bp::initializers::run_exe(pd::kKeysHelperExecutable()),
                  bp::initializers::set_cmd_line(ConstructCommandLine(false, "-cpb")),
                  bp::initializers::set_on_error(error_code),
                  bp::initializers::inherit_env(),
                  bp::initializers::bind_stdout(sink)
  ));

  if (error_code)
    return testing::AssertionFailure() << "Failed to execute " << pd::kKeysHelperExecutable()
                                       << ": " << error_code.message();

  biostr::file_descriptor_source source(anon_pipe.source, biostr::close_handle);
  biostr::stream<biostr::file_descriptor_source> input_stream(source);
  std::string zero_state_log;
  std::vector<std::string> endpoints;
  while (std::getline(input_stream, zero_state_log)) {
    endpoints = ExtractEndpoints(zero_state_log);
    // TODO(Fraser#5#): 2012-08-30 - Avoid hanging here if endpoints is always empty
    if (!endpoints.empty())
      break;
  }

  for (int i(2); i != vault_count + 2; ++i) {
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
    args += " --peer " + endpoints.front();
    vault_processes_.push_back(
        bp::child(bp::execute(bp::initializers::run_exe(pd::kVaultExecutable()),
                              bp::initializers::set_cmd_line(ConstructCommandLine(true, args)),
                              bp::initializers::set_on_error(error_code),
                              bp::initializers::inherit_env())));
  }

  auto exit_code = wait_for_exit(zero_state_child, error_code);
  LOG(kInfo) << pd::kKeysHelperExecutable() << " has completed with exit code " << exit_code;

  return testing::AssertionSuccess();
}

testing::AssertionResult NetworkHelper::StopLocalNetwork() {
  return testing::AssertionSuccess();
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
