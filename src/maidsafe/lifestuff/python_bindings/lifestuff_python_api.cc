/*
* ============================================================================
*
* Copyright [2012] maidsafe.net limited
*
* Description:  Exposing the LifeStuff API as a module to Python.
* Version:      1.0
* Created:      2012-11-28
* Revision:     none
* Compiler:     gcc
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

#include "boost/filesystem/path.hpp"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4100 4127 4244)
#endif
#include "boost/python.hpp"
#include "boost/python/suite/indexing/map_indexing_suite.hpp"
#include "boost/python/suite/indexing/vector_indexing_suite.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/lifestuff_api.h"

/**
 * NOTE
 * - set PYTHONPATH to your build directory, or move the module to where Python finds it
 * - create /tmp/maidsafe_log.ini to enable logging, if desired
 * - in Python, call "from lifestuff_python_api import *"
 * - slots in the LifeStuff constructor are passed via dictionary, e.g. simply {}
 * - paths and NonEmptyStrings are passed via strings
 *
 * TODO
 * - extend slots to actually call Python functions passed via dictionary
 * - handle API functions that take arguments as pointers/references
 */

namespace bpy = boost::python;
namespace ls = maidsafe::lifestuff;

namespace {
struct PathConverter {
  static PyObject* convert(const boost::filesystem::path& path) {
    return bpy::incref(bpy::str(path.c_str()).ptr());
  }
};

struct NonEmptyStringConverter {
  static PyObject* convert(const maidsafe::NonEmptyString& nes) {
    return bpy::incref(bpy::str(nes.string().c_str()).ptr());
  }
};

template<class T1, class T2>
struct PairToTupleConverter {
  static PyObject* convert(const std::pair<T1, T2>& pair) {
    return bpy::incref(bpy::make_tuple(pair.first, pair.second).ptr());
  }
};

// struct SlotsConverter {
//   static PyObject* convert(const maidsafe::lifestuff::Slots& slots) {
//     return bpy::incref(&slots);
//   }
// };

void SetEmptySlots(maidsafe::lifestuff::Slots* pslots) {
  assert(pslots);
  auto three_strings_func = [](const maidsafe::NonEmptyString&,
                               const maidsafe::NonEmptyString&,
                               const maidsafe::NonEmptyString&) {}; // NOLINT
  auto three_plus_one_strings_func = [](const maidsafe::NonEmptyString&,
                                        const maidsafe::NonEmptyString&,
                                        const std::string&,
                                        const maidsafe::NonEmptyString&) {}; // NOLINT
  auto four_strings_func = [](const maidsafe::NonEmptyString&,
                              const maidsafe::NonEmptyString&,
                              const maidsafe::NonEmptyString&,
                              const maidsafe::NonEmptyString&) {}; // NOLINT
  auto five_strings_func = [](const maidsafe::NonEmptyString&,
                              const maidsafe::NonEmptyString&,
                              const maidsafe::NonEmptyString&,
                              const maidsafe::NonEmptyString&,
                              const maidsafe::NonEmptyString&) {}; // NOLINT
  pslots->chat_slot = four_strings_func;
  pslots->file_success_slot = five_strings_func;
  pslots->file_failure_slot = three_strings_func;
  pslots->new_contact_slot = three_plus_one_strings_func;
  pslots->confirmed_contact_slot = three_strings_func;
  pslots->profile_picture_slot = three_strings_func;
  pslots->contact_presence_slot = [](const maidsafe::NonEmptyString&,
                                     const maidsafe::NonEmptyString&,
                                     const maidsafe::NonEmptyString&,
                                     maidsafe::lifestuff::ContactPresence) {}; // NOLINT
  pslots->contact_deletion_slot = three_plus_one_strings_func;
  pslots->lifestuff_card_update_slot = three_strings_func;
  pslots->network_health_slot = [](const int&) {}; // NOLINT
  pslots->immediate_quit_required_slot = [] {}; // NOLINT
  pslots->update_available_slot = [](const maidsafe::NonEmptyString&) {}; // NOLINT
  pslots->operation_progress_slot = [](maidsafe::lifestuff::Operation,
                                       maidsafe::lifestuff::SubTask) {}; // NOLINT
}

struct PathExtractor {
  static void* convertible(PyObject* obj_ptr) {
    return PyString_Check(obj_ptr) ? obj_ptr : nullptr;
  }
  static void construct(PyObject* obj_ptr, bpy::converter::rvalue_from_python_stage1_data* data) {
    const char* value = PyString_AsString(obj_ptr);
    assert(value);
    typedef bpy::converter::rvalue_from_python_storage<boost::filesystem::path> storage_type;
    void* storage = reinterpret_cast<storage_type*>(data)->storage.bytes;
    new(storage) boost::filesystem::path(value);
    data->convertible = storage;
  }
};

struct NonEmptyStringExtractor {
  static void* convertible(PyObject* obj_ptr) {
    return PyString_Check(obj_ptr) ? obj_ptr : nullptr;
  }
  static void construct(PyObject* obj_ptr, bpy::converter::rvalue_from_python_stage1_data* data) {
    const char* value = PyString_AsString(obj_ptr);
    assert(value);
    typedef bpy::converter::rvalue_from_python_storage<maidsafe::NonEmptyString> storage_type;
    void* storage = reinterpret_cast<storage_type*>(data)->storage.bytes;
    new(storage) maidsafe::NonEmptyString(value);
    data->convertible = storage;
  }
};

struct SlotsExtractor {
  static void* convertible(PyObject* obj_ptr) {
    return PyDict_Check(obj_ptr) ? obj_ptr : nullptr;
  }
  static void construct(PyObject*, bpy::converter::rvalue_from_python_stage1_data* data) {
    typedef bpy::converter::rvalue_from_python_storage<maidsafe::lifestuff::Slots> storage_type;
    void* storage = reinterpret_cast<storage_type*>(data)->storage.bytes;
    auto pslots = new(storage) maidsafe::lifestuff::Slots();
    SetEmptySlots(pslots);
    // TODO(Steve) connect slots as per passed in dictionary
    data->convertible = storage;
  }
};

class LifestuffWrapper : public ls::LifeStuff {
 public :
  LifestuffWrapper(PyObject* obj_ptr,
                   const ls::Slots& slot_functions,
                   const fs::path& base_directory)
      : LifeStuff(slot_functions, base_directory),
        self(obj_ptr) {}

  LifestuffWrapper(PyObject* obj_ptr, const ls::LifeStuff& lifestuff)
      : LifeStuff(lifestuff), self(obj_ptr) {}

  ~LifestuffWrapper() {}

  virtual int GetLifestuffCard(const maidsafe::NonEmptyString& my_public_id,
                               const std::string& contact_public_id,
                               ls::SocialInfoMap& social_info) {
    return bpy::call_method<int>(self,
                                 "GetLifestuffCard",
                                 my_public_id,
                                 contact_public_id,
                                 std::ref(social_info));
  }

  virtual int AcceptSentFile(const maidsafe::NonEmptyString& identifier,
                             const fs::path& absolute_path = fs::path(),
                             std::string* file_name = nullptr) {
    return bpy::call_method<int>(self,
                                 "AcceptSentFile",
                                 identifier,
                                 absolute_path,
                                 bpy::ptr(file_name));
  }

  virtual int ReadHiddenFile(const fs::path& absolute_path, std::string* content) {
    return bpy::call_method<int>(self, "ReadHiddenFile", absolute_path, bpy::ptr(content));
  }

  virtual int SearchHiddenFiles(const fs::path& absolute_path,
                                std::vector<std::string>* results) {
    return bpy::call_method<int>(self, "SearchHiddenFiles", absolute_path, bpy::ptr(results));
  }

 private :
  LifestuffWrapper(const LifestuffWrapper&);
  LifestuffWrapper& operator=(const LifestuffWrapper&);
  PyObject* self;
};

#ifdef __GNUC__
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Weffc++"
#endif
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(create_user_overloads, CreateUser, 3, 4)
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(get_contacts_overloads, GetContacts, 1, 2)
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(accept_sent_file_overloads, AcceptSentFile, 1, 3)
#ifdef __GNUC__
#  pragma GCC diagnostic pop
#endif

}  // namespace

BOOST_PYTHON_MODULE(lifestuff_python_api) {
  bpy::enum_<ls::ContactPresence>("ContactPresence")
      .value("kOffline", ls::ContactPresence::kOffline)
      .value("kOnline", ls::ContactPresence::kOnline);

  bpy::enum_<ls::Operation>("Operation")
      .value("kCreateUser", ls::Operation::kCreateUser)
      .value("kLogIn", ls::Operation::kLogIn)
      .value("kLogOut", ls::Operation::kLogOut);

  bpy::enum_<ls::SubTask>("SubTask")
      .value("kInitialiseAnonymousComponents", ls::SubTask::kInitialiseAnonymousComponents)
      .value("kCreateUserCredentials", ls::SubTask::kCreateUserCredentials)
      .value("kCreateVault", ls::SubTask::kCreateVault)
      .value("kInitialiseClientComponents", ls::SubTask::kInitialiseClientComponents)
      .value("kRetrieveUserCredentials", ls::SubTask::kRetrieveUserCredentials)
      .value("kStoreUserCredentials", ls::SubTask::kStoreUserCredentials)
      .value("kWaitForNetworkOperations", ls::SubTask::kWaitForNetworkOperations)
      .value("kCleanUp", ls::SubTask::kCleanUp);

  bpy::enum_<ls::ContactStatus>("ContactStatus")
      .value("kAll", ls::ContactStatus::kAll)
      .value("kUninitialised", ls::ContactStatus::kUninitialised)
      .value("kRequestSent", ls::ContactStatus::kRequestSent)
      .value("kPendingResponse", ls::ContactStatus::kPendingResponse)
      .value("kConfirmed", ls::ContactStatus::kConfirmed)
      .value("kBlocked", ls::ContactStatus::kBlocked);


  maidsafe::log::Logging::Instance().Initialise(0, nullptr);
  LOG(kInfo) << "Initialising LifeStuff Python API";
//   bpy::register_exception_translator<std::exception>([](const std::exception& ex) {
//     PyErr_SetString(PyExc_RuntimeError, ex.what());
//   });
  bpy::to_python_converter<boost::filesystem::path, PathConverter>();
  bpy::to_python_converter<maidsafe::NonEmptyString, NonEmptyStringConverter>();
  bpy::to_python_converter<std::pair<ls::ContactStatus, ls::ContactPresence>,
      PairToTupleConverter<ls::ContactStatus, ls::ContactPresence> >();
//   bpy::to_python_converter<maidsafe::lifestuff::Slots, SlotsConverter>();
  bpy::converter::registry::push_back(&PathExtractor::convertible,
                                      &PathExtractor::construct,
                                      bpy::type_id<boost::filesystem::path>());
  bpy::converter::registry::push_back(&NonEmptyStringExtractor::convertible,
                                      &NonEmptyStringExtractor::construct,
                                      bpy::type_id<maidsafe::NonEmptyString>());
  bpy::converter::registry::push_back(&SlotsExtractor::convertible,
                                      &SlotsExtractor::construct,
                                      bpy::type_id<maidsafe::lifestuff::Slots>());

  bpy::class_<std::map<maidsafe::NonEmptyString,
      std::pair<ls::ContactStatus, ls::ContactPresence> >>("ContactMap")
      .def(bpy::map_indexing_suite<std::map<maidsafe::NonEmptyString,
           std::pair<ls::ContactStatus, ls::ContactPresence>>>());

  bpy::class_<std::vector<maidsafe::NonEmptyString> >("NonEmptyStringVector")
      .def(bpy::vector_indexing_suite<std::vector<maidsafe::NonEmptyString>, true >());

  bpy::class_<std::map<maidsafe::NonEmptyString, std::string> >("SocialInfoMap")
      .def(bpy::map_indexing_suite<std::map<maidsafe::NonEmptyString, std::string> >());

  bpy::class_<ls::LifeStuff, LifestuffWrapper>(
      "LifeStuff", bpy::init<ls::Slots, boost::filesystem::path>())

      // Credential operations
      .def("CreateUser", &LifestuffWrapper::CreateUser, create_user_overloads())
      .def("CreatePublicId", &LifestuffWrapper::CreatePublicId)
      .def("LogIn", &LifestuffWrapper::LogIn)
      .def("LogOut", &LifestuffWrapper::LogOut)
      .def("MountDrive", &LifestuffWrapper::MountDrive)
      .def("UnMountDrive", &LifestuffWrapper::UnMountDrive)
      .def("StartMessagesAndIntros", &LifestuffWrapper::StartMessagesAndIntros)
      .def("StopMessagesAndIntros", &LifestuffWrapper::StopMessagesAndIntros)
      .def("CheckPassword", &LifestuffWrapper::CheckPassword)
      .def("ChangeKeyword", &LifestuffWrapper::ChangeKeyword)
      .def("ChangePin", &LifestuffWrapper::ChangePin)
      .def("ChangePassword", &LifestuffWrapper::ChangePassword)
//       .def("ChangePublicId", &LifestuffWrapper::ChangePublicId)
      .def("LeaveLifeStuff", &LifestuffWrapper::LeaveLifeStuff)

      // Contact operations
      .def("AddContact", &LifestuffWrapper::AddContact)
      .def("ConfirmContact", &LifestuffWrapper::ConfirmContact)
      .def("DeclineContact", &LifestuffWrapper::DeclineContact)
      .def("RemoveContact", &LifestuffWrapper::RemoveContact)
      .def("ChangeProfilePicture", &LifestuffWrapper::ChangeProfilePicture)
      .def("GetOwnProfilePicture", &LifestuffWrapper::GetOwnProfilePicture)
      .def("GetContactProfilePicture", &LifestuffWrapper::GetContactProfilePicture)
      .def("GetLifestuffCard", &LifestuffWrapper::GetLifestuffCard)
      .def("SetLifestuffCard", &LifestuffWrapper::SetLifestuffCard)
      .def("GetContacts", &LifestuffWrapper::GetContacts, get_contacts_overloads())
      .def("PublicIdsList", &LifestuffWrapper::PublicIdsList)

      // Messaging
      .def("SendChatMessage", &LifestuffWrapper::SendChatMessage)
      .def("SendFile", &LifestuffWrapper::SendFile)
      .def("AcceptSentFile", &LifestuffWrapper::AcceptSentFile, accept_sent_file_overloads())
      .def("RejectSentFile", &LifestuffWrapper::RejectSentFile)

      // Filesystem
      .def("ReadHiddenFile", &LifestuffWrapper::ReadHiddenFile)
      .def("WriteHiddenFile", &LifestuffWrapper::WriteHiddenFile)
      .def("DeleteHiddenFile", &LifestuffWrapper::DeleteHiddenFile)
      .def("SearchHiddenFiles", &LifestuffWrapper::SearchHiddenFiles)

      // getters
      .def("state", &LifestuffWrapper::state)
      .def("logged_in_state", &LifestuffWrapper::logged_in_state)
      .def("mount_path", &LifestuffWrapper::mount_path);
}
