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
 * - implement converter for std::vector<NonEmptyString> to Python object (as in PublicIdsList)
 * - implement converter for Python object to SocialInfoMap (as in Get/SetLifestuffCard)
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

void SetEmptySlots(maidsafe::lifestuff::Slots* pslots, std::vector<PyObject*>& v) {
  assert(pslots);
  pslots->chat_slot = [v](
      const maidsafe::NonEmptyString& s1, const maidsafe::NonEmptyString& s2,
      const maidsafe::NonEmptyString& s3, const maidsafe::NonEmptyString& s4) {
        PyObject_CallObject(v[0],
            (NonEmptyStringConverter::convert(s1), NonEmptyStringConverter::convert(s2),
             NonEmptyStringConverter::convert(s3), NonEmptyStringConverter::convert(s4)));
      };
  pslots->file_success_slot = [v](
      const maidsafe::NonEmptyString& s1, const maidsafe::NonEmptyString& s2,
      const maidsafe::NonEmptyString& s3, const maidsafe::NonEmptyString& s4,
      const maidsafe::NonEmptyString& s5) {
        PyObject_CallObject(v[1],
            (NonEmptyStringConverter::convert(s1), NonEmptyStringConverter::convert(s2),
             NonEmptyStringConverter::convert(s3), NonEmptyStringConverter::convert(s4),
             NonEmptyStringConverter::convert(s5)));
      };
  pslots->file_failure_slot = [v](
      const maidsafe::NonEmptyString& s1, const maidsafe::NonEmptyString& s2,
      const maidsafe::NonEmptyString& s3) {
        PyObject_CallObject(v[2],
            (NonEmptyStringConverter::convert(s1), NonEmptyStringConverter::convert(s2),
             NonEmptyStringConverter::convert(s3)));
      };
  pslots->new_contact_slot = [v](
      const maidsafe::NonEmptyString& s1, const maidsafe::NonEmptyString& s2,
      const std::string& s3, const maidsafe::NonEmptyString& s4) {
        PyObject_CallObject(v[3],
            (NonEmptyStringConverter::convert(s1), NonEmptyStringConverter::convert(s2),
             boost::python::converter::arg_to_python<std::string>(s3),
             NonEmptyStringConverter::convert(s4)));
      };
  pslots->confirmed_contact_slot = [v](
      const maidsafe::NonEmptyString& s1, const maidsafe::NonEmptyString& s2,
      const maidsafe::NonEmptyString& s3) {
        PyObject_CallObject(v[4],
            (NonEmptyStringConverter::convert(s1), NonEmptyStringConverter::convert(s2),
             NonEmptyStringConverter::convert(s3)));
      };
  pslots->profile_picture_slot = [v](
      const maidsafe::NonEmptyString& s1, const maidsafe::NonEmptyString& s2,
      const maidsafe::NonEmptyString& s3) {
        PyObject_CallObject(v[5],
            (NonEmptyStringConverter::convert(s1), NonEmptyStringConverter::convert(s2),
             NonEmptyStringConverter::convert(s3)));
      };
  pslots->contact_presence_slot = [v](
      const maidsafe::NonEmptyString& s1, const maidsafe::NonEmptyString& s2,
      const maidsafe::NonEmptyString& s3, maidsafe::lifestuff::ContactPresence /*presence*/) {
        PyObject_CallObject(v[6],
            (NonEmptyStringConverter::convert(s1), NonEmptyStringConverter::convert(s2),
             NonEmptyStringConverter::convert(s3)));
      };
  pslots->contact_deletion_slot = [v](
      const maidsafe::NonEmptyString& s1, const maidsafe::NonEmptyString& s2,
      const std::string& s3, const maidsafe::NonEmptyString& s4) {
        PyObject_CallObject(v[7],
            (NonEmptyStringConverter::convert(s1), NonEmptyStringConverter::convert(s2),
             boost::python::converter::arg_to_python<std::string>(s3),
             NonEmptyStringConverter::convert(s4)));
      };
  pslots->lifestuff_card_update_slot = [v](
      const maidsafe::NonEmptyString& s1, const maidsafe::NonEmptyString& s2,
      const maidsafe::NonEmptyString& s3) {
        PyObject_CallObject(v[8],
            (NonEmptyStringConverter::convert(s1), NonEmptyStringConverter::convert(s2),
             NonEmptyStringConverter::convert(s3)));
      };
  pslots->network_health_slot = [v](const int& i) {
      boost::python::call<void>(v[9], i); };
  pslots->immediate_quit_required_slot = [v]() { boost::python::call<void>(v[10]);; };
  pslots->update_available_slot =  [v](const maidsafe::NonEmptyString& s1) {
        PyObject_CallObject(v[11], NonEmptyStringConverter::convert(s1));
      };
  pslots->operation_progress_slot = [v](maidsafe::lifestuff::Operation /*operation*/,
                                        maidsafe::lifestuff::SubTask /*sub_task*/) {
        boost::python::call<void>(v[12], "O_P get called");
      };
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
    return PyList_Check(obj_ptr) ? obj_ptr : nullptr;
  }
  static void construct(PyObject* obj_ptr, bpy::converter::rvalue_from_python_stage1_data* data) {
    typedef bpy::converter::rvalue_from_python_storage<maidsafe::lifestuff::Slots> storage_type;
    void* storage = reinterpret_cast<storage_type*>(data)->storage.bytes;
    auto pslots = new(storage) maidsafe::lifestuff::Slots();

    using namespace boost::python;
    list l(handle<>(borrowed(obj_ptr)));
    // Grab pointer to memory into which to construct the new std::vector<T>
    void* l_storage =
        ((boost::python::converter::rvalue_from_python_storage<std::vector<PyObject*> >*)
        data)->storage.bytes;
    // in-place construct the new std::vector<T> using the character data
    // extracted from the python object
    std::vector<PyObject*>& v = *(new (l_storage) std::vector<PyObject*>());
    // populate the vector from list contains !!!
    int le = len(l);
    v.resize(le);
    for(int i = 0;i < le; ++i)
      v[i] = extract<PyObject*>(l[i]);

    SetEmptySlots(pslots, v);
    data->convertible = storage;
  }
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

  bpy::class_<ls::LifeStuff>(
      "LifeStuff", bpy::init<ls::Slots, boost::filesystem::path>())

      // Credential operations
      .def("CreateUser", &ls::LifeStuff::CreateUser, create_user_overloads())
      .def("CreatePublicId", &ls::LifeStuff::CreatePublicId)
      .def("LogIn", &ls::LifeStuff::LogIn)
      .def("LogOut", &ls::LifeStuff::LogOut)
      .def("MountDrive", &ls::LifeStuff::MountDrive)
      .def("UnMountDrive", &ls::LifeStuff::UnMountDrive)
      .def("StartMessagesAndIntros", &ls::LifeStuff::StartMessagesAndIntros)
      .def("StopMessagesAndIntros", &ls::LifeStuff::StopMessagesAndIntros)
      .def("CheckPassword", &ls::LifeStuff::CheckPassword)
      .def("ChangeKeyword", &ls::LifeStuff::ChangeKeyword)
      .def("ChangePin", &ls::LifeStuff::ChangePin)
      .def("ChangePassword", &ls::LifeStuff::ChangePassword)
//       .def("ChangePublicId", &ls::LifeStuff::ChangePublicId)
      .def("LeaveLifeStuff", &ls::LifeStuff::LeaveLifeStuff)

      // Contact operations
      .def("AddContact", &ls::LifeStuff::AddContact)
      .def("ConfirmContact", &ls::LifeStuff::ConfirmContact)
      .def("DeclineContact", &ls::LifeStuff::DeclineContact)
      .def("RemoveContact", &ls::LifeStuff::RemoveContact)
      .def("ChangeProfilePicture", &ls::LifeStuff::ChangeProfilePicture)
      .def("GetOwnProfilePicture", &ls::LifeStuff::GetOwnProfilePicture)
      .def("GetContactProfilePicture", &ls::LifeStuff::GetContactProfilePicture)
      .def("GetLifestuffCard", &ls::LifeStuff::GetLifestuffCard)
      .def("SetLifestuffCard", &ls::LifeStuff::SetLifestuffCard)
      .def("GetContacts", &ls::LifeStuff::GetContacts, get_contacts_overloads())
      .def("PublicIdsList", &ls::LifeStuff::PublicIdsList)

      // Messaging
      .def("SendChatMessage", &ls::LifeStuff::SendChatMessage)
      .def("SendFile", &ls::LifeStuff::SendFile)
      .def("AcceptSentFile", &ls::LifeStuff::AcceptSentFile, accept_sent_file_overloads())
      .def("RejectSentFile", &ls::LifeStuff::RejectSentFile)

      // Filesystem
      .def("ReadHiddenFile", &ls::LifeStuff::ReadHiddenFile)
      .def("WriteHiddenFile", &ls::LifeStuff::WriteHiddenFile)
      .def("DeleteHiddenFile", &ls::LifeStuff::DeleteHiddenFile)
      .def("SearchHiddenFiles", &ls::LifeStuff::SearchHiddenFiles)

      // getters
      .def("state", &ls::LifeStuff::state)
      .def("logged_in_state", &ls::LifeStuff::logged_in_state)
      .def("mount_path", &ls::LifeStuff::mount_path);
}
