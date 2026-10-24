/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2022 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "xenia/kernel/xboxkrnl/xboxkrnl_modules.h"
#include "xenia/base/logging.h"
#include "xenia/kernel/kernel_state.h"
#include "xenia/kernel/user_module.h"
#include "xenia/kernel/util/shim_utils.h"
#include "xenia/kernel/xboxkrnl/xboxkrnl_private.h"
#include "xenia/xbox.h"

namespace xe {
namespace kernel {
namespace xboxkrnl {

// XAM 17559 supplies its current FILETIME after decoding a KDC reply
// (81949FC8 -> import 81A73AA4) and propagates this call's status.
dword_result_t XexSetLastKdcTime_entry(qword_t time) {
  kernel_state()->SetLastKdcTime(time);
  return X_STATUS_SUCCESS;
}
DECLARE_XBOXKRNL_EXPORT1(XexSetLastKdcTime, kModules, kSketchy);

dword_result_t XexCheckExecutablePrivilege_entry(dword_t privilege) {
  // BOOL
  // DWORD Privilege

  // Privilege is bit position in xe_xex2_system_flags enum - so:
  // Privilege=6 -> 0x00000040 -> XEX_SYSTEM_INSECURE_SOCKETS
  uint32_t mask = 1 << privilege;

  auto module = kernel_state()->GetExecutableModule();
  if (!module) {
    return 0;
  }

  uint32_t flags = 0;
  module->GetOptHeader<uint32_t>(XEX_HEADER_SYSTEM_FLAGS, &flags);

  return (flags & mask) > 0;
}
DECLARE_XBOXKRNL_EXPORT1(XexCheckExecutablePrivilege, kModules, kImplemented);

dword_result_t XexGetModuleHandle(std::string module_name,
                                  xe::be<uint32_t>* hmodule_ptr) {
  object_ref<XModule> module;

  if (module_name.empty()) {
    module = kernel_state()->GetExecutableModule();
  } else {
    module = kernel_state()->GetModule(module_name);
  }

  if (!module) {
    *hmodule_ptr = 0;
    return X_ERROR_NOT_FOUND;
  }

  // NOTE: we don't retain the handle for return.
  *hmodule_ptr = module->hmodule_ptr();

  return X_ERROR_SUCCESS;
}

dword_result_t XexGetModuleHandle_entry(lpstring_t module_name,
                                        lpdword_t hmodule_ptr) {
  return XexGetModuleHandle(module_name ? module_name.value() : "",
                            hmodule_ptr);
}
DECLARE_XBOXKRNL_EXPORT1(XexGetModuleHandle, kModules, kImplemented);

dword_result_t XexGetModuleSection_entry(lpvoid_t hmodule, lpstring_t name,
                                         lpdword_t data_ptr,
                                         lpdword_t size_ptr) {
  X_STATUS result = X_STATUS_SUCCESS;

  // The real XAM names a module it loaded by its kernel object handle here
  // (0x01xxxxxx), not by the loader-entry pointer XexLoadImage returns.
  object_ref<XModule> module;
  if ((hmodule.guest_address() & 0xFF000000) == 0x01000000) {
    module = kernel_state()->object_table()->LookupObject<XModule>(
        hmodule.guest_address());
  }
  if (!module) {
    module = XModule::GetFromHModule(kernel_state(), hmodule);
  }
  if (module) {
    uint32_t section_data = 0;
    uint32_t section_size = 0;
    result = module->GetSection(name.value(), &section_data, &section_size);
    XELOGE("SECDIAG XexGetModuleSection({:08X} '{}', '{}') = {:08X}",
           uint32_t(hmodule.guest_address()), module->name(), name.value(),
           uint32_t(result));  // TEMP-DIAG
    if (XSUCCEEDED(result)) {
      *data_ptr = section_data;
      *size_ptr = section_size;
    }
  } else {
    result = X_STATUS_INVALID_HANDLE;
    XELOGE("SECDIAG XexGetModuleSection({:08X}, '{}') invalid handle",
           uint32_t(hmodule.guest_address()), name.value());  // TEMP-DIAG
  }

  return result;
}
DECLARE_XBOXKRNL_EXPORT1(XexGetModuleSection, kModules, kImplemented);

inline const std::map<X_MODULE_FLAGS, std::string> xex_load_image_map = {
    {TITLE_PROCESS, "Title Process"},
    {TITLE_IMPORT, "Title Import"},
    {DEBUGGER, "Debugger Loaded"},
    {LOAD_DLL, "Load DLL"},
    {LOAD_PATCH, "Load Patch"},
    {LOAD_FULL_PATCH, "Load Full Patch"},
    {LOAD_DELTA_PATCH, "Load Delta Patch"},
    {BOUND_PATH, "Load By Bound Path"},
    {SILENT_LOAD, "Load Silently"}};

dword_result_t xeXexLoadImage(
    lpstring_t module_name, dword_t module_flags, dword_t min_version,
    lpdword_t hmodule_ptr,
    const std::function<object_ref<UserModule>()>& load_callback,
    bool isFromMemory) {
  X_STATUS result = X_STATUS_NO_SUCH_FILE;

  std::string summary = "Loading Xex Image:";
  uint32_t unused_flag = module_flags;

  for (const auto& entry : xex_load_image_map) {
    if (module_flags & entry.first) {
      summary += fmt::format(" {},", entry.second);
      unused_flag &= ~entry.first;
    }
  }
  if (unused_flag) {
    summary += fmt::format(" Unk flag: {:08X}", unused_flag);
  }
  XELOGD("{}", summary);

  if (!hmodule_ptr) {
    return X_ERROR_INVALID_PARAMETER;
  }

  uint32_t hmodule = 0;
  auto module = kernel_state()->GetModule(module_name.value());
  if (module) {
    if (isFromMemory) {
      // Existing module found; return error status.
      *hmodule_ptr = hmodule;
      return X_STATUS_OBJECT_NAME_COLLISION;
    } else {
      // Existing module found.
      hmodule = module->hmodule_ptr();
      result = X_STATUS_SUCCESS;
    }
  } else {
    // Not found; attempt to load as a user module.
    auto user_module = load_callback();
    if (user_module) {
      kernel_state()->ApplyTitleUpdate(user_module);
      kernel_state()->FinishLoadingUserModule(user_module);
      // Give up object ownership, this reference will be released by the last
      // XexUnloadImage call
      auto user_module_raw = user_module.release();
      hmodule = user_module_raw->hmodule_ptr();
      result = X_STATUS_SUCCESS;
    }
  }

  // Increment the module's load count.
  if (hmodule) {
    auto ldr_data =
        kernel_memory()->TranslateVirtual<X_LDR_DATA_TABLE_ENTRY*>(hmodule);
    ldr_data->load_count++;
  }

  *hmodule_ptr = hmodule;

  XELOGE("LOADDIAG XexLoadImage('{}', flags {:08X}, minver {:08X}) = {:08X} hmodule {:08X}",
         module_name.value(), uint32_t(module_flags), uint32_t(min_version),
         uint32_t(result), hmodule);  // TEMP-DIAG
  return result;
}

dword_result_t XexLoadImage_entry(lpstring_t module_name, dword_t module_flags,
                                  dword_t min_version, lpdword_t hmodule_ptr) {
  auto load_callback = [module_name] {
    return kernel_state()->LoadUserModule(module_name.value());
  };
  return xeXexLoadImage(module_name, module_flags, min_version, hmodule_ptr,
                        load_callback, false);
}
DECLARE_XBOXKRNL_EXPORT1(XexLoadImage, kModules, kImplemented);

dword_result_t XexLoadImageFromMemory_entry(lpdword_t buffer, dword_t size,
                                            lpstring_t module_name,
                                            dword_t module_flags,
                                            dword_t min_version,
                                            lpdword_t hmodule_ptr) {
  auto load_callback = [module_name, buffer, size] {
    return kernel_state()->LoadUserModuleFromMemory(module_name.value(), buffer,
                                                    size);
  };
  return xeXexLoadImage(module_name, module_flags, min_version, hmodule_ptr,
                        load_callback, true);
}
DECLARE_XBOXKRNL_EXPORT1(XexLoadImageFromMemory, kModules, kImplemented);

// XexLoadExecutable(name, &module, flags, minimum version): the handle pointer
// comes second, unlike XexLoadImage. Passing them in XexLoadImage's order wrote
// the result through the flags value, over the running dashboard.
dword_result_t XexLoadExecutable_entry(lpstring_t module_name,
                                       lpdword_t hmodule_ptr,
                                       dword_t module_flags,
                                       dword_t min_version) {
  // XAM must have retired the old title before mapping another at its base.
  if (kernel_state()->GetExecutableModule()) {
    XELOGE("XexLoadExecutable: old title is still active; refusing {}",
           module_name.value());
    return X_STATUS_UNSUCCESSFUL;
  }
  const uint32_t result = XexLoadImage_entry(
      module_name, module_flags, min_version, hmodule_ptr);
  if (XSUCCEEDED(result)) {
    auto loaded = kernel_state()->GetModule(module_name.value(), true);
    if (!loaded) return X_STATUS_NO_SUCH_FILE;
    kernel_state()->SetExecutableModule(
        retain_object(static_cast<UserModule*>(loaded.get())));
  }
  return result;
}
DECLARE_XBOXKRNL_EXPORT1(XexLoadExecutable, kModules, kSketchy);

void ExTerminateTitleProcess_entry() {
  kernel_state()->TerminateTitleProcess();
}
DECLARE_XBOXKRNL_EXPORT1(ExTerminateTitleProcess, kModules, kSketchy);

dword_result_t XexStartExecutable_entry(dword_t init_routine) {
  return kernel_state()->StartTitleExecutable(init_routine);
}
DECLARE_XBOXKRNL_EXPORT1(XexStartExecutable, kModules, kSketchy);

dword_result_t XexUnloadImage_entry(lpvoid_t hmodule) {
  auto module = XModule::GetFromHModule(kernel_state(), hmodule);
  if (!module) {
    return X_STATUS_INVALID_HANDLE;
  }

  // Can't unload kernel modules from user code.
  if (module->module_type() != XModule::ModuleType::kKernelModule) {
    auto ldr_data = hmodule.as<X_LDR_DATA_TABLE_ENTRY*>();
    if (--ldr_data->load_count == 0) {
      // No more references, free it.
      module->Release();
      kernel_state()->UnloadUserModule(object_ref<UserModule>(
          reinterpret_cast<UserModule*>(module.release())));
    }
  }

  return X_STATUS_SUCCESS;
}
DECLARE_XBOXKRNL_EXPORT1(XexUnloadImage, kModules, kImplemented);

dword_result_t XexGetProcedureAddress_entry(lpvoid_t hmodule, dword_t ordinal,
                                            lpdword_t out_function_ptr) {
  // May be entry point?
  assert_not_zero(ordinal);

  bool is_string_name = (ordinal & 0xFFFF0000) != 0;
  auto string_name =
      reinterpret_cast<const char*>(kernel_memory()->TranslateVirtual(ordinal));

  X_STATUS result = X_STATUS_INVALID_HANDLE;

  object_ref<XModule> module;
  if (!hmodule) {
    module = kernel_state()->GetExecutableModule();
  } else {
    module = XModule::GetFromHModule(kernel_state(), hmodule);
  }
  if (module) {
    uint32_t ptr;
    if (is_string_name) {
      ptr = module->GetProcAddressByName(string_name);
    } else {
      ptr = module->GetProcAddressByOrdinal(ordinal);
    }
    if (ptr) {
      *out_function_ptr = ptr;
      result = X_STATUS_SUCCESS;
    } else {
      if (is_string_name) {
        XELOGW("ERROR: XexGetProcedureAddress export '{}' in '{}' not found!",
               string_name, module->name());
      } else {
        XELOGW(
            "ERROR: XexGetProcedureAddress ordinal {} (0x{:X}) in '{}' not "
            "found!",
            static_cast<uint32_t>(ordinal), static_cast<uint32_t>(ordinal),
            module->name());
      }
      *out_function_ptr = 0;
      result = X_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND;
    }
  }

  return result;
}
DECLARE_XBOXKRNL_EXPORT1(XexGetProcedureAddress, kModules, kImplemented);

void ExRegisterTitleTerminateNotification_entry(
    pointer_t<X_EX_TITLE_TERMINATE_REGISTRATION> reg, dword_t create) {
  if (create) {
    // Adding.
    kernel_state()->RegisterTitleTerminateNotification(
        reg->notification_routine, reg->priority, reg.guest_address());
  } else {
    // Removing.
    kernel_state()->RemoveTitleTerminateNotification(reg->notification_routine);
  }
}
DECLARE_XBOXKRNL_EXPORT1(ExRegisterTitleTerminateNotification, kModules,
                         kImplemented);
// todo: replace magic numbers
dword_result_t XexLoadImageHeaders_entry(pointer_t<X_ANSI_STRING> path,
                                         pointer_t<xex2_header> header,
                                         dword_t buffer_size,
                                         const ppc_context_t& ctx) {
  if (buffer_size < 0x800) {
    return X_STATUS_BUFFER_TOO_SMALL;
  }
  auto current_kernel = ctx->kernel_state;
  auto target_path = util::TranslateAnsiPath(current_kernel->memory(), path);

  vfs::File* vfs_file = nullptr;
  vfs::FileAction file_action;
  X_STATUS result = current_kernel->file_system()->OpenFile(
      nullptr, target_path, vfs::FileDisposition::kOpen,
      vfs::FileAccess::kGenericRead, false, true, &vfs_file, &file_action);

  if (!vfs_file) {
    return result;
  }
  size_t bytes_read = 0;

  X_STATUS result_status = vfs_file->ReadSync(
      std::span<uint8_t>(reinterpret_cast<uint8_t*>(header.host_address()),
                         2048),
      0, &bytes_read);

  if (result_status < 0) {
    vfs_file->Destroy();
    return result_status;
  }

  if (header->magic != 'XEX2') {
    vfs_file->Destroy();
    return X_STATUS_INVALID_IMAGE_FORMAT;
  }
  unsigned int header_size = header->header_size;

  if (header_size < 0x800 || header_size > 0x10000 ||
      (header_size & 0x7FF) != 0) {
    result_status = X_STATUS_INVALID_IMAGE_FORMAT;
  } else if (header_size <= buffer_size) {
    if (header_size <= 0x800) {
      result_status = X_STATUS_SUCCESS;
    } else {
      result_status = vfs_file->ReadSync(
          std::span<uint8_t>(
              reinterpret_cast<uint8_t*>(header.host_address() + 2048),
              header_size - 2048),
          2048, &bytes_read);
      if (result_status >= X_STATUS_SUCCESS) {
        result_status = X_STATUS_SUCCESS;
      }
    }

  } else {
    result_status = X_STATUS_BUFFER_TOO_SMALL;
  }

  // The kernel hands back relocated headers: the security-info field holds a
  // guest pointer, not the file offset. XAM's manifest check reads it as a
  // pointer (lwz 0x10(hdr); addi 8) and hashes the 0x100-byte signature there;
  // with the raw offset it read guest address 0x98 and the init thread died.
  if (result_status == X_STATUS_SUCCESS) {
    const uint32_t security_offset = header->security_offset;
    if (security_offset && security_offset < header_size) {
      header->security_offset = header.guest_address() + security_offset;
    }
  }

  vfs_file->Destroy();
  return result_status;
}
DECLARE_XBOXKRNL_EXPORT1(XexLoadImageHeaders, kModules, kImplemented);

}  // namespace xboxkrnl
}  // namespace kernel
}  // namespace xe

DECLARE_XBOXKRNL_EMPTY_REGISTER_EXPORTS(Module);
