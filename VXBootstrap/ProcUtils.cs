using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace vxbootstrap
{
    class ProcUtils
    {

        static byte[] GetSettingsBytes(NativeMethods.load_library_meta meta, NativeMethods.load_library_content content)
        {
            int size = Marshal.SizeOf(meta);
            foreach (var f in content.filepath)
            {
                size += Marshal.SizeOf(f);
            }
            byte[] arr = new byte[size];

            IntPtr ptr = Marshal.AllocHGlobal(size);

            Marshal.StructureToPtr(meta, ptr, false);
            Marshal.Copy(ptr, arr, 0, Marshal.SizeOf(meta));
            int offset = Marshal.SizeOf(meta);
            foreach (var f in content.filepath)
            {
                Marshal.StructureToPtr(f, ptr, false);
                Marshal.Copy(ptr, arr, offset, Marshal.SizeOf(f));
                offset += Marshal.SizeOf(f);
            }

            Marshal.FreeHGlobal(ptr);
            return arr;
        }

        public static Boolean CreateProcessSuspended(String process_cmd, String exe_base_path, out uint target_pid, out uint target_tid)
        {
            target_pid = 0;
            target_tid = 0;
            NativeMethods.STARTUPINFO si = new NativeMethods.STARTUPINFO();
            NativeMethods.PROCESS_INFORMATION pi = new NativeMethods.PROCESS_INFORMATION();
            if (NativeMethods.CreateProcess(null, process_cmd,
                IntPtr.Zero, IntPtr.Zero, false,
                NativeMethods.ProcessCreationFlags.CREATE_SUSPENDED,
                IntPtr.Zero, exe_base_path, ref si, out pi))
            {
                target_pid = pi.dwProcessId;
                target_tid = pi.dwThreadId;
                return true;
            }

            return false;
        }

        public static void TerminateProcessByPID(uint pid, uint exitcode = 0)
        {
            IntPtr hProcess = NativeMethods.OpenProcess((uint)NativeMethods.ProcessAccessFlags.All, false, (int)pid);
            NativeMethods.TerminateProcess(hProcess, exitcode);
        }

        public static Boolean IsTargetWOW64(uint pid)
        {
            Boolean isWow64 = false;
            NativeMethods.IsWow64Process(NativeMethods.OpenProcess((uint)NativeMethods.ProcessAccessFlags.All, false, (int)pid), out isWow64);
            return isWow64;
        }

        public static IntPtr WriteToProcessByPID(uint target_pid, Byte[] data)
        {
            IntPtr hProcess = NativeMethods.OpenProcess((uint)NativeMethods.ProcessAccessFlags.All, false, (int)target_pid);

            IntPtr addr = NativeMethods.VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, NativeMethods.AllocationType.Commit | NativeMethods.AllocationType.Reserve, NativeMethods.MemoryProtection.ExecuteReadWrite);
            if (addr == IntPtr.Zero)
            {
                Console.WriteLine($"[-] Error allocating memory in process: {Marshal.GetLastWin32Error()}!");

                NativeMethods.CloseHandle(hProcess);
                return addr;
            }
            IntPtr bytes_written;
            if (!NativeMethods.WriteProcessMemory(hProcess, addr, data, data.Length, out bytes_written))
            {
                Console.WriteLine($"[-] Error writing data to process: {Marshal.GetLastWin32Error()}!");
                NativeMethods.CloseHandle(hProcess);
                return addr;
            }

            NativeMethods.CloseHandle(hProcess);
            return addr;
        }

        public static IntPtr WriteStringToProcess(uint target_pid, String dll_path)
        {

            UnicodeEncoding Unicode = new UnicodeEncoding();
            int byteCount = Unicode.GetByteCount(dll_path.ToCharArray(), 0, dll_path.Count());
            Byte[] buffer = new Byte[byteCount];
            int bytesEncodedCount = Unicode.GetBytes(dll_path, 0, dll_path.Count(), buffer, 0);
            return WriteToProcessByPID(target_pid, buffer);
        }
        public static Boolean InitializePayloads(uint target_pid, Boolean is_wow64, string[] libs_to_sideload, out IntPtr settings_addr, out IntPtr shellcode_addr)
        {
            NativeMethods.load_library_meta llm = new NativeMethods.load_library_meta();
            NativeMethods.load_library_content llc = new NativeMethods.load_library_content();
            llm.ldr_load_dll = NativeMethods.GetProcAddress(NativeMethods.GetModuleHandle("ntdll.dll"), "LdrLoadDll");
            llm.num_libs_to_load = (uint)libs_to_sideload.Count();
            llc.filepath = new NativeMethods.UNICODE_STRING[llm.num_libs_to_load];
            foreach (int indx in Enumerable.Range(0, libs_to_sideload.Count()))
            {
                String dll_path = libs_to_sideload[indx];
                if (dll_path.EndsWith(".dlldynamic"))
                {
                    if (is_wow64)
                    {
                        dll_path = dll_path.Replace(".dlldynamic", "32.dll");
                    }
                    else
                    {
                        dll_path = dll_path.Replace(".dlldynamic", "64.dll");
                    }
                }
                llc.filepath[indx].Length = (ushort)(dll_path.Length * 2);
                llc.filepath[indx].MaximumLength = (ushort)((dll_path.Length + 1) * 2);
                llc.filepath[indx].Buffer = WriteStringToProcess(target_pid, dll_path);

            }

            /* -- Original HOST Function Call
            __declspec(noinline) static void __stdcall load_library_worker(load_library_t *s){
	            HMODULE module_handle; unsigned int ret = 0;
	            for(int i = 0; i < s->num_libs_to_load; i++){
		            s->ldr_load_dll(NULL, 0, &s->filepath[i], &module_handle);
	            }
	            return;
            }
            */
            Byte[] shellcode = {
            0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x89, 0x4D, 0x10, 0xC7, 0x45, 0xF8, 0x00,
            0x00, 0x00, 0x00, 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x39, 0x48, 0x8B, 0x45, 0x10,
            0x48, 0x8B, 0x00, 0x8B, 0x55, 0xFC, 0x48, 0x63, 0xD2, 0x48, 0x83, 0xC2, 0x01, 0x48, 0x89, 0xD1,
            0x48, 0xC1, 0xE1, 0x04, 0x48, 0x8B, 0x55, 0x10, 0x48, 0x01, 0xD1, 0x48, 0x8D, 0x55, 0xF0, 0x49,
            0x89, 0xD1, 0x49, 0x89, 0xC8, 0xBA, 0x00, 0x00, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x00, 0x00, 0xFF,
            0xD0, 0x83, 0x45, 0xFC, 0x01, 0x48, 0x8B, 0x45, 0x10, 0x8B, 0x50, 0x08, 0x8B, 0x45, 0xFC, 0x39,
            0xC2, 0x77, 0xB9, 0x90, 0x48, 0x83, 0xC4, 0x30, 0x5D, 0xC3
            };
            if (is_wow64)
            {
                shellcode = new byte[]
                {
                    0x55, 0x89, 0xE5, 0x83, 0xEC, 0x28, 0xC7, 0x45, 0xF0, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x45, 0xF4,
                    0x00, 0x00, 0x00, 0x00, 0xEB, 0x3A, 0x8B, 0x45, 0x08, 0x8B, 0x00, 0x8B, 0x55, 0xF4, 0x8D, 0x0C,
                    0xD5, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x55, 0x08, 0x01, 0xCA, 0x8D, 0x4A, 0x08, 0x8D, 0x55, 0xEC,
                    0x89, 0x54, 0x24, 0x0C, 0x89, 0x4C, 0x24, 0x08, 0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,
                    0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x83, 0xEC, 0x10, 0x83, 0x45, 0xF4, 0x01,
                    0x8B, 0x45, 0x08, 0x8B, 0x50, 0x04, 0x8B, 0x45, 0xF4, 0x39, 0xC2, 0x77, 0xB9, 0x90, 0xC9, 0xC2,
                    0x04, 0x00
                };
            }

            try
            {
                byte[] settings_data = GetSettingsBytes(llm, llc);
                settings_addr = WriteToProcessByPID(target_pid, settings_data);
                shellcode_addr = WriteToProcessByPID(target_pid, shellcode);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                settings_addr = IntPtr.Zero;
                shellcode_addr = IntPtr.Zero;
                return false;
            }


            return true;
        }

        public static Boolean InjectRemoteThread(uint target_pid, IntPtr shellcode_addr, IntPtr settings_addr)
        {
            IntPtr hProcess = NativeMethods.OpenProcess((uint)NativeMethods.ProcessAccessFlags.All, false, (int)target_pid);
            NativeMethods.CreateRemoteThread(hProcess, IntPtr.Zero, 0, shellcode_addr, settings_addr, 0, IntPtr.Zero);
            NativeMethods.CloseHandle(hProcess);
            return true;
        }

        public static Boolean InjectQueueUserAPC(uint target_tid, IntPtr shellcode_addr, IntPtr settings_addr)
        {
            IntPtr thread_handle = NativeMethods.OpenThread(NativeMethods.ThreadAccess.ALL_ACCESS, false, target_tid);
            unsafe
            {
                NativeMethods.QueueUserAPC(shellcode_addr, thread_handle, (UIntPtr)settings_addr.ToPointer());
            }
            IntPtr thread_handle_2 = NativeMethods.OpenThread(NativeMethods.ThreadAccess.ALL_ACCESS, false, target_tid);
            NativeMethods.ResumeThread(thread_handle_2);
            NativeMethods.CloseHandle(thread_handle_2);
            NativeMethods.CloseHandle(thread_handle);
            return true;
        }

    }
}
