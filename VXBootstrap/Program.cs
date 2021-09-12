using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;

namespace vxbootstrap
{
    class Program
    {


        static void usage()
        {
            Console.WriteLine("Usage: vxcmd=start vxexe=PATH_TO_EXE vxlibs=PATH_TO_LIBS [vxwd=PATH_TO_WD] [ARGS...]");
            Console.WriteLine("Usage: vxcmd=inject vxlibs=PATH_TO_LIBS vxpid=PID vxtid=TID vxls=LEAVE_SUSPENDED");
            Environment.Exit(-1);
        }


        static void StartProcess(String target_exe, string[] libs_to_sideload, String target_working_directory, List<String> target_args)
        {
            // Get Full Path of Executable as our starting directory.
            String full_path_to_executable = Path.GetFullPath(target_exe);
            String base_path_of_executable = Path.GetDirectoryName(full_path_to_executable);
            String args_str = String.Join(" ", target_args);
            if (target_working_directory == "")
            {
                target_working_directory = base_path_of_executable;
            }

            String cmd = $"\"{full_path_to_executable}\" " + args_str;
            if (!ProcUtils.CreateProcessSuspended(cmd, target_working_directory, out uint target_pid, out uint target_tid))
            {
                Console.WriteLine($"Error Creating Process {Marshal.GetLastWin32Error()}");
                Environment.Exit(-1);
            }
            Console.WriteLine($"Start Process {cmd} In: {target_working_directory} Args: {args_str} Libs: {String.Join(" ", libs_to_sideload)}");
            Console.WriteLine($"Created Process: {target_pid} {target_tid}");

            InjectProcess(target_pid, target_tid, libs_to_sideload, false);
        }

        static void InjectProcess(uint target_process_id, uint target_thread_id, string[] libs_to_sideload, Boolean leave_suspended)
        {
            Boolean is_wow64 = ProcUtils.IsTargetWOW64(target_process_id);
            Console.WriteLine($"Inject Process: wow64: {is_wow64} {target_process_id} {target_thread_id} {String.Join(" ", libs_to_sideload)}  {leave_suspended}");
            Debug.WriteLine($"Inject Process: wow64: {is_wow64} {target_process_id} {target_thread_id} {String.Join(" ", libs_to_sideload)}  {leave_suspended}");
            //    NativeMethods.TerminateProcessByPID(target_process_id);
            IntPtr settings_addr = IntPtr.Zero;
            IntPtr shellcode_addr = IntPtr.Zero;
            if (!ProcUtils.InitializePayloads(target_process_id, is_wow64, libs_to_sideload, out settings_addr, out shellcode_addr))
            {
                Console.WriteLine($"Error Initializing Payloads");
                ProcUtils.TerminateProcessByPID(target_process_id);
                Environment.Exit(-1);
            }


            if (!leave_suspended)
            {
                ProcUtils.InjectQueueUserAPC(target_thread_id, shellcode_addr, settings_addr);
            }
            else
            {
                ProcUtils.InjectRemoteThread(target_process_id, shellcode_addr, settings_addr);
            }

            if (Environment.GetEnvironmentVariable("VXAPP_ID") != null)
            {
                Console.WriteLine($"Registering PID: {target_process_id}");
                try
                {
                    NamedPipeClientStream npcs = new NamedPipeClientStream(".", "VX_" + Environment.GetEnvironmentVariable("VXAPP_ID"), PipeDirection.Out);
                    StreamWriter sw = new StreamWriter(npcs);
                    npcs.Connect(1000);
                    sw.Write($"REGISTER {target_process_id}");
                    sw.Flush();
                    sw.Close();
                }
                catch
                { }
            }

        }

        static void Main(string[] args)
        {
            if (Environment.GetEnvironmentVariable("PDXDBG") == "1")
            {
                NativeMethods.AllocConsole();
            }

            if (args.Count() < 2) { usage(); }
            String cmd = "";
            String target_exe = "";
            string[] libs_to_sideload = null;
            if (Environment.GetEnvironmentVariable("PDXPL") != null)
            {
                libs_to_sideload = Environment.GetEnvironmentVariable("PDXPL").Split(';');
            }
            String target_working_directory = "";
            List<String> target_args = new List<string>();
            uint process_id = 0;
            uint thread_id = 0;
            Boolean leave_suspended = false;

            foreach (var arg in args)
            {
                if (arg.StartsWith("vxcmd="))
                {
                    cmd = arg.Replace("vxcmd=", "");
                }
                else if (arg.StartsWith("vxexe="))
                {
                    target_exe = arg.Replace("vxexe=", "");
                }
                else if (arg.StartsWith("vxlibs="))
                {
                    String slibs = arg.Replace("vxlibs=", "");
                    libs_to_sideload = slibs.Split(';');
                }
                else if (arg.StartsWith("vxwd="))
                {
                    target_working_directory = arg.Replace("vxwd=", "");
                }
                else if (arg.StartsWith("vxpid="))
                {
                    process_id = uint.Parse(arg.Replace("vxpid=", ""));
                }
                else if (arg.StartsWith("vxtid="))
                {
                    thread_id = uint.Parse(arg.Replace("vxtid=", ""));
                }
                else if (arg.StartsWith("vxls="))
                {
                    leave_suspended = Convert.ToBoolean(uint.Parse(arg.Replace("vxls=", "")));
                }
                else
                {
                    target_args.Add(arg);
                }
            }

            switch (cmd)
            {
                case "start":
                    StartProcess(target_exe, libs_to_sideload, target_working_directory, target_args);
                    Environment.Exit(0);
                    break;
                case "inject":
                    InjectProcess(process_id, thread_id, libs_to_sideload, leave_suspended);
                    Environment.Exit(0);
                    break;
                default:
                    usage();
                    break;
            }
        }
    }
}
