using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;

using HWND = System.IntPtr;
using HANDLE = System.IntPtr;
using HMODULE = System.IntPtr;

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
        const int PROCESS_CREATE_THREAD = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_READ = 0x0010;

        // used for VirtualAllocEx
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 4;

        Process[] getProcess(string processName){
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
            Process[] process = getProcess(args[0]);
        }
    }
}
