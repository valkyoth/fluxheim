using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class FluxheimWindowsConsoleSignalHelper
{
    private const uint CreateNewConsole = 0x00000010;
    private const uint CtrlBreakEvent = 1;
    private const uint Infinite = 0xffffffff;
    private const uint WaitObject0 = 0;
    private const uint WaitTimeout = 258;

    private delegate bool ConsoleCtrlHandler(uint signal);

    private static readonly ConsoleCtrlHandler IgnoreConsoleSignal = _ => true;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int Size;
        public string Reserved;
        public string Desktop;
        public string Title;
        public int X;
        public int Y;
        public int XSize;
        public int YSize;
        public int XCountChars;
        public int YCountChars;
        public int FillAttribute;
        public int Flags;
        public short ShowWindow;
        public short Reserved2Size;
        public IntPtr Reserved2;
        public IntPtr StandardInput;
        public IntPtr StandardOutput;
        public IntPtr StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GenerateConsoleCtrlEvent(uint signal, uint processGroupId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleCtrlHandler(ConsoleCtrlHandler handler, bool add);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static int Run(string binaryArgument, string configArgument)
    {
        string binary = Path.GetFullPath(binaryArgument);
        string config = Path.GetFullPath(configArgument);
        if (!File.Exists(binary) || !File.Exists(config))
        {
            Console.Error.WriteLine("Fluxheim executable or configuration is missing");
            return 2;
        }
        if (binary.IndexOf('"') >= 0 || config.IndexOf('"') >= 0)
        {
            Console.Error.WriteLine("test paths must not contain quotation marks");
            return 2;
        }

        ProcessInformation child = default(ProcessInformation);
        try
        {
            var startup = new StartupInfo { Size = Marshal.SizeOf<StartupInfo>() };
            var commandLine = new StringBuilder(
                "\"" + binary + "\" --config \"" + config + "\"");
            if (!CreateProcessW(
                    binary,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CreateNewConsole,
                    IntPtr.Zero,
                    Path.GetDirectoryName(binary),
                    ref startup,
                    out child))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW failed");
            }
            CloseHandle(child.Thread);
            child.Thread = IntPtr.Zero;

            Console.Out.WriteLine("STARTED=" + child.ProcessId);
            Console.Out.Flush();
            if (!string.Equals(Console.In.ReadLine(), "stop", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("expected stop command on standard input");
            }

            FreeConsole();
            if (!AttachConsole(child.ProcessId))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "AttachConsole failed");
            }
            if (!SetConsoleCtrlHandler(IgnoreConsoleSignal, true))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "SetConsoleCtrlHandler failed");
            }
            if (!GenerateConsoleCtrlEvent(CtrlBreakEvent, 0))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GenerateConsoleCtrlEvent failed");
            }
            if (WaitForSingleObject(child.Process, 15000) != WaitObject0)
            {
                throw new TimeoutException("Fluxheim did not exit after CTRL_BREAK_EVENT");
            }
            if (!GetExitCodeProcess(child.Process, out uint exitCode))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetExitCodeProcess failed");
            }
            return exitCode == 0 ? 0 : 1;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.Message);
            return 1;
        }
        finally
        {
            FreeConsole();
            if (child.Thread != IntPtr.Zero)
            {
                CloseHandle(child.Thread);
            }
            if (child.Process != IntPtr.Zero)
            {
                if (WaitForSingleObject(child.Process, 0) == WaitTimeout)
                {
                    TerminateProcess(child.Process, 1);
                    WaitForSingleObject(child.Process, Infinite);
                }
                CloseHandle(child.Process);
            }
        }
    }
}
