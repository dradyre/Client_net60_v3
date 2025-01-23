using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
    public class Execution
    {
        public string ExecutePowershell(string command)
        {
            //string command = "Get-Pocess"; // PowerShell command to execute

            // Create a new process to run PowerShell
            ProcessStartInfo processStartInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = command,
                RedirectStandardOutput = true,  // Capture standard output
                RedirectStandardError = true,   // Capture error output
                //RedirectStandardInput = true, // Used for dynamic adding commands to the powershell. 
                UseShellExecute = false,       // Do not use shell execution
                CreateNoWindow = true          // Run without creating a new window
            };

            using (Process process = Process.Start(processStartInfo))
            {
                using (System.IO.StreamReader reader = process.StandardOutput)
                using (System.IO.StreamReader errorReader = process.StandardError)
                {
                    string output = reader.ReadToEnd(); // Read the standard output
                    string errors = errorReader.ReadToEnd(); // Read the error output
                    string result;
                    if (!string.IsNullOrEmpty(output))
                    {
                        Console.WriteLine("Output:");
                        Console.WriteLine(output);
                        result = "Output: " + output;
                        return output;
                    }

                    if (!string.IsNullOrEmpty(errors))
                    {
                        Console.WriteLine("Errors:");
                        Console.WriteLine(errors);
                        result = "Error: " + errors;
                        return errors;
                    }
                    return errors;
                }
            }
        }
    }
}
