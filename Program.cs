using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        string zpk = "0123456789ABCDEF0123456789ABCDEF";
        string newZpk = "0123456789ABCDEF0123456789ABCDEG";
        List<string> list = [zpk, newZpk];


        // Example PIN
        string pin = "1357";

        foreach (var item in list)
        {
            // Encrypt the PIN
            string encryptedPin = Encrypt(pin, item);
            Console.WriteLine($"Encrypted PIN: {encryptedPin}");

            // Decrypt the PIN
            string decryptedPin = Decrypt(encryptedPin, item);
            Console.WriteLine($"Decrypted PIN: {decryptedPin}");
        }
    }

    public static string Encrypt(string data, string key)
    {
        using (var aes = new AesManaged())
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            Array.Resize(ref keyBytes, aes.KeySize / 8); // Adjust the key size
            aes.Key = keyBytes;

            aes.GenerateIV();
            var iv = aes.IV;
            var encryptor = aes.CreateEncryptor(aes.Key, iv);

            using (var ms = new System.IO.MemoryStream())
            {
                ms.Write(iv, 0, iv.Length);
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (var sw = new System.IO.StreamWriter(cs))
                    {
                        sw.Write(data);
                    }
                }
                return Convert.ToBase64String(ms.ToArray());
            }
        }
    }

    public static string Decrypt(string encryptedData, string key)
    {
        byte[] fullCipher = Convert.FromBase64String(encryptedData);

        using (var aes = new AesManaged())
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            Array.Resize(ref keyBytes, aes.KeySize / 8); // Adjust the key size
            aes.Key = keyBytes;

            byte[] iv = new byte[aes.BlockSize / 8];
            byte[] cipher = new byte[fullCipher.Length - iv.Length];

            Array.Copy(fullCipher, iv, iv.Length);
            Array.Copy(fullCipher, iv.Length, cipher, 0, cipher.Length);

            var decryptor = aes.CreateDecryptor(aes.Key, iv);

            using (var ms = new System.IO.MemoryStream(cipher))
            {
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    using (var sr = new System.IO.StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
        }
    }
}
