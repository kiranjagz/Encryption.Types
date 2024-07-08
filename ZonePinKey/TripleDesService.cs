using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Encryption.Types.ZonePinKey
{
    public class TripleDesService
    {
        public string Encrypt(string data, string key)
        {
            using (var tripleDes = new TripleDESCryptoServiceProvider())
            {
                tripleDes.Key = Get24ByteKey(key);
                tripleDes.Mode = CipherMode.ECB;
                tripleDes.Padding = PaddingMode.PKCS7;

                var encryptor = tripleDes.CreateEncryptor();
                byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                byte[] encryptedBytes = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);

                return Convert.ToBase64String(encryptedBytes);
            }
        }

        public string Decrypt(string encryptedData, string key)
        {
            using (var tripleDes = new TripleDESCryptoServiceProvider())
            {
                tripleDes.Key = Get24ByteKey(key);
                tripleDes.Mode = CipherMode.ECB;
                tripleDes.Padding = PaddingMode.PKCS7;

                var decryptor = tripleDes.CreateDecryptor();
                byte[] encryptedBytes = Convert.FromBase64String(encryptedData);
                byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }

        private byte[] Get24ByteKey(string key)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            if (keyBytes.Length == 24)
            {
                return keyBytes;
            }
            else if (keyBytes.Length < 24)
            {
                byte[] paddedKeyBytes = new byte[24];
                Array.Copy(keyBytes, paddedKeyBytes, keyBytes.Length);
                return paddedKeyBytes;
            }
            else
            {
                byte[] truncatedKeyBytes = new byte[24];
                Array.Copy(keyBytes, truncatedKeyBytes, 24);
                return truncatedKeyBytes;
            }
        }
    }
}
