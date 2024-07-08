using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption.Types.ZonePinKey
{
    internal class ZonePinKeyService
    {
        string zpk = "0123456789ABCDEF0123456789ABCDEF"; // Example ZPK (must be 24 bytes for 3DES)
        string pin = "1357";
        public string Encrypt(string data, string key)
        {
            byte[] keyBytes = Get24ByteKey(key);
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);

            var cipher = new PaddedBufferedBlockCipher(new DesEdeEngine(), new Pkcs7Padding());
            cipher.Init(true, new KeyParameter(keyBytes));

            byte[] outputBytes = new byte[cipher.GetOutputSize(dataBytes.Length)];
            int length = cipher.ProcessBytes(dataBytes, 0, dataBytes.Length, outputBytes, 0);
            cipher.DoFinal(outputBytes, length);

            return Convert.ToBase64String(outputBytes);
        }

        public string Decrypt(string encryptedData, string key)
        {
            byte[] keyBytes = Get24ByteKey(key);
            byte[] encryptedBytes = Convert.FromBase64String(encryptedData);

            var cipher = new PaddedBufferedBlockCipher(new DesEdeEngine(), new Pkcs7Padding());
            cipher.Init(false, new KeyParameter(keyBytes));

            byte[] outputBytes = new byte[cipher.GetOutputSize(encryptedBytes.Length)];
            int length = cipher.ProcessBytes(encryptedBytes, 0, encryptedBytes.Length, outputBytes, 0);
            cipher.DoFinal(outputBytes, length);

            return Encoding.UTF8.GetString(outputBytes).TrimEnd('\0');
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
