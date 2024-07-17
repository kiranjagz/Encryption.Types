﻿using System;
using System.Security.Cryptography;
using System.Text;

class PinBlockConversion
{
    public static void Main()
    {
        string incomingPinBlock = "63E831C7FFC8D618";
        string incomingZPK = "CA97081C9AE88BE0251AFF0AA5654A14";



        //string convertedPinBlock = ConvertPinBlock(decryptedPinBlock, "ISO-0");
        var convertedPinBlock = "042278FFFFFFFFFF";
        Console.WriteLine("Outgoing Clear PINBlock: " + convertedPinBlock);

        string outgoingZPK = incomingZPK; // In this example, we're using the same ZPK for simplicity
        string encryptedPinBlock = EncryptPinBlock(convertedPinBlock, outgoingZPK);
        Console.WriteLine("Outgoing PINBlock: " + encryptedPinBlock);


        string decryptedPinBlock = DecryptPinBlock(encryptedPinBlock, incomingZPK);
        Console.WriteLine("Incoming Clear PINBlock: " + decryptedPinBlock);
    }

    private static string DecryptPinBlock(string pinBlock, string zpk)
    {
        byte[] pinBlockBytes = StringToByteArray(pinBlock);
        byte[] zpkBytes = StringToByteArray(zpk);

        using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
        {
            tdes.Key = zpkBytes;
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.None;

            ICryptoTransform decryptor = tdes.CreateDecryptor();
            byte[] result = decryptor.TransformFinalBlock(pinBlockBytes, 0, pinBlockBytes.Length);

            return ByteArrayToString(result);
        }
    }

    private static string EncryptPinBlock(string pinBlock, string zpk)
    {
        byte[] pinBlockBytes = StringToByteArray(pinBlock);
        byte[] zpkBytes = StringToByteArray(zpk);

        using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
        {
            tdes.Key = zpkBytes;
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.None;

            ICryptoTransform encryptor = tdes.CreateEncryptor();
            byte[] result = encryptor.TransformFinalBlock(pinBlockBytes, 0, pinBlockBytes.Length);

            return ByteArrayToString(result);
        }
    }

    private static string ConvertPinBlock(string pinBlock, string format)
    {
        // Implement conversion logic here if necessary
        return pinBlock;
    }

    private static byte[] StringToByteArray(string hex)
    {
        int numberChars = hex.Length;
        byte[] bytes = new byte[numberChars / 2];
        for (int i = 0; i < numberChars; i += 2)
        {
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }
        return bytes;
    }

    private static string ByteArrayToString(byte[] bytes)
    {
        StringBuilder hex = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
        {
            hex.AppendFormat("{0:x2}", b);
        }
        return hex.ToString().ToUpper();
    }
}
