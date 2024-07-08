using Encryption.Types.ZonePinKey;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        string zpk = "0123456789ABCDEF0123456789ABCDEF";

        // Example PIN
        string pin = "1357";

        var tripleDesService = new TripleDesService();
        var zonePinKeyService = new ZonePinKeyService();

        // Encrypt the PIN
        string encryptedPin = tripleDesService.Encrypt(pin, zpk);
        Console.WriteLine($"This is 3DES Encrypted PIN: {encryptedPin}");

        // Decrypt the PIN
        string decryptedPin = tripleDesService.Decrypt(encryptedPin, zpk);
        Console.WriteLine($"This is 3DES Decrypted PIN: {decryptedPin}");

        // Encrypt the PIN
        string encryptedPinZPK = zonePinKeyService.Encrypt(pin, zpk);
        Console.WriteLine($"This is ZPK Encrypted PIN: {encryptedPinZPK}");
    }


}
