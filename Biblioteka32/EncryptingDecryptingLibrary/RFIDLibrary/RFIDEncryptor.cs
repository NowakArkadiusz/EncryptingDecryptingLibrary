using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RFIDLibrary
{
    // Definicja interfejsu dla klasy RFIDEncryptor
    [ComVisible(true)]
    [Guid("4D62DDCE-C3A4-4AB8-B42E-D33FF362B1D2")] 
    public interface IRFIDEncryptor
    {
        string EncryptData(string uid, string dataToEncrypt, string keyPath);
        string DecryptData(string uid, string encryptedData, string keyPath);
    }

    // Implementacja klasy RFIDEncryptor
    [ComVisible(true)]
    [Guid("448A544F-F2A5-4296-B662-05C3DC2ED912")] 
    [ClassInterface(ClassInterfaceType.None)]
    public class RFIDEncryptor : IRFIDEncryptor
    {
        public string EncryptData(string uid, string dataToEncrypt, string keyPath)
        {
            string keyHex = File.ReadAllText(keyPath);
            byte[] key = HexStringToByteArray(keyHex);
            byte[] uidBytes = StringToByteArray(uid);
            byte[] dataBytes = StringToByteArray(dataToEncrypt);

            byte[] xorKey = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                xorKey[i] = (byte)(uidBytes[i] ^ key[i]);
            }

            using (Aes aes = Aes.Create())
            {
                aes.Key = xorKey;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.Zeros;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                byte[] encrypted = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);

                return BitConverter.ToString(encrypted).Replace("-", "");
            }
        }

        public string DecryptData(string uid, string encryptedData, string keyPath)
        {
            string keyHex = File.ReadAllText(keyPath);
            byte[] key = HexStringToByteArray(keyHex);
            byte[] uidBytes = StringToByteArray(uid);
            byte[] encryptedBytes = StringToByteArray(encryptedData);

            byte[] xorKey = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                xorKey[i] = (byte)(uidBytes[i] ^ key[i]);
            }

            using (Aes aes = Aes.Create())
            {
                aes.Key = xorKey;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.Zeros;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                byte[] decrypted = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

                return BitConverter.ToString(decrypted).Replace("-", "");
            }
        }

        private static byte[] StringToByteArray(string hex)
        {
            int length = hex.Length;
            byte[] bytes = new byte[length / 2];
            for (int i = 0; i < length; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            int length = hex.Length;
            byte[] bytes = new byte[length / 2];
            for (int i = 0; i < length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }
    }
}
