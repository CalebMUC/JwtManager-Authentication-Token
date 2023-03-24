using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace JwtManager_Authentication_Token.EncryptionDecryption
{
    public class EncryptionDecryption
    {
        private static IConfiguration _config;

        public EncryptionDecryption(IConfiguration config)
        {
            _config = config;
        }
        public static string Encrypt(string Encryptionkey,string plaintext)
        {
            byte[] iv = new byte[16];
            byte[] EncryptedData ;

            string output = null;
          
            using (Aes aes= Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(Encryptionkey);
                aes.IV = iv;

                ICryptoTransform Encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream stream= new MemoryStream())
                {
                    using (CryptoStream cryptoStream= new CryptoStream(stream,Encryptor,CryptoStreamMode.Write))
                    {
                        using (StreamWriter writer = new StreamWriter(cryptoStream))
                        
                        {
                            writer.Write(plaintext);
                        }

                        EncryptedData = stream.ToArray();


                        
                    }
                }

            }
            return Convert.ToBase64String(EncryptedData);

        }
        public static string Decrypt(string decryptionkey, string cipherText) 
        {
         
            string output = null;

            byte[] iv = new byte[16];
            byte[] decryptedData = Convert.FromBase64String(cipherText);

            using (Aes aes= Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(decryptionkey);
                aes.IV = iv;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream stream= new MemoryStream(decryptedData))
                {
                    using (CryptoStream cryptoStream= new CryptoStream(stream,decryptor, CryptoStreamMode.Read)) 
                    {
                        StreamReader reader = new StreamReader(cryptoStream);
                         
                        output= reader.ReadToEnd();

                        return output;

                    }
                }
            }

        }
    }
}
