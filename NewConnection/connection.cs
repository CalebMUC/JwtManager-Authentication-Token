using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using JwtManager_Authentication_Token.EncryptionDecryption;

namespace JwtManager_Authentication_Token.NewConnection
{
    public class connection
    {
        private static IConfiguration _config;

        public connection(IConfiguration config)
        {
            _config = config;
        }
        public static string GetConnection(string ServerName,string DatabaseName, string UserID, string Password, string decryptionkey)
        {
           

            string decryptedUserID = EncryptionDecryption.EncryptionDecryption.Decrypt(decryptionkey, UserID);
            string decryptedPassword = EncryptionDecryption.EncryptionDecryption.Decrypt(decryptionkey, Password);


            string connectiostring = AddConnectionString(ServerName, DatabaseName, decryptedUserID, decryptedPassword);

            return connectiostring;


        }


        public static string AddConnectionString(string ServerName, string DataBaseName, string UserID, string Password)
        {
            string myConnectionString = "Data Source= " + ServerName + "; Initial Catalog= " + DataBaseName + "; User ID=" + UserID + "; Password=" + Password + " ";

            return myConnectionString;
        }
    }
}
