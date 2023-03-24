using JwtManager_Authentication_Token.models;
using JwtManager_Authentication_Token.NewConnection;
using JwtManager_Authentication_Token.Authentication;
using JwtManager_Authentication_Token.EncryptionDecryption;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;

namespace JwtManager_Authentication_Token.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        private static IConfiguration _config;
      

        public ValuesController(IConfiguration config)
        {
            _config = config;

        }
        
        [AllowAnonymous]// it prevents the authentication process to happen at the point of calling this method
        [HttpPost]
        public IActionResult Login([FromBody] UserLogIn userLogIn)
        {
            string ServerName = _config["DatabaseParameters:ServerName"];
            string DataBaseName = _config["DatabaseParameters:DatabaseName"];
            string USerID = _config["DatabaseParameters:USerID"];
            string Password = _config["DatabaseParameters:Password"];
            string decryptionkey = _config["EncryptionKey:key"];
            string Securitykey = _config["jwt:key"];
            string ValidIssuer = _config["jwt:Issuer"];
            string ValidAudience = _config["jwt:Audience"];

            var user = UserAuthentication.Authenticate(userLogIn);
            var connectionstring = connection.GetConnection(ServerName,DataBaseName,USerID,Password,decryptionkey);
            var myConnectionString = _config.GetConnectionString("MyConnectionString");
            

            if (user != null)
            {
                var token = UserAuthentication.GenerateToken(user, Securitykey, ValidIssuer, ValidAudience);
                //var principal = GetPrincipal(token);

                
                

                    return Ok(token);
            }
            
            return NotFound("userDetails is empty");
        }
        [HttpPost("AddUsers")]
        public IActionResult AddUser(UserModel user) 
        {
            string ServerName = _config["DatabaseParameters:ServerName"];
            string DataBaseName = _config["DatabaseParameters:DatabaseName"];
            string USerID = _config["DatabaseParameters:USerID"];
            string Password = _config["DatabaseParameters:Password"];
            string decryptionkey = _config["EncryptionKey:key"];

            var EncryptedPassword = EncryptionDecryption.EncryptionDecryption.Encrypt(decryptionkey, user.Password);
            string connectionString = connection.GetConnection(ServerName, DataBaseName, USerID, Password, decryptionkey);

            using (SqlConnection sqlConnection= new SqlConnection(connectionString)) 
            {
                
                SqlCommand command = new SqlCommand("p_AddUser", sqlConnection);
                command.CommandType = System.Data.CommandType.StoredProcedure;
                command.Parameters.AddWithValue("@Name", user.UserName);
                command.Parameters.AddWithValue("@EmailAddress", user.EmailAddress);
                command.Parameters.AddWithValue("@Role", user.Role);
                command.Parameters.AddWithValue("@Password", EncryptedPassword);

                sqlConnection.Open();
                command.ExecuteNonQuery();
                sqlConnection.Close();


            }

            return Ok("user Sucessfully Added");

        }
       

      
       


    }
}
