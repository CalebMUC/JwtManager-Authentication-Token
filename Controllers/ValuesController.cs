using JwtManager_Authentication_Token.models;
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
            var user = Authenticate(userLogIn);
            

            if (user != null)
            {
                var token = GenerateToken(user);

                //var principal = GetPrincipal(token);

                
                

                    return Ok(token);
            }
            
            return NotFound("userDetails is empty");
        }
        //public IActionResult ValidateToken(string token)
        //{
        //    if (token != null)
        //    {
        //        var simpleprincipal = GetPrincipal(token);

        //        return Ok(simpleprincipal);
        //    }

        //    return NotFound();
        //}

        private string GenerateToken(UserModel user)
        {
            //var securitykey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["jwt:key"]));

            var securitykey = Convert.FromBase64String(_config["jwt:key"]);

            string validAudience = _config["jwt:Audience"];
            string validIssuer = _config["jwt:issuer"];

            var tokenHandler = new JwtSecurityTokenHandler();
            //var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);
            //claims are way to store data about the user

            //Another Method that can be used to generate a token

            var tokenDescriptor = new SecurityTokenDescriptor

            {
                Subject = new ClaimsIdentity(new[]
                 {
               new Claim(ClaimTypes.Name, user.UserName),
                  //new Claim(ClaimTypes.Email, user.EmailAddress),
                  //new Claim(ClaimTypes.Role, user.Role),


                  }),
                Expires = DateTime.UtcNow.AddMinutes(30),
                Audience = validAudience,
                Issuer = validIssuer,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(securitykey), SecurityAlgorithms.HmacSha256)
            //            //Claims = new Dictionary<string, object>
            //            //{
            //            //    { "KeyId", "my-key-identifier" }
            //}
            };
            // End of Method

            //claims
            //    var Claims = new[]
            //{
            //    new Claim(ClaimTypes.NameIdentifier, user.UserName),
            //    new Claim(ClaimTypes.Email, user.EmailAddress),
            //    new Claim(ClaimTypes.Role, user.Role),

            //};
            //define the token object
            //var token = new JwtSecurityToken(_config["jwt:issuer"],
            //    _config["jwt:Audience"],
            //    Claims,
            //    expires: DateTime.Now.AddMinutes(15),
            //    signingCredentials: credentials
            //        );

            var stoken = tokenHandler.CreateToken(tokenDescriptor);
            var token = tokenHandler.WriteToken(stoken);

  


            //var stoken = tokenHandler.WriteToken(token);


            var simplePrincipal = GetPrincipal(token);

            return token;

            
            
            

        }

        private static ClaimsPrincipal GetPrincipal(string token)
        {

            dynamic principal = null;

            string validAudience = _config["jwt:Audience"];

            string validIssuer = _config["jwt:issuer"];

            try
            {
                var tokenhandler = new JwtSecurityTokenHandler();
                var jwtToken = tokenhandler.ReadToken(token) as JwtSecurityToken;

                var symmetrickey =Convert.FromBase64String(_config["jwt:key"])  ;

                TokenValidationParameters tokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    RequireExpirationTime = true,
                    ValidateIssuerSigningKey = true,
                    ValidAudience = validAudience,
                    ValidIssuer = validIssuer,
                    IssuerSigningKey = new SymmetricSecurityKey(symmetrickey)

                };

                SecurityToken securityToken;
                    principal = tokenhandler.ValidateToken(token, tokenValidationParameters, out securityToken);

                return principal;
            }
            catch (SecurityTokenException ste) 
            {
                return principal;
            }


        }
        private UserModel Authenticate(UserLogIn userLogIn)
        {
            var currentuser = UserValues.users.FirstOrDefault(o => o.UserName.ToLower() == userLogIn.UserName.ToLower() &&
             o.Password == userLogIn.Password.ToLower());

            if(currentuser != null)
            {   
                return currentuser;
            }
            return null ;

            
        }
    }
}
