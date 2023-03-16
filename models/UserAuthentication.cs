using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JwtManager_Authentication_Token.models
{
    public class UserAuthentication
    {
        private static IConfiguration _config;

        public UserAuthentication(IConfiguration config)
        {
            _config = config;
        }

       



        public static string GenerateToken(UserModel user)
        {
            //var securitykey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["jwt:key"]));

            var securitykey = Convert.FromBase64String(_config["jwt:key"]);

            string validAudience = _config["jwt:Audience"];
            string validIssuer = _config["jwt:issuer"];

            var tokenHandler = new JwtSecurityTokenHandler();
            //var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);
            //claims are way to store data about the user
            var tokenDescriptor = new SecurityTokenDescriptor

            {
                Subject = new ClaimsIdentity(new[]
                 {
                new Claim(ClaimTypes.Name, user.UserName),
                  }),
                Expires = DateTime.UtcNow.AddMinutes(30),
                Audience = validAudience,
                Issuer = validIssuer,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(securitykey), SecurityAlgorithms.HmacSha256)
                //Claims = new Dictionary<string, object>
                //{
                //    { "KeyId", "my-key-identifier" }
                //}
            };

            //var Claims = new[]
            //{
            //    new Claim(ClaimTypes.NameIdentifier, user.UserName),
            //    new Claim(ClaimTypes.Email, user.EmailAddress),
            //    new Claim(ClaimTypes.Role, user.Role),

            //};
            ////define the token object
            //var token = new JwtSecurityToken(_config["jwt:issuer"],
            //    _config["jwt:Audience"],
            //    Claims,
            //    expires: DateTime.Now.AddMinutes(15),
            //    signingCredentials: credentials
            //        );

            var stoken = tokenHandler.CreateToken(tokenDescriptor);
            var token = tokenHandler.WriteToken(stoken);

            var simplePrincipal = GetPrincipal(token);

            return token;





        }
        public static ClaimsPrincipal GetPrincipal(string token)
        {

            dynamic principal = null;

            

            string validIssuer = _config["jwt:issuer"];

            string validAudience = _config["jwt:Audience"];

            try
            {
                var tokenhandler = new JwtSecurityTokenHandler();
                var jwtToken = tokenhandler.ReadToken(token) as JwtSecurityToken;

                var symmetrickey = Convert.FromBase64String(_config["jwt:key"]);

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
        public static UserModel Authenticate(UserLogIn userLogIn)
        {
            var currentuser = UserValues.users.FirstOrDefault(o => o.UserName.ToLower() == userLogIn.UserName.ToLower() &&
             o.Password == userLogIn.Password.ToLower());

            if (currentuser != null)
            {
                return currentuser;
            }
            return null;


        }
    }
}
