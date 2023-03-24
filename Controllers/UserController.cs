using JwtManager_Authentication_Token.models;
using JwtManager_Authentication_Token.Controllers;
using JwtManager_Authentication_Token.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace JwtManager_Authentication_Token.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private IConfiguration _config;

        public UserController(IConfiguration config)
        {
            _config = config;
        }


        [HttpGet("Admins")]

        [Authorize(Roles = "adminstrator")]
        
        public IActionResult AdminsEndpoint()
        {
            
            var currentuser = GetCurrentUser();

            return Ok($"hi {currentuser.UserName} you are an {currentuser.Role} ");
        }
        [HttpGet("Users")]
        [Authorize(Roles = "user")]
        public IActionResult SellersEndpoint()
        {
            var currentuser = GetCurrentUser();

            return Ok($"hi {currentuser.UserName} you are {currentuser.Role} ");
        }
        [HttpGet("publice")]
        public IActionResult publice()
        {
            return Ok("you are on public property");
        }
        private UserModel GetCurrentUser()
        {
            //UserLogIn userLogIn = new UserLogIn();

            //var user = UserAuthentication.Authenticate(userLogIn);";

            string Securitykey = _config["jwt:key"];
            string ValidIssuer = _config["jwt:Issuer"];
            string ValidAudience = _config["jwt:Audience"];

            var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IkNhbGViIE11Y2hpcmkiLCJlbWFpbCI6Im11Y2hpcmljYWxlYjA1QGdtYWlsLmNvbSIsInJvbGUiOiJhZG1pbnN0cmF0b3IiLCJuYmYiOjE2NzkzMTQyNzksImV4cCI6MTY3OTMxNjA3OSwiaWF0IjoxNjc5MzE0Mjc5LCJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo0NDMzNC8iLCJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo0NDMzNC8ifQ.b4uAEpZZgkbFrEQoY3hwExZJbYROkKBjpGKT_2fRXuY";
            var simplePrincipal = UserAuthentication.GetPrincipal(token,Securitykey,ValidIssuer,ValidAudience);



            var identity = simplePrincipal.Identity as ClaimsIdentity;
            if (identity != null)
            {
                var userclaims = identity.Claims;

                return new UserModel
                {
                    UserName = userclaims.FirstOrDefault(o => o.Type == ClaimTypes.Name)?.Value,
                    EmailAddress = userclaims.FirstOrDefault(o => o.Type == ClaimTypes.Email)?.Value,
                    Role = userclaims.FirstOrDefault(o => o.Type == ClaimTypes.Role)?.Value,
                    Password = userclaims.FirstOrDefault(o => o.Type == ClaimTypes.Role)?.Value

                };
                
            }

            return null;
        }
    }
   
}
