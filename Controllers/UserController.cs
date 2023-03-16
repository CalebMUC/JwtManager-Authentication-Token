using JwtManager_Authentication_Token.models;
using JwtManager_Authentication_Token.Controllers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JwtManager_Authentication_Token.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {


        [HttpGet("Admins")]

        [Authorize(Roles = "adminstrator")]
        public IActionResult AdminsEndpoint()
        {
            
            var currentuser = GetCurrentUser();

            return Ok($"hi {currentuser.UserName} you are an{currentuser.Role} ");
        }
        [HttpGet("Users")]
        [Authorize(Roles = "user")]
        public IActionResult SellersEndpoint()
        {
            var currentuser = GetCurrentUser();

            return Ok($"hi {currentuser.UserName} you are an{currentuser.Role} ");
        }
        [HttpGet("publice")]
        public IActionResult publice()
        {
            return Ok("you are on public property");
        }
        private UserModel GetCurrentUser()
        {
            //UserLogIn userLogIn = new UserLogIn();

            //var user = UserAuthentication.Authenticate(userLogIn);

            //var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IkNhbGViIE11Y2hpcmkiLCJuYmYiOjE2Nzg4ODgxMDMsImV4cCI6MTY3ODg4OTkwMywiaWF0IjoxNjc4ODg4MTAzLCJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo0NDMzNC8iLCJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo0NDMzNC8ifQ.BFEeN0QfCmjHyELTJpRYv1VeWXObpCmpoZHkfJw3SBw";

            //var simplePrincipal = UserAuthentication.GetPrincipal(token);

        

            var identity = HttpContext.User.Identity as ClaimsIdentity;
            if (identity != null)
            {
                var userclaims = identity.Claims;

                return new UserModel
                {
                    UserName = userclaims.FirstOrDefault(o => o.Type == ClaimTypes.NameIdentifier)?.Value,
                    EmailAddress = userclaims.FirstOrDefault(o => o.Type == ClaimTypes.Email)?.Value,
                    Role = userclaims.FirstOrDefault(o => o.Type == ClaimTypes.Role)?.Value,
                    Password = userclaims.FirstOrDefault(o => o.Type == ClaimTypes.Role)?.Value

                };
                
            }

            return null;
        }
    }
   
}
