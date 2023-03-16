using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtManager_Authentication_Token.models
{
    public class UserModel
    {
        public string UserName { get; set; }
        public string EmailAddress { get; set; }
        public string Role{ get; set; }
        public string Password { get; set; }

    }
}
