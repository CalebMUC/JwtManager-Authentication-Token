using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtManager_Authentication_Token.models
{
    public class UserValues
    {
        //defied when we are not using real users from the  DB otherwise we would use users from the DB

        public static List<UserModel> users = new List<UserModel>()
        {
            new UserModel(){
                UserName="Caleb Muchiri" ,
                EmailAddress="muchiricaleb05@gmail.com",
                Password="caleb",
                Role="adminstrator" },
             new UserModel(){
                UserName="Mark" ,
                EmailAddress="muchiricaleb08@gmail.com",
                Password="mark",
                Role="user" },


        };
        
       
       
        }
    }

