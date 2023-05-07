﻿
namespace LMS.Models.Auth
{
    public class Register
    {
        public string UserName { get; set; }

        public string Password { get; set; }

        public string ConfirmPassword { get; set; }

        public string Email { get; set; }

        public string FullName { get; set; }

        public DateTime? BirthDate { get; set; }
    }
}
