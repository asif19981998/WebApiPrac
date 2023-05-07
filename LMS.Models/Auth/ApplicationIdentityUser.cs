using Microsoft.AspNetCore.Identity;

namespace LMS.Models.Auth
{
    public class ApplicationIdentityUser:IdentityUser
    {
        public string FullName { get; set; }
        public DateTime BirthDate { get; set; }
    }
}
