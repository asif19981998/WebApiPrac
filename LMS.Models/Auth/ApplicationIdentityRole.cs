using Microsoft.AspNetCore.Identity;

namespace LMS.Models.Auth
{
    public class ApplicationIdentityRole: IdentityRole
    {
        public string Description { get; set; }
    }
}
