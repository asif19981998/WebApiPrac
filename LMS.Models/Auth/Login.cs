
namespace LMS.Models.Auth
{
    public class Login
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public bool RememberMe { get; set; }
        public string Email { get; set; }
    }
}
