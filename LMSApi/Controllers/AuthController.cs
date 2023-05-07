using LMS.Models.Auth;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using LMSApi.Models;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace LMSApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private UserManager<ApplicationIdentityUser> _userManager;
        private SignInManager<ApplicationIdentityUser> _signInManager;
        private readonly IAuthenticationSchemeProvider _authenticationSchemeProvider;

        public AuthController(UserManager<ApplicationIdentityUser> userManager, SignInManager<ApplicationIdentityUser> signInManager, IAuthenticationSchemeProvider authenticationSchemeProvider)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _authenticationSchemeProvider = authenticationSchemeProvider;
        }
        // GET: api/<AuthController>
        [HttpPost("Register")]
        public async Task<IActionResult> Register(Register model)
        {

            //Test Code For Google Authetication
            var schemes = await _authenticationSchemeProvider.GetAllSchemesAsync();

            // Filter out the schemes that are not external providers
            var externalSchemes = schemes.Where(s => !string.IsNullOrEmpty(s.DisplayName));
           
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationIdentityUser
            {
                UserName = model.UserName,
                Email = model.Email
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return Ok();
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(Login model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberMe, false);

            if (!result.Succeeded)
            {
                return BadRequest(new { message = "Username or password is incorrect" });
            }

            var user = await _userManager.FindByNameAsync(model.UserName);
            var claims = await _userManager.GetClaimsAsync(user);
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var authProperties = new AuthenticationProperties
            {
                ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(30),
                IsPersistent = model.RememberMe,
                AllowRefresh = false,
                
            };

            //await HttpContext.SignInAsync(
            //    CookieAuthenticationDefaults.AuthenticationScheme,
            //    new ClaimsPrincipal(claimsIdentity),
            //    authProperties);
            //var cookieOptions = new CookieOptions();
            //cookieOptions.IsEssential = true;
            var cookieOptions = new CookieOptions
            {
                Expires = DateTime.Now.AddDays(7),
                HttpOnly = true,
                SameSite = SameSiteMode.Strict,
                Secure = true
            };

            Response.Cookies.Append("jwt", "rakib", cookieOptions);
            //Response.Cookies.Append("Session", "MySessionValue", cookieOptions);
            return Ok(new { message = "Login successful" });
        }
        // GET api/<AuthController>/5
        [HttpGet("GetCookie")]
        public List<Customer> Get(int id)
        {
            //Response.Cookies.Append("name", "rakib", new CookieOptions
            //{
            //    HttpOnly = true
            //});

            List<Customer> customers = new List<Customer> 
            { 
                new Customer() {Id=1,Name="Sakib",Code="123258"},
                new Customer() {Id=1,Name="Sakib",Code="123258"},
                new Customer() {Id=1,Name="Sakib",Code="123258"}

            };

            return customers;
        }

        // POST api/<AuthController>
        [HttpGet]
        public void Post([FromBody] string value)
        {
        }

        // PUT api/<AuthController>/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/<AuthController>/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
