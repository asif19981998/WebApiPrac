using LMS.IoCContainer;
using LMS.Models.Auth;
using LMSApi;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
//using Microsoft.AspNetCore.Authentication.Google;
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddDbContext<LMSDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
IoCContainer.Configure(builder.Services);
builder.Services.AddIdentity<ApplicationIdentityUser, ApplicationIdentityRole>()
                .AddEntityFrameworkStores<LMSDbContext>()
                .AddDefaultTokenProviders();
builder.Services.AddHttpContextAccessor();
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.CheckConsentNeeded = context => true;
    options.MinimumSameSitePolicy = SameSiteMode.None;
});
builder.Services.AddAuthentication(
    CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie();
builder.Services.AddAuthentication().AddGoogle(options =>
{
    options.ClientId = "275767469911-2o7jsgev5fvp3kes6ff16uunbjgkh8bq.apps.googleusercontent.com";
    options.ClientSecret = "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";
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
