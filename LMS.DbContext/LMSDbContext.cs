using LMS.Models.Auth;
using LMS.Models.Models;
using LMSApi.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace LMSApi
{
    public class LMSDbContext : IdentityDbContext<ApplicationIdentityUser, ApplicationIdentityRole, string>
    {
        public LMSDbContext(DbContextOptions<LMSDbContext> options) : base(options) { }

        public DbSet<Customer> Customers { get; set; }
		public DbSet<CustomerType> CustomerTypes { get; set; }

		protected override void OnModelCreating(ModelBuilder modelBuilder)
		{
			base.OnModelCreating(modelBuilder);
			modelBuilder.ApplyConfiguration(new CustomerConfiguration());
			modelBuilder.ApplyConfiguration(new CustomerTypeConfiguration());

		}

	}

	
}
