
using LMS.BLL.IServices;
using LMS.BLL.Services;
using LMS.Repository.Repository;
using LMS.Repository.RepositoryService;
using Microsoft.Extensions.DependencyInjection;

namespace LMS.IoCContainer
{
    public static class IoCContainer
    {
        public static void Configure(IServiceCollection services)
        {
            services.AddTransient<ICustomerService, CustomerService>();
            services.AddTransient<ICustomerRepository, CustomerRepository>();
        }
    }
}
