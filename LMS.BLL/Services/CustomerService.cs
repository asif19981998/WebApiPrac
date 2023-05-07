
using Base.Services;
using LMS.BLL.IServices;
using LMS.Repository.RepositoryService;
using LMSApi.Models;

namespace LMS.BLL.Services
{
    public class CustomerService:BaseService<Customer>,ICustomerService
    {
        private ICustomerRepository _customerRepository;
        public CustomerService(ICustomerRepository customerRepository):base(customerRepository)
        {
            _customerRepository = customerRepository;   
        }
    }
}
