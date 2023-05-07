using Base.Repositories;
using LMS.Repository.RepositoryService;
using LMSApi;
using LMSApi.Models;


namespace LMS.Repository.Repository
{
    public class CustomerRepository:BaseRepository<Customer>,ICustomerRepository
    {
        private LMSDbContext _db;
        public CustomerRepository(LMSDbContext db):base(db)
        {
            _db= db;
        }
       

    }
}
