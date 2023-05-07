using Base.Contracts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;

namespace Base.Services
{
    public class BaseService<T>:IMainRepository<T> where T : class
    {
        private IMainRepository<T> _repository;
        public BaseService(IMainRepository<T> irepository)
        {
            _repository = irepository;
        }
        public virtual bool Add(T entity)
        {
            return _repository.Add(entity);
        }

        public virtual async Task<bool> AddAsync(T entity)
        {
            return await _repository.AddAsync(entity);
        }

        public virtual bool AddOrUpdate(Expression<Func<T, object>> identifier, ICollection<T> entityCollections)
        {
            //Not Implemented Yet
            throw new NotImplementedException();
        }

        public virtual bool AddRange(ICollection<T> entities)
        {
            return _repository.AddRange(entities);
        }

        public virtual async Task<bool> AddRangeAsync(ICollection<T> entities)
        {
            return await _repository.AddRangeAsync(entities);
        }

        public virtual ICollection<T> GetAll()
        {
            return _repository.GetAll();
        }

        public virtual async Task<ICollection<T>> GetAllAsync()
        {
            return await _repository.GetAllAsync();
        }

        public virtual T GetById(long id)
        {
            return _repository.GetById(id);
        }

        public virtual async Task<T> GetByIdAsync(long id)
        {
            return await _repository.GetByIdAsync(id);
        }

        public virtual bool Remove(T entity, bool isShiftDeleted = false)
        {
            return _repository.Remove(entity, false);
        }

        public virtual bool RemoveRange(ICollection<T> entities, bool isShiftDeleted = false)
        {
            return _repository.RemoveRange(entities, false);
        }

        public virtual bool Update(T entity)
        {
            return _repository.Update(entity);
        }

        public virtual Task<bool> UpdateAsync(T entity)
        {
            return _repository.UpdateAsync(entity);
        }

        public virtual bool UpdateRange(ICollection<T> entities)
        {
            return _repository.UpdateRange(entities);
        }

        public virtual async Task<bool> UpdateRangeAsync(ICollection<T> entities)
        {
            return await _repository.UpdateRangeAsync(entities);
        }
    }
}
