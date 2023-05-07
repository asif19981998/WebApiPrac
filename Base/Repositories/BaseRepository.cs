using Base.Contracts;
using LMS.Models.ModelContracts;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;

namespace Base.Repositories
{
    public class BaseRepository<T>:IMainRepository<T> where T:class, IEntity
    {
        private DbContext _db;
        public BaseRepository(DbContext db)
        {
            _db = db;

        }

        DbSet<T> Table => _db.Set<T>();

        public virtual bool Add(T entity)
        {
            Table.Add(entity);
            return SaveChanges();

        }

        public virtual async Task<bool> AddAsync(T entity)
        {
            await Table.AddAsync(entity);
            return await SaveChangesAsync();
        }

        public virtual bool AddOrUpdate(Expression<Func<T, object>> identifier, ICollection<T> entityCollections)
        {
            //Not Implemented Yet
            return false;
        }
        private bool AddOrUpdate(T entity)
        {
            //Not Implemented Yet
            return false;
        }
        public virtual bool AddRange(ICollection<T> entities)
        {
            Table.AddRange(entities);
            return SaveChanges();
        }

        public virtual async Task<bool> AddRangeAsync(ICollection<T> entities)
        {
            await Table.AddRangeAsync(entities);
            return await SaveChangesAsync();
        }

        public virtual ICollection<T> GetAll()
        {
            return Table.ToList();
        }
        public virtual async Task<ICollection<T>> GetAllAsync()
        {
            return await Table.ToListAsync();
        }
        public virtual T GetById(long id)
        {
            return Table.FirstOrDefault(c => c.Id == id);
        }
        public virtual async Task<T> GetByIdAsync(long id)
        {
            return await Table.FirstOrDefaultAsync(c => c.Id == id);
        }

        public virtual bool Remove(T entity, bool isShiftDeleted)
        {

            var isDelete = Table.Remove(entity);
            return SaveChanges();
        }
        public virtual bool RemoveRange(ICollection<T> entities, bool isShiftDeleted)
        {
            //if (entities == null || entities.Count <= 0)
            //{
            //    return false;
            //}
            //if (isShiftDeleted)
            //{
            //    Table.RemoveRange(entities);
            //    return SaveChanges();
            //}
            //foreach (var entity in entities)
            //{
            //    if (entities is IDeleteAble model) model.IsDeleted = true;

            //}
            //var isDeleted = UpdateRange(entities);
            //return isDeleted;
            return false;
        }

        public virtual bool Update(T entity)
        {
            try
            {
                Table.Attach(entity);
                _db.Entry(entity).State = EntityState.Modified;
                return SaveChanges();
            }
            catch (InvalidOperationException e)
            {
                if (!e.Message.ToLower().Contains("attach") && !e.Message.ToLower().Contains("multiple instances"))
                {
                    return false;
                }

                return AddOrUpdate(entity);

            }
        }
        public virtual async Task<bool> UpdateAsync(T entity)
        {
            Update(entity);
            return await SaveChangesAsync();

        }
        public virtual bool UpdateRange(ICollection<T> entities)
        {
            Table.UpdateRange(entities);
            return SaveChanges();
        }
        public virtual async Task<bool> UpdateRangeAsync(ICollection<T> entities)
        {
            Table.UpdateRange(entities);
            return await SaveChangesAsync();


        }
        private bool SaveChanges()
        {
            return _db.SaveChanges() > 0;
        }
        private async Task<bool> SaveChangesAsync()
        {

            return await _db.SaveChangesAsync() > 0;
        }

    }
}
