using LMS.Models.ModelContracts;
using LMS.Models.Models;
using System.ComponentModel.DataAnnotations.Schema;

namespace LMSApi.Models
{
    public class Customer:IEntity
    {
		public long Id { get; set; }
		public string Name { get; set; }
		public string Code { get; set; }

		public long CustomerTypeId { get; set; }

		public  CustomerType? CustomerType { get; set; }

	}
}
