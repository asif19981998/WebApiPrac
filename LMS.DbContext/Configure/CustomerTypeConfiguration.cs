using LMS.Models.Models;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore;

public class CustomerTypeConfiguration : IEntityTypeConfiguration<CustomerType>
{
	public void Configure(EntityTypeBuilder<CustomerType> builder)
	{
		builder.HasKey(ct => ct.Id);

		builder.Property(ct => ct.Name).IsRequired();
		builder.Property(ct => ct.Code).IsRequired();
	}
}