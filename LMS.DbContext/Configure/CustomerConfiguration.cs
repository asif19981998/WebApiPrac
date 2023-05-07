using LMSApi.Models;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore;

public class CustomerConfiguration : IEntityTypeConfiguration<Customer>
{
	public void Configure(EntityTypeBuilder<Customer> builder)
	{
		builder.HasKey(c => c.Id);

		builder.Property(c => c.Name).IsRequired();
		builder.Property(c => c.Code).IsRequired();

		builder.HasOne(c => c.CustomerType)
			.WithMany()
			.HasForeignKey(c => c.CustomerTypeId)
			.OnDelete(DeleteBehavior.Restrict);
	}
}