using System.Reflection;
using AuraDecor.Core.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuraDecor.Repository.Data;

public class AppDbContext : IdentityDbContext<User>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder); 

        modelBuilder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());
        // var FurnitureData = AppDbContextDataSeed.DataSeeder.GetFurnitureData();
        // modelBuilder.Entity<Furniture>().HasData(FurnitureData);
    }

    public DbSet<Furniture> Furniture { get; set; }
    public DbSet<FurnitureCategory> FurnitureCategories { get; set; }
    public DbSet<FurnitureBrand> FurnitureBrands { get; set; }
    public DbSet<Cart> Carts { get; set; }
    public DbSet<CartItem> CartItems { get; set; }
    public DbSet<Order> Orders { get; set; }
    public DbSet<OrderItem> OrdersItems { get; set; }

   
}