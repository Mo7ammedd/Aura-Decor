using AuraDecor.APIs.Errors;
using AuraDecor.APIs.Helpers;
using AuraDecor.Core.Configuration;
using AuraDecor.Core.Repositories.Contract;
using AuraDecor.Core.Services.Contract;
using AuraDecor.Repository;
using AuraDecor.Repository.Data;
using AuraDecor.Services;
using AuraDecor.Servicies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using StackExchange.Redis;

namespace AuraDecor.APIs.Extensions;

public static class ApplicationServicesExtensions
{
    public static IServiceCollection AddApplicationServices(this IServiceCollection services, IConfiguration config)
    {
        services.AddScoped<IUnitOfWork, UnitOfWork>();
        services.AddScoped<IFurnitureService, FurnitureService>();
        services.AddScoped<IRoleService, RoleService>();
        services.AddScoped<ICartService, CartService>();
        services.AddScoped<IOrderService, OrderService>();

        services.AddScoped<IResponseCacheService, ResponseCacheService>();
        services.AddSingleton<IEmailService, EmailService>();

        services.AddAutoMapper(m => m.AddProfile<MappingProfiles>());
        services.AddDbContext<AppDbContext>(options =>
            options.UseSqlServer(config.GetConnectionString("DefaultConnection")));
        services.AddSingleton<IConnectionMultiplexer, ConnectionMultiplexer>(c =>
        {
            var configuration = ConfigurationOptions.Parse(config.GetConnectionString("Redis"), true);
            return ConnectionMultiplexer.Connect(configuration);
        });
        services.Configure<ApiBehaviorOptions>(options =>
        {
            options.InvalidModelStateResponseFactory = context =>
            {
                var errors = context.ModelState
                    .Where(e => e.Value.Errors.Count > 0)
                    .SelectMany(x => x.Value.Errors)
                    .Select(x => x.ErrorMessage).ToArray();

                var errorResponse = new ApiValidationErrorResponse
                {
                    Errors = errors
                };

                return new BadRequestObjectResult(errorResponse);
            };
        });
        services.Configure<EmailSettings>(
            config.GetSection("EmailSettings"));


        return services;
    }
}