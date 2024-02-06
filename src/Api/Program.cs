using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Api;

public class Program
{
    private static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder
            .Services.AddAuthorizationBuilder()
            .AddPolicy("admin_greetings", policy => policy.RequireRole("admin"));
        builder.Services.AddAuthorization().AddAuthentication().AddJwtBearer();
        var app = builder.Build();

        app.UseAuthentication();
        app.Use(
            async (context, next) =>
            {
                var result = await context.AuthenticateAsync(
                    JwtBearerDefaults.AuthenticationScheme
                );
                if (!result.Succeeded)
                {
                    if (context.Request.Path == "/secret" && result.Failure is not null)
                    {
                        // to log failure cause
                        throw result.Failure;
                    }
                }

                context.User = result.Principal!;

                await next();
            }
        );
        app.UseAuthorization();
        app.MapGet("/secret", () => "Hello world!").RequireAuthorization("admin_greetings");
        app.MapGet("/", () => "Welcome");
        await app.RunAsync();
    }
}
