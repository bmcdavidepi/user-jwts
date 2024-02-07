global using Xunit;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace Api.Tests;

internal class UserCreateRequest
{
    public Dictionary<string, string> Claims { get; init; } = [];
    public List<string> Roles { get; init; } = [];
    public string Username { get; init; } = string.Empty;
}

public sealed class AppHostFixture : IDisposable
{
    private static readonly byte[] signingKey = Encoding.ASCII.GetBytes(
        "THIS IS USED TO SIGN AND VERIFY JWT TOKENS, REPLACE IT WITH YOUR OWN SECRET, IT CAN BE ANY STRING"
    );
    private Dictionary<string, UserJwt> createdUsers = [];
    private readonly TestHost host = new();
    private HttpClient? defaultClient;

    internal record UserJwt(string Id, string Token);

    public HttpClient GetHttpClient() => defaultClient ??= host.CreateDefaultClient();

    public void Dispose() => CommonDispose().GetAwaiter().GetResult();

    private async Task CommonDispose()
    {
        await host.DisposeAsync();
        defaultClient?.Dispose();
        this.createdUsers.Clear();
    }

    internal void AssignBearerTokenForUser(string userId, HttpRequestMessage message)
    {
        if (!this.createdUsers.TryGetValue(userId, out var user))
        {
            return;
        }

        message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", user.Token);
    }

    /// <summary>Wrapper for dotnet CLI Tool user-jwts: https://learn.microsoft.com/en-us/aspnet/core/security/authentication/jwt-authn?view=aspnetcore-8.0</summary>
    internal async Task<UserJwt> CreateUserJwt(UserCreateRequest request)
    {
        await Task.CompletedTask;
        if (this.createdUsers.TryGetValue(request.Username, out var user))
        {
            return user;
        }

        if (GenerateJwtToken(request) is string jwt)
        {
            user = this.createdUsers[request.Username] = new UserJwt(request.Username, jwt);
            return user;
        }

        throw new InvalidOperationException("Unable to create user");
    }

    private string GenerateJwtToken(UserCreateRequest user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var claimsId = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, user.Username) });
        foreach (var claim in user.Claims)
        {
            claimsId.AddClaim(new(claim.Key, claim.Value));
        }
        foreach (var role in user.Roles)
        {
            claimsId.AddClaim(new(ClaimTypes.Role, role));
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = claimsId,
            Expires = DateTime.UtcNow.AddDays(1),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(signingKey),
                SecurityAlgorithms.HmacSha256Signature
            )
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private class TestHost : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureTestServices(o =>
                o.AddTransient<JwtBearerHandler, TestJwtBearerHandler>()
            );
        }

        internal class TestJwtBearerHandler(
            IOptionsMonitor<JwtBearerOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder
        ) : JwtBearerHandler(options, logger, encoder)
        {
            protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
            {
                var result = await base.HandleAuthenticateAsync();

                if (result.Failure is not SecurityTokenSignatureKeyNotFoundException)
                {
                    return result;
                }

                var tokenHandler = new JwtSecurityTokenHandler();
                var tokens = base.Context.Request.Headers.Authorization.ToString().Split(' ');
                if (tokens.Length < 2)
                {
                    return result;
                }

                // var token = tokenHandler.ReadJwtToken(tokens[1]);
                ClaimsPrincipal? claimsPrincipal;
                try
                {
                    // https://jasonwatmore.com/post/2021/12/14/net-6-jwt-authentication-tutorial-with-example-api
                    claimsPrincipal = tokenHandler.ValidateToken(
                        tokens[1],
                        new TokenValidationParameters
                        {
                            ValidateIssuerSigningKey = true,
                            IssuerSigningKey = new SymmetricSecurityKey(signingKey),
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                            ClockSkew = TimeSpan.Zero
                        },
                        out SecurityToken validatedToken
                    );
                }
                catch (Exception)
                {
                    throw;
                }

                if (claimsPrincipal is null)
                {
                    return result;
                }

                var scheme = JwtBearerDefaults.AuthenticationScheme;
                var ticket = new AuthenticationTicket(claimsPrincipal, scheme);
                var newResult = HandleRequestResult.Success(ticket);

                return newResult;
            }
        }
    }
}
