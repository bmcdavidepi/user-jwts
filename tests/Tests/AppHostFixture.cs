global using Xunit;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Api.Tests;

internal class UserCreateRequest
{
    public Dictionary<string, string> Claims { get; init; } = [];
    public List<string> Roles { get; init; } = [];
    public string Username { get; init; } = string.Empty;
}

public sealed class AppHostFixture : IDisposable
{
    private static readonly string ApiProjectPath = GetApiProjectPath();
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

        foreach (var users in this.createdUsers)
        {
            var commandArgs = $"user-jwts remove --project {ApiProjectPath} {users.Key}";
            var result = await ExecuteDotNetCli(commandArgs);
        }

        await CreateUserJwt(new() { Username = "placeholder", Roles = ["none"] });
    }

    private static string GetApiProjectPath()
    {
        const string partialPath = "src/Api/Api.csproj";
        var startingFolder = new DirectoryInfo(Environment.CurrentDirectory);
        var fileInfo = new FileInfo(Path.Combine(startingFolder.FullName, partialPath));

        if (fileInfo.Exists)
        {
            return fileInfo.FullName;
        }

        while (!fileInfo.Exists && fileInfo.Directory is not null)
        {
            startingFolder = startingFolder.Parent!;
            fileInfo = new FileInfo(Path.Combine(startingFolder.FullName, partialPath));

            if (fileInfo.Exists)
            {
                return fileInfo.FullName;
            }
        }

        throw new InvalidOperationException();
    }

    internal static async Task<string> ExecuteDotNetCli(string commandArgs, string file = "dotnet")
    {
        var output = new StringBuilder();
        var errors = new StringBuilder();
        using var process = new Process();
        var startInfo = new ProcessStartInfo
        {
            FileName = file,
            Arguments = commandArgs,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        process.OutputDataReceived += (s, e) => output.AppendLine(e.Data);
        process.ErrorDataReceived += (s, e) => errors.AppendLine(e.Data);
        process.StartInfo = startInfo;
        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        await process.WaitForExitAsync();

        return errors.Length != Environment.NewLine.Length ? errors.ToString() : output.ToString();
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
        if (this.createdUsers.TryGetValue(request.Username, out var user))
        {
            return user;
        }

        var rootCommand =
            $"user-jwts create --project {ApiProjectPath} -o json --name {request.Username}";
        var commandBuilder = new StringBuilder();
        commandBuilder.Append(rootCommand);

        foreach (var claim in request.Claims)
        {
            var claimString = $" --claim {claim.Key}={claim.Value}";
            commandBuilder.Append(claimString);
        }

        foreach (var role in request.Roles)
        {
            var roleString = $" --role {role}";
            commandBuilder.Append(roleString);
        }

        var result = await ExecuteDotNetCli(commandBuilder.ToString());

        if (result[0] == '{')
        {
            user = System.Text.Json.JsonSerializer.Deserialize<UserJwt>(result)!;
            await Task.Delay(250); // allows user to propagate to filesystem otherwise its too quick to pass auth

            this.createdUsers[user.Id] = user;
            return user;
        }

        throw new InvalidOperationException(result);
    }

    private class TestHost : WebApplicationFactory<Program> { }
}
