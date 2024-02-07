namespace Api.Tests;

public class RouteTests(AppHostFixture host) : IClassFixture<AppHostFixture>
{
    [Fact]
    public async Task ShouldResolveRoot()
    {
        var client = host.GetHttpClient();
        var result = await client.GetAsync("/");
        var contentResult = await result.Content.ReadAsStringAsync();

        Assert.True(result.IsSuccessStatusCode);
        Assert.Equal("Welcome", contentResult);
    }

    [Fact]
    public async Task ShouldNotResolveSecretWithoutToken()
    {
        var client = host.GetHttpClient();
        var result = await client.GetAsync("/secret");

        Assert.False(result.IsSuccessStatusCode);
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, result.StatusCode);
    }

    [Fact]
    public async Task ShouldResolveSecretWithToken()
    {
        var client = host.GetHttpClient();
        var user = await host.CreateUserJwt(new() { Username = "user1", Roles = ["admin"] });
        using var httpMessage = new HttpRequestMessage
        {
            RequestUri = new Uri("secret", UriKind.Relative),
        };
        host.AssignBearerTokenForUser(user.Id, httpMessage);
        var result = await client.SendAsync(httpMessage);
        var contentResult = await result.Content.ReadAsStringAsync();

        Assert.Equal(System.Net.HttpStatusCode.OK, result.StatusCode);
        Assert.Equal("Hello world!", contentResult);
    }
}
