// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace Cratis.AuthProxy.Security.for_AccessControl;

[Collection(SecuritySpecCollection.Name)]
public class when_a_browser_switches_users(SecurityHarness harness) : IAsyncLifetime
{
    const string Alice = "readable-identity-alice";
    const string Bob = "readable-identity-bob";
    HttpResponseMessage _response;
    JsonElement _rewrittenIdentity;

    public async ValueTask InitializeAsync()
    {
        harness.Origin.IdentityResponse = () => Results.Json(new { detail = "from-service" });
        try
        {
            var aliceCookies = await IssueCookies(Alice);
            var bobCookies = await IssueCookies(Bob);
            var readable = aliceCookies.Single(_ => _.StartsWith($"{Cookies.Identity}=", StringComparison.Ordinal));
            var authorization = bobCookies.Single(_ => _.StartsWith($"{Cookies.IdentityAuthorization}=", StringComparison.Ordinal));
            using var client = harness.CreateSecurityClient();
            using var request = SecurityHarness.Authenticated(HttpMethod.Get, "/.cratis/me", Bob);
            request.Headers.Add("Cookie", $"{authorization}; {readable}");
            _response = await client.SendAsync(request);
            var cookies = _response.Headers.GetValues("Set-Cookie").ToArray();
            var identity = cookies.Single(_ => _.StartsWith($"{Cookies.Identity}=", StringComparison.Ordinal)).Split(';', 2)[0].Split('=', 2)[1];
            using var document = JsonDocument.Parse(Convert.FromBase64String(Uri.UnescapeDataString(identity)));
            _rewrittenIdentity = document.RootElement.Clone();
        }
        finally
        {
            harness.Origin.IdentityResponse = () => Results.Json(new { });
        }
    }

    public ValueTask DisposeAsync()
    {
        _response?.Dispose();
        return ValueTask.CompletedTask;
    }

    [Fact] void should_authorize_the_current_caller() => Assert.Equal(HttpStatusCode.OK, _response.StatusCode);
    [Fact]
    void should_name_the_current_caller()
    {
        Assert.Equal(Bob, _rewrittenIdentity.GetProperty("id").GetString());
        Assert.Equal(Bob, _rewrittenIdentity.GetProperty("name").GetString());
    }

    async Task<string[]> IssueCookies(string caller)
    {
        using var client = harness.CreateSecurityClient();
        using var request = SecurityHarness.Authenticated(HttpMethod.Get, "/.cratis/me", caller);
        using var response = await client.SendAsync(request);
        return response.Headers.GetValues("Set-Cookie").Select(_ => _.Split(';', 2)[0]).ToArray();
    }
}
