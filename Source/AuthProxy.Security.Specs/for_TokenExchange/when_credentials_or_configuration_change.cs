// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.Security.for_TokenExchange;

public class when_credentials_or_configuration_change
{
    [Theory]
    [InlineData("duplicate-authorization")]
    [InlineData("query-token")]
    [InlineData("session-cookie")]
    public async Task should_refuse_ambiguous_credentials_before_exchange(string presentation)
    {
        await using var harness = new TokenExchangeHarness();
        using var client = harness.CreateBearerClient();
        using var request = Request(harness.Subject());
        switch (presentation)
        {
            case "duplicate-authorization":
                request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + harness.Subject());
                break;
            case "query-token":
                request.RequestUri = new(BearerRouteHarness.RoutePrefix + "?access_token=" + Uri.EscapeDataString(harness.Subject()), UriKind.Relative);
                break;
            case "session-cookie":
                var options = harness.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get("Cookies");
                var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "session-user")], "Cookies"));
                var ticket = new AuthenticationTicket(principal, "Cookies");
                request.Headers.TryAddWithoutValidation("Cookie", $"{options.Cookie.Name}={options.TicketDataFormat.Protect(ticket)}");
                break;
        }
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, harness.Calls);
        Assert.Empty(harness.Origin.Received);
    }

    [Fact]
    public async Task should_not_reuse_tenant_a_exchange_for_tenant_b()
    {
        await using var harness = new TokenExchangeHarness();
        using var client = harness.CreateBearerClient();
        var subject = harness.Subject();
        using var first = await client.SendAsync(Request(subject), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(1, harness.Calls);
        harness.Origin.Clear();
        harness.Status = HttpStatusCode.BadRequest; // Identity answers invalid_grant for tenant B.
        using var request = Request(subject);
        request.Headers.Host = "b.direct.example.test";
        using var second = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, second.StatusCode);
        Assert.Equal(2, harness.Calls);
        var form = QueryHelpers.ParseQuery(harness.Form);
        Assert.Equal("tenant-b", form["tenant"].ToString());
        Assert.Equal(subject, form["subject_token"].ToString());
        Assert.Empty(harness.Origin.Received);
    }

    [Fact]
    public async Task should_refuse_the_raw_external_token_after_exchange_is_removed_on_reload()
    {
        await using var harness = new TokenExchangeHarness();
        using var client = harness.CreateBearerClient();
        var subject = harness.Subject();
        using var before = await client.SendAsync(Request(subject), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        var monitor = harness.Services.GetRequiredService<IOptionsMonitor<C.AuthProxy>>();
        Assert.NotNull(monitor.CurrentValue.Services["app"].BearerRoutes[0].TokenExchange);
        harness.DisableExchange();
        Assert.Null(monitor.CurrentValue.Services["app"].BearerRoutes[0].TokenExchange);
        harness.Origin.Clear();
        using var after = await client.SendAsync(Request(subject), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
        Assert.Equal(1, harness.Calls);
        Assert.Empty(harness.Origin.Received);
    }

    static HttpRequestMessage Request(string subject)
    {
        var request = BearerRouteHarness.WithToken(HttpMethod.Get, BearerRouteHarness.RoutePrefix, subject);
        request.Headers.Host = "a.direct.example.test";
        return request;
    }
}
