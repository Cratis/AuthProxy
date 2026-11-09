// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

[Collection(BearerRouteSpecCollection.Name)]
public class when_a_session_accompanies_a_bearer(BearerRouteHarness harness)
{
    [Fact]
    public async Task should_refuse_without_forwarding()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();
        var options = harness.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "session-user"), new Claim("tid", BearerRouteHarness.SessionTenantId)], "Cookies"));
        var ticket = new AuthenticationTicket(principal, "Cookies");
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, $"{BearerRouteHarness.RoutePrefix}/tools", harness.Issuer.Token());
        request.Headers.TryAddWithoutValidation("Cookie", $"{options.Cookie.Name}={options.TicketDataFormat.Protect(ticket)}");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
    }
}
