// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteAuthenticationMiddleware;

public class when_an_issued_token_targets_another_service_or_tenant : given.a_real_issued_token_pipeline
{
    [Theory]
    [InlineData("catalog.test", null, StatusCodes.Status401Unauthorized)]
    [InlineData("portal.test", "tenant-b", StatusCodes.Status403Forbidden)]
    public async Task should_refuse_the_machine_without_authenticating_the_browser(string host, string? tenant, int status)
    {
        var context = await Send(cookie: true, token: Token, host: host, tenant: tenant);
        context.Response.StatusCode.ShouldEqual(status);
        if (status == StatusCodes.Status401Unauthorized)
        {
            context.Response.Headers.WWWAuthenticate.ToString().ShouldEqual($"Bearer error=\"invalid_token\", resource_metadata=\"{Metadata}\"");
        }
        else
        {
            context.User.Identity!.AuthenticationType.ShouldEqual(ClientCredentialsDefaults.AuthenticationScheme);
            context.User.FindFirst(ClientCredentialsDefaults.TenantClaimType)!.Value.ShouldEqual("tenant-a");
        }

        DownstreamCalls.ShouldEqual(0);
        CookieValidations.ShouldEqual(0);
        JwtAuthentications.ShouldEqual(0);
        Validator.ReceivedCalls().ShouldBeEmpty();
        Forwarder.ReceivedCalls().ShouldBeEmpty();
    }
}
