// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteAuthenticationMiddleware;

public class when_an_issued_token_reaches_authentication : given.a_real_issued_token_pipeline
{
    [Theory]
    [InlineData("/api/x")]
    [InlineData("/API/x")]
    public async Task should_authenticate_only_the_machine_on_either_path_spelling(string path)
    {
        var context = await Send(path, cookie: true, token: Token);
        context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
        context.User.Identity!.AuthenticationType.ShouldEqual(ClientCredentialsDefaults.AuthenticationScheme);
        context.User.FindFirst("sub")!.Value.ShouldEqual("machine");
        context.User.FindFirst(ClientCredentialsDefaults.TenantClaimType)!.Value.ShouldEqual("tenant-a");
        DownstreamCalls.ShouldEqual(1);
        CookieValidations.ShouldEqual(0);
        JwtAuthentications.ShouldEqual(0);
        Validator.ReceivedCalls().ShouldBeEmpty();
        Forwarder.ReceivedCalls().ShouldBeEmpty();
    }
}
