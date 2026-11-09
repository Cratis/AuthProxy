// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteAuthenticationMiddleware;

public class when_the_gate_decision_is_missing_or_inconsistent : given.a_real_issued_token_pipeline
{
    [Theory]
    [InlineData("missing")]
    [InlineData("token")]
    [InlineData("route")]
    public async Task should_refuse_instead_of_revalidating_or_using_the_cookie(string inconsistency)
    {
        BetweenGateAndAuthentication = context =>
        {
            var credential = IssuedBearerRouteCredential.Read(context);
            switch (inconsistency)
            {
                case "missing":
                    context.Items.Remove(typeof(IssuedBearerRouteCredential));
                    break;
                case "token":
                    context.Request.Headers.Authorization = "Bearer different-credential";
                    break;
                case "route":
                    IssuedBearerRouteCredential.Store(context, credential with { Route = credential.Route with { ServiceName = "catalog" } });
                    break;
            }
        };
        var context = await Send(cookie: false, token: Token);
        context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
        context.Items[AuthenticationServiceCollectionExtensions.SelectedSchemeItemKey].ShouldEqual(ClientCredentialsDefaults.AuthenticationScheme);
        context.Response.Headers.WWWAuthenticate.ToString().ShouldEqual($"Bearer error=\"invalid_token\", resource_metadata=\"{Metadata}\"");
        DownstreamCalls.ShouldEqual(0);
        CookieValidations.ShouldEqual(0);
        JwtAuthentications.ShouldEqual(0);
        Validator.ReceivedCalls().ShouldBeEmpty();
    }
}
