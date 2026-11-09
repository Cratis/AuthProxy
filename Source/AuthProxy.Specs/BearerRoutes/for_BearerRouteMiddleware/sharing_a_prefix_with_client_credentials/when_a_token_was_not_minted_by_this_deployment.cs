// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware.sharing_a_prefix_with_client_credentials;

public class when_a_token_was_not_minted_by_this_deployment : given.a_bearer_route_sharing_its_prefix_with_client_credentials
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task should_not_recognize_an_altered_or_foreign_token(bool altered)
    {
        var token = altered
            ? Issue(IssuedFor)
            : new ClientCredentialsTokenProtector(new EphemeralDataProtectionProvider()).CreateToken(IssuedFor, "foreign-client");
        if (altered)
        {
            var position = token.Length / 2;
            token = token[..position] + (token[position] == 'A' ? 'B' : 'A') + token[(position + 1)..];
        }

        TokenProtector.IsIssued(token).ShouldBeFalse();
        TokenProtector.TryValidate(token, out _).ShouldBeFalse();
        var context = Request("/api/tools", $"Bearer {token}");
        await Middleware.InvokeAsync(context);
        await Validator.Received(1).Validate(context.Request, Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>());
        context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
        Forwarder.ReceivedCalls().ShouldBeEmpty();
        Next.ReceivedCalls().ShouldBeEmpty();
    }
}
