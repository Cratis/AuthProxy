// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.PersonalAccessTokens;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware;

/// <summary>
/// A credential that is refused is refused as the kind it is: it is never retried as the other kind, and nothing
/// of it is sent back.
/// </summary>
public class when_a_credential_cannot_be_used_on_the_route : given_a_credential_dispatching_gate
{
    public static TheoryData<string, string> Refusals => new()
    {
        { PatOnlyPath, "Bearer direct_pat_v1_short" },
        { PatOnlyPath, "Bearer {bad-checksum}" },
        { PatOnlyPath, "Bearer {other-resource}" },
        { PatOnlyPath, $"Bearer {JwtLikeToken}" },
        { PatOnlyPath, "Bearer opaque-token" },
        { PatOnlyPath, "Bearer " },
        { OAuthPath, "Bearer {pat}" },
        { OAuthPath, "Bearer {bad-checksum}" },
        { CombinedPath, "Bearer {bad-checksum}" },
        { CombinedPath, "Bearer {other-resource}" },
        { CombinedPath, "Bearer direct_pat_v1_short" },
        { PatOnlyPath, "DPoP {pat}" },
        { CombinedPath, "Basic {pat}" },
    };

    static string Resolve(string authorization) => authorization
        .Replace("{bad-checksum}", TestPersonalAccessTokens.CreateWithBadChecksum("direct"), StringComparison.Ordinal)
        .Replace("{other-resource}", Pat("studio"), StringComparison.Ordinal)
        .Replace("{pat}", Pat(), StringComparison.Ordinal);

    [Theory]
    [MemberData(nameof(Refusals))]
    public async Task should_refuse_as_an_invalid_token_without_trying_the_other_branch(string path, string authorization)
    {
        var value = Resolve(authorization);
        var context = Request(path, "GET", value);
        await Middleware.InvokeAsync(context);

        context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);

        // A route that accepts personal access tokens alone names its realm and nothing else (see BearerChallenge).
        if (path == PatOnlyPath)
        {
            Challenge(context).ShouldEqual("Bearer realm=\"direct\"");
        }
        else
        {
            Challenge(context).ShouldContain("error=\"invalid_token\"");
        }

        Body(context).ShouldEqual(ErrorBody("unauthorized"));
        Forwarder.ReceivedCalls().ShouldBeEmpty();
        Next.ReceivedCalls().ShouldBeEmpty();
        Validator.ReceivedCalls().ShouldBeEmpty();

        var secret = value[(value.IndexOf(' ', StringComparison.Ordinal) + 1)..];
        if (secret.Length > 0)
        {
            Body(context).ShouldNotContain(secret);
            Challenge(context).ShouldNotContain(secret);
        }
    }
}
