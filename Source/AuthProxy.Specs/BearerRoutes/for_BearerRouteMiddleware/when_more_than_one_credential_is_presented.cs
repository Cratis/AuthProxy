// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware;

/// <summary>
/// More than one credential is a malformed request (RFC 6750 §3.1), not a bad token: neither is chosen, neither
/// branch sees either, and the answer is the same on every kind of route.
/// </summary>
public class when_more_than_one_credential_is_presented : given_a_credential_dispatching_gate
{
    public static TheoryData<string, string[], string> Presentations => new()
    {
        { CombinedPath, [$"Bearer {Pat()}", $"Bearer {JwtLikeToken}"], string.Empty },
        { CombinedPath, [$"Bearer {JwtLikeToken}", $"Bearer {Pat()}"], string.Empty },
        { CombinedPath, [$"Bearer {Pat()}", $"Bearer {Pat()}"], string.Empty },
        { PatOnlyPath, [$"Bearer {Pat()}", $"Bearer {Pat()}"], string.Empty },
        { OAuthPath, [$"Bearer {JwtLikeToken}", $"Bearer {JwtLikeToken}"], string.Empty },
        { CombinedPath, [$"Bearer {Pat()}, Bearer {JwtLikeToken}"], string.Empty },
        { PatOnlyPath, [$"Bearer {Pat()},{Pat()}"], string.Empty },
        { CombinedPath, [$"Bearer {Pat()}"], "?access_token=" + JwtLikeToken },
        { OAuthPath, [$"Bearer {JwtLikeToken}"], "?access_token=" + JwtLikeToken },
    };

    [Theory]
    [MemberData(nameof(Presentations))]
    public async Task should_refuse_as_an_invalid_request_before_either_branch(string path, string[] authorization, string query)
    {
        var context = Request(path, "GET", authorization);
        context.Request.QueryString = new QueryString(query);
        await Middleware.InvokeAsync(context);

        context.Response.StatusCode.ShouldEqual(BearerChallenge.MultipleCredentialsStatusCode);
        context.Response.StatusCode.ShouldEqual(StatusCodes.Status400BadRequest);
        Challenge(context).ShouldEqual("Bearer error=\"invalid_request\"");
        Body(context).ShouldEqual(ErrorBody("invalid_request"));
        Validator.ReceivedCalls().ShouldBeEmpty();
        Forwarder.ReceivedCalls().ShouldBeEmpty();
        Next.ReceivedCalls().ShouldBeEmpty();
    }
}
