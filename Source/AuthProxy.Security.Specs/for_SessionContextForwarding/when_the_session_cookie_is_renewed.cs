// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Security.for_SessionContextForwarding;

public class when_the_session_cookie_is_renewed : given.a_session_context
{
    [Fact]
    public async Task should_keep_the_original_start_after_sliding_renewal()
    {
        await using var harness = new SessionContextHarness();
        var cookie = await harness.SignIn();
        var before = await Forward(harness, cookie);
        harness.Clock.Advance(TimeSpan.FromMinutes(31));
        using var client = harness.CreateBearerClient();
        using var request = SessionContextHarness.Request(cookie);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.TryGetValues("Set-Cookie", out var renewed));
        var renewedCookie = string.Join("; ", renewed.Select(value => value.Split(';', 2)[0]));
        Assert.NotEqual(cookie, renewedCookie);
        var after = await Forward(harness, renewedCookie);
        Assert.Equal(Value(before, SessionClaims.Started), Value(after, SessionClaims.Started));
        Assert.Equal(Value(before, SessionClaims.SignInProvider), Value(after, SessionClaims.SignInProvider));
    }
}
