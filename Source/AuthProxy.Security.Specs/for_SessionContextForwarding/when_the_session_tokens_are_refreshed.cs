// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens;
using Cratis.AuthProxy.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.for_SessionContextForwarding;

public class when_the_session_tokens_are_refreshed : given.a_session_context
{
    [Fact]
    public async Task should_keep_the_original_context_after_refreshing_the_provider_token()
    {
        await using var harness = new SessionContextHarness();
        using var client = harness.CreateBearerClient();
        var session = await harness.Services.GetRequiredService<IUserTokenStore>().Create(new("provider-one", "spec-refresh-token"), CancellationToken.None);
        var cookie = await harness.SignIn(tokenSession: session);
        var before = await Forward(harness, cookie);
        harness.Clock.Advance(TimeSpan.FromMinutes(1));
        var token = await harness.Services.GetRequiredService<IUserAccessTokens>().GetFor(session, new C.ServiceAccessToken { Scopes = ["api://service/read"] }, CancellationToken.None);
        Assert.Equal("refreshed-token", token.Token);
        Assert.Equal(1, harness.Refreshes);
        var after = await Forward(harness, cookie);
        Assert.Equal(Value(before, SessionClaims.Started), Value(after, SessionClaims.Started));
        Assert.Equal(Value(before, SessionClaims.SignInProvider), Value(after, SessionClaims.SignInProvider));
    }
}
