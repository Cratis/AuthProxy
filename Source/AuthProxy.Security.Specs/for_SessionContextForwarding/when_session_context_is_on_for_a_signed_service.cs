// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using System.Text.Json.Nodes;
using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Security.for_SessionContextForwarding;

public class when_session_context_is_on_for_a_signed_service : given.a_session_context
{
    [Theory]
    [InlineData(true, "provider-one")]
    [InlineData(false, "github")]
    public async Task should_forward_only_protected_context_and_cover_both_claims_with_the_signature(bool oidc, string scheme)
    {
        await using var harness = new SessionContextHarness();
        var cookie = await harness.SignIn(oidc);
        var observed = await Forward(harness, cookie);
        Assert.Equal(harness.Clock.GetUtcNow().ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), Value(observed, SessionClaims.Started));
        Assert.Equal(scheme, Value(observed, SessionClaims.SignInProvider));
        Assert.DoesNotContain(Claims(observed), claim => claim!["typ"]!.GetValue<string>() == "auth_time");
        Assert.True(Verify(Observation(observed)));
        foreach (var type in new[] { SessionClaims.Started, SessionClaims.SignInProvider })
        {
            var principal = JsonNode.Parse(Convert.FromBase64String(observed.Value(Headers.Principal)))!;
            principal["claims"]!.AsArray().Single(claim => claim!["typ"]!.GetValue<string>() == type)!["val"] = "tampered";
            var headers = Observation(observed).Headers.ToDictionary(header => header.Key, header => header.Value, StringComparer.OrdinalIgnoreCase);
            headers[Headers.Principal] = [Convert.ToBase64String(Encoding.UTF8.GetBytes(principal.ToJsonString()))];
            Assert.False(Verify(Observation(observed) with { Headers = headers }));
        }
    }
}
