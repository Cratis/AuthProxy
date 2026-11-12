// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Nodes;

namespace Cratis.AuthProxy.Security.for_SessionContextForwarding.given;

public class a_session_context
{
    protected static JsonArray Claims(ForwardedRequest request) => JsonNode.Parse(Convert.FromBase64String(request.Value(Headers.Principal)))!["claims"]!.AsArray();
    protected static string Value(ForwardedRequest request, string type) => Claims(request).Single(claim => claim!["typ"]!.GetValue<string>() == type)!["val"]!.GetValue<string>();
    protected static ForwardedIdentityObservation Observation(ForwardedRequest request) => new(request.Method, request.Path + request.QueryString, request.Headers.ToDictionary(header => header.Key, header => new[] { header.Value }, StringComparer.OrdinalIgnoreCase), false);
    protected static bool Verify(ForwardedIdentityObservation request) => ForwardedIdentityVerifier.Verify(request, SessionContextHarness.Audience, SessionContextHarness.KeyId, SessionContextHarness.Key);

    protected static async Task RejectSpoof(string type, string suffix)
    {
        await using var harness = new SessionContextHarness();
        var cookie = await harness.SignIn(hostileClaim: type);
        using var client = harness.CreateBearerClient();
        using var request = SessionContextHarness.Request(cookie);
        request.Headers.Add(Headers.Principal, Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($$"""{"claims":[{"typ":"{{type}}","val":"caller-forged"}]}""")));
        request.Headers.Add("x-ms-client-principal-" + suffix, "caller-forged");
        request.Headers.Add(HeaderAuthenticationHandler.ClaimsHeader, type + "=caller-forged");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var observed = harness.Observed();
        Assert.NotEqual("caller-forged", Value(observed, type));
        Assert.DoesNotContain("caller-forged", System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(observed.Value(Headers.Principal))), StringComparison.Ordinal);
        Assert.False(observed.Has("x-ms-client-principal-" + suffix));
        Assert.True(Verify(Observation(observed)));
    }

    protected static async Task<ForwardedRequest> Forward(SessionContextHarness harness, string cookie)
    {
        using var client = harness.CreateBearerClient();
        using var request = SessionContextHarness.Request(cookie);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return harness.Observed();
    }
}
