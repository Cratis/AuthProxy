// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ForwardingPaths;

/// <summary>Anonymous declarations do not widen forwarding, and missing sessions still use today's refusal.</summary>
/// <param name="harness">The running proxy and recording origins.</param>
[Collection(ForwardingPathSpecCollection.Name)]
public class when_an_anonymous_path_is_not_forwarded(ForwardingPathHarness harness)
{
    [Fact]
    public async Task should_not_contact_the_origin_for_an_anonymous_but_unlisted_path()
    {
        harness.ClearOrigins();
        var status = await harness.Raw("GET", "/reports/api/hook", "localhost", authenticated: false);
        Assert.Equal(HttpStatusCode.NotFound, status);
        harness.AssertNoOrigins();
    }

    [Fact]
    public async Task should_forward_an_allowed_anonymous_path()
    {
        harness.ClearOrigins();
        var status = await harness.Raw("GET", "/reports/api/health", "localhost", authenticated: false);
        Assert.Equal(HttpStatusCode.OK, status);
        harness.AssertOnlyOrigin(harness.Reports, "/api/health");
    }

    [Fact]
    public async Task should_not_reveal_the_policy_to_a_caller_without_a_session()
    {
        harness.ClearOrigins();
        var status = await harness.Raw("GET", "/reports/api/other", "localhost", authenticated: false, ("Accept", "application/json"));
        Assert.Equal(HttpStatusCode.Unauthorized, status);
        harness.AssertNoOrigins();
    }
}
