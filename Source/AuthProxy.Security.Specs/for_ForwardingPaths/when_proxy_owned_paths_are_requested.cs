// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ForwardingPaths;

/// <summary>A service policy does not intercept paths answered by AuthProxy itself.</summary>
/// <param name="harness">The running proxy and recording origins.</param>
[Collection(ForwardingPathSpecCollection.Name)]
public class when_proxy_owned_paths_are_requested(ForwardingPathHarness harness)
{
    [Fact]
    public async Task should_answer_without_contacting_any_origin()
    {
        harness.ClearOrigins();
        var status = await harness.Raw("GET", "/.cratis/providers", ForwardingPathHarness.PortalHost, authenticated: false);
        Assert.Equal(HttpStatusCode.OK, status);
        harness.AssertNoOrigins();
    }
}
