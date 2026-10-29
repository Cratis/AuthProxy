// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ForwardingPaths;

/// <summary>Method scopes do not imply OPTIONS and cannot be evaded with an override header.</summary>
/// <param name="harness">The running proxy and recording origins.</param>
[Collection(ForwardingPathSpecCollection.Name)]
public class when_methods_are_scoped(ForwardingPathHarness harness)
{
    [Theory]
    [InlineData("GET", "/api/report", false)]
    [InlineData("HEAD", "/api/report", false)]
    [InlineData("DELETE", "/api/items", false)]
    [InlineData("POST", "/api/items", true)]
    public async Task should_not_contact_the_origin(string method, string target, bool overrideMethod)
    {
        harness.ClearOrigins();
        (string, string)[] headers = overrideMethod ? [("X-HTTP-Method-Override", "DELETE")] : [];
        var status = await harness.Raw(method, target, ForwardingPathHarness.PortalHost, authenticated: true, headers);
        Assert.Equal(HttpStatusCode.NotFound, status);
        harness.AssertNoOrigins();
    }

    [Theory]
    [InlineData("POST", "/api/report")]
    [InlineData("OPTIONS", "/api/report")]
    [InlineData("GET", "/api/items")]
    public async Task should_forward_a_method_not_denied(string method, string target)
    {
        harness.ClearOrigins();
        var status = await harness.Raw(method, target, ForwardingPathHarness.PortalHost, authenticated: true);
        Assert.Equal(HttpStatusCode.OK, status);
        harness.AssertOnlyOrigin(harness.Portal, target);
    }
}
