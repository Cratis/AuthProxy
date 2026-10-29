// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ForwardingPaths;

/// <summary>Literal, encoded and normalized attempts to reach hidden portal endpoints stay at the edge.</summary>
/// <param name="harness">The running proxy and recording origins.</param>
[Collection(ForwardingPathSpecCollection.Name)]
public class when_a_denied_path_is_requested(ForwardingPathHarness harness)
{
    [Theory]
    [InlineData("/openapi", false)]
    [InlineData("/OPENAPI", false)]
    [InlineData("/OpenApi/v1.json", false)]
    [InlineData("/openapi/", false)]
    [InlineData("//openapi", false)]
    [InlineData("/openapi//x", false)]
    [InlineData("/x/../openapi", false)]
    [InlineData("/x/%2e%2e/openapi", false)]
    [InlineData("/x/%2E%2E/openapi", false)]
    [InlineData("/x/%252e%252e/openapi", false)]
    [InlineData("/x%2fopenapi", false)]
    [InlineData("/x%2Fopenapi", false)]
    [InlineData("/x/..%2fopenapi", false)]
    [InlineData("/x\\..\\openapi", true)]
    [InlineData("/openapi;a=b", false)]
    [InlineData("/x/..;/openapi", false)]
    [InlineData("/openapi%00", true)]
    [InlineData("/%C0%AE%C0%AE/openapi", true)]
    [InlineData("/private.", false)]
    [InlineData("/private./x", false)]
    [InlineData("/private%20", false)]
    [InlineData("/private%09", false)]
    [InlineData("/private%EF%BC%8F", false)]
    [InlineData("/private%EF%BC%BC", false)]
    [InlineData("/pr%C4%B1vate", false)]
    [InlineData("/PRIVATE", false)]
    [InlineData("/.cratis/commands", false)]
    [InlineData("/.cratis/QUERIES/x", false)]
    public async Task should_not_contact_the_origin(string target, bool kestrelMayReject)
    {
        harness.ClearOrigins();
        var status = await harness.Raw("GET", target, ForwardingPathHarness.PortalHost, authenticated: true);
        if (kestrelMayReject)
        {
            Assert.True(status is HttpStatusCode.BadRequest or HttpStatusCode.NotFound, $"Unexpected status: {status}");
        }
        else
        {
            Assert.Equal(HttpStatusCode.NotFound, status);
        }
        harness.AssertNoOrigins();
    }

    [Theory]
    [InlineData("/openapix")]
    [InlineData("/.cratis/commandsx")]
    [InlineData("/api/other")]
    public async Task should_forward_a_distinct_segment(string target)
    {
        harness.ClearOrigins();
        var status = await harness.Raw("GET", target, ForwardingPathHarness.PortalHost, authenticated: true);
        Assert.Equal(HttpStatusCode.OK, status);
        harness.AssertOnlyOrigin(harness.Portal, target);
    }
}
