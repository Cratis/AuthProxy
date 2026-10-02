// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A stripped browser prefix must not create cookie-authenticated access to a bearer-only backend resource.
/// Bearer prefixes also cannot shadow another service's browser prefix, regardless of host restrictions.
/// </summary>
public class when_a_bearer_route_has_a_browser_prefix_alias
{
    [Fact]
    public void should_refuse_a_service_whose_browser_prefix_would_be_stripped()
    {
        using var harness = new StrippedPrefixHarness();
        var error = Assert.Throws<OptionsValidationException>(() => harness.CreateBearerClient().Dispose());

        Assert.Contains(nameof(C.Service.StripPathPrefix), error.Message, StringComparison.Ordinal);
        Assert.Empty(harness.Origin.Received);
    }

    [Theory]
    [InlineData("/MCP", "/mcp")]
    [InlineData("/mcp/tools", "/mcp")]
    [InlineData(" /mcp/ ", "/mcp")]
    [InlineData("/app", "/app/mcp")]
    public void should_refuse_overlap_with_another_services_prefix(string otherPrefix, string bearerPrefix)
    {
        using var harness = new OverlappingPrefixHarness(otherPrefix, bearerPrefix);
        var error = Assert.Throws<OptionsValidationException>(() => harness.CreateBearerClient().Dispose());

        Assert.Contains("overlaps service 'other' PathPrefix", error.Message, StringComparison.Ordinal);
        Assert.Empty(harness.Origin.Received);
    }

    [Fact]
    public void should_allow_distinct_segments()
    {
        using var harness = new OverlappingPrefixHarness("/mcpx", BearerRouteHarness.RoutePrefix);
        using var client = harness.CreateBearerClient();
    }

    sealed class StrippedPrefixHarness : BearerRouteHarness
    {
        protected override void AddSettings(IDictionary<string, string?> settings)
        {
            settings[$"{C.AuthProxy.SectionKey}:Services:app:PathPrefix"] = "/app";
            settings[$"{C.AuthProxy.SectionKey}:Services:app:StripPathPrefix"] = "true";
            settings[$"{C.AuthProxy.SectionKey}:Services:app:BearerRoutes:0:PathPrefix"] = "/api/mcp";
        }
    }

    sealed class OverlappingPrefixHarness(string otherPrefix, string bearerPrefix) : BearerRouteHarness
    {
        protected override void AddSettings(IDictionary<string, string?> settings)
        {
            settings[$"{C.AuthProxy.SectionKey}:Services:app:Hosts:0"] = "app.example.test";
            settings[$"{C.AuthProxy.SectionKey}:Services:app:BearerRoutes:0:PathPrefix"] = bearerPrefix;
            settings[$"{C.AuthProxy.SectionKey}:Services:other:Hosts:0"] = "other.example.test";
            settings[$"{C.AuthProxy.SectionKey}:Services:other:PathPrefix"] = otherPrefix;
            settings[$"{C.AuthProxy.SectionKey}:Services:other:Backend:BaseUrl"] = Origin.BaseUrl;
            settings[$"{C.AuthProxy.SectionKey}:Services:other:ResolveIdentityDetails"] = "false";
        }
    }
}
