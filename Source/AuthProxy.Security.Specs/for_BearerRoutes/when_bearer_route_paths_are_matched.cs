// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http;

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A bearer route covers its prefix case-insensitively and on segment boundaries only: <c language="text">/mcpx</c> and
/// <c language="text">/api/mcp</c> are not <c language="text">/mcp</c>, so a token presented there is refused as off its routes. A
/// path that a backend could decode or normalize into some other path — an encoded separator, any
/// other remaining percent-encoding, a backslash, a dot segment, a path parameter (<c language="text">;</c>), which
/// Tomcat, Jetty and Spring strip before resolving the dot segment it hides in — is refused before the token is looked at, because
/// the principal forwarded with it would be vouched for at a path that is not a bearer route.
/// <para>
/// Paths are set on the server-side request directly, as the server would hand them to the gate after decoding;
/// an <see cref="HttpClient"/> would normalize some of them away first.
/// </para>
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_bearer_route_paths_are_matched(BearerRouteHarness harness) : IAsyncLifetime
{
    HttpContext? _upperCase;
    HttpContext? _exactPrefix;
    HttpContext? _trailingSeparator;
    HttpContext? _longerSegment;
    HttpContext? _nestedUnderAnotherPath;
    HttpContext? _encodedSeparator;
    HttpContext? _doubleEncodedDot;
    HttpContext? _dotSegment;
    HttpContext? _backslash;
    HttpContext? _backslashAfterThePrefix;
    HttpContext? _parentSegmentWithPathParameter;
    HttpContext? _currentSegmentWithPathParameter;
    HttpContext? _pathParameterOnAnOrdinarySegment;

    public async Task InitializeAsync()
    {
        harness.Origin.Clear();

        _upperCase = await Send("/MCP/upper-case");
        _exactPrefix = await Send(BearerRouteHarness.RoutePrefix);
        _trailingSeparator = await Send($"{BearerRouteHarness.RoutePrefix}/");
        _longerSegment = await Send("/mcpx/tools");
        _nestedUnderAnotherPath = await Send("/api/mcp/tools");
        _encodedSeparator = await Send("/mcp/..%2Fapi/items");
        _doubleEncodedDot = await Send("/mcp/%2E%2E/api/items");
        _dotSegment = await Send("/mcp/../api/items");
        _backslash = await Send("/mcp/tools\\..\\..\\api\\items");
        _backslashAfterThePrefix = await Send("/mcp\\..\\api\\items");
        _parentSegmentWithPathParameter = await Send("/mcp/..;/api/items");
        _currentSegmentWithPathParameter = await Send("/mcp/.;/x");
        _pathParameterOnAnOrdinarySegment = await Send("/mcp/tools;jsessionid=abc");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_match_the_prefix_case_insensitively() => Assert.Equal(StatusCodes.Status200OK, _upperCase!.Response.StatusCode);
    [Fact] public void should_forward_the_case_insensitive_match() => Assert.True(harness.Origin.ReceivedAnythingFor("/MCP/upper-case"));
    [Fact] public void should_match_the_prefix_itself() => Assert.Equal(StatusCodes.Status200OK, _exactPrefix!.Response.StatusCode);
    [Fact] public void should_match_the_prefix_with_a_trailing_separator() => Assert.Equal(StatusCodes.Status200OK, _trailingSeparator!.Response.StatusCode);
    [Fact] public void should_not_match_a_longer_segment() => Assert.Equal(StatusCodes.Status401Unauthorized, _longerSegment!.Response.StatusCode);
    [Fact] public void should_refuse_the_token_off_its_routes_on_a_longer_segment() => Assert.Equal("Bearer error=\"invalid_token\"", _longerSegment!.Response.Headers.WWWAuthenticate.ToString());
    [Fact] public void should_not_match_the_prefix_under_another_path() => Assert.Equal(StatusCodes.Status401Unauthorized, _nestedUnderAnotherPath!.Response.StatusCode);
    [Fact] public void should_refuse_an_encoded_separator() => Assert.Equal(StatusCodes.Status400BadRequest, _encodedSeparator!.Response.StatusCode);
    [Fact] public void should_not_let_the_refusal_be_cached() => Assert.Equal("no-store", _encodedSeparator!.Response.Headers.CacheControl.ToString());
    [Fact] public void should_refuse_without_a_challenge() => Assert.False(_encodedSeparator!.Response.Headers.ContainsKey("WWW-Authenticate"));
    [Fact] public void should_refuse_remaining_percent_encoding() => Assert.Equal(StatusCodes.Status400BadRequest, _doubleEncodedDot!.Response.StatusCode);
    [Fact] public void should_refuse_a_dot_segment() => Assert.Equal(StatusCodes.Status400BadRequest, _dotSegment!.Response.StatusCode);
    [Fact] public void should_refuse_a_backslash() => Assert.Equal(StatusCodes.Status400BadRequest, _backslash!.Response.StatusCode);
    [Fact] public void should_refuse_a_backslash_before_matching_the_prefix() => Assert.Equal(StatusCodes.Status400BadRequest, _backslashAfterThePrefix!.Response.StatusCode);
    [Fact] public void should_refuse_a_parent_segment_hidden_by_a_path_parameter() => Assert.Equal(StatusCodes.Status400BadRequest, _parentSegmentWithPathParameter!.Response.StatusCode);
    [Fact] public void should_refuse_a_current_segment_hidden_by_a_path_parameter() => Assert.Equal(StatusCodes.Status400BadRequest, _currentSegmentWithPathParameter!.Response.StatusCode);
    [Fact] public void should_refuse_a_path_parameter_on_any_segment() => Assert.Equal(StatusCodes.Status400BadRequest, _pathParameterOnAnOrdinarySegment!.Response.StatusCode);
    [Fact] public void should_forward_none_of_the_path_parameter_paths() => Assert.DoesNotContain(harness.Origin.Received, _ => _.Path.Contains(';', StringComparison.Ordinal));
    [Fact] public void should_forward_none_of_the_refused_paths() => Assert.DoesNotContain(harness.Origin.Received, _ => _.Path.Contains("api", StringComparison.OrdinalIgnoreCase) || _.Path.Contains("mcpx", StringComparison.OrdinalIgnoreCase));

    Task<HttpContext> Send(string path)
    {
        var token = harness.Issuer.Token();
        return harness.Server.SendAsync(context =>
        {
            context.Request.Method = HttpMethods.Get;
            context.Request.Path = new PathString(path);
            context.Request.Headers.Authorization = $"Bearer {token}";
        });
    }
}
