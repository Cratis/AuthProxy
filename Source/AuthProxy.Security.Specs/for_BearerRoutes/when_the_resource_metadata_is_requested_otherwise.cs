// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// The protected-resource metadata path is the one path of a bearer route served without a token, so it is exactly
/// that path and nothing more: read with <c language="text">GET</c> or <c language="text">HEAD</c>, matched case-insensitively and
/// with or without a trailing separator, and every other method refused with <c language="text">405</c> without reaching
/// the backend. Nothing beneath the path is served without a session.
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_the_resource_metadata_is_requested_otherwise(BearerRouteHarness harness) : IAsyncLifetime
{
    const string UpperCasePath = "/.WELL-KNOWN/oauth-protected-resource/MCP";
    const string BeneathPath = $"{BearerRouteHarness.ResourceMetadataPath}/beneath";

    HttpResponseMessage? _head;
    HttpResponseMessage? _put;
    HttpResponseMessage? _delete;
    HttpResponseMessage? _options;
    HttpResponseMessage? _upperCase;
    HttpResponseMessage? _trailingSeparator;
    HttpResponseMessage? _beneath;
    bool _headForwarded;
    bool _writesForwarded;
    bool _beneathForwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        _head = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, BearerRouteHarness.ResourceMetadataPath));
        _headForwarded = harness.Origin.ReceivedAnythingFor(BearerRouteHarness.ResourceMetadataPath);

        harness.Origin.Clear();
        _put = await client.SendAsync(new HttpRequestMessage(HttpMethod.Put, BearerRouteHarness.ResourceMetadataPath));
        _delete = await client.SendAsync(new HttpRequestMessage(HttpMethod.Delete, BearerRouteHarness.ResourceMetadataPath));
        _options = await client.SendAsync(new HttpRequestMessage(HttpMethod.Options, BearerRouteHarness.ResourceMetadataPath));
        _writesForwarded = harness.Origin.ReceivedAnythingFor(BearerRouteHarness.ResourceMetadataPath);

        _upperCase = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, UpperCasePath));
        _trailingSeparator = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, $"{BearerRouteHarness.ResourceMetadataPath}/"));

        _beneath = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, BeneathPath));
        _beneathForwarded = harness.Origin.ReceivedAnythingFor(BeneathPath);
    }

    public Task DisposeAsync()
    {
        _head?.Dispose();
        _put?.Dispose();
        _delete?.Dispose();
        _options?.Dispose();
        _upperCase?.Dispose();
        _trailingSeparator?.Dispose();
        _beneath?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_serve_head() => Assert.Equal(HttpStatusCode.OK, _head!.StatusCode);
    [Fact] public void should_forward_head() => Assert.True(_headForwarded);
    [Fact] public void should_refuse_put() => Assert.Equal(HttpStatusCode.MethodNotAllowed, _put!.StatusCode);
    [Fact] public void should_refuse_delete() => Assert.Equal(HttpStatusCode.MethodNotAllowed, _delete!.StatusCode);
    [Fact] public void should_refuse_options() => Assert.Equal(HttpStatusCode.MethodNotAllowed, _options!.StatusCode);
    [Fact] public void should_name_the_methods_it_allows() => Assert.Equal("GET, HEAD", _put!.Content.Headers.Allow.Count > 0 ? string.Join(", ", _put.Content.Headers.Allow) : string.Empty);
    [Fact] public void should_not_cache_put_refusals() => Assert.True(_put!.Headers.CacheControl?.NoStore);
    [Fact] public void should_not_cache_delete_refusals() => Assert.True(_delete!.Headers.CacheControl?.NoStore);
    [Fact] public void should_not_cache_options_refusals() => Assert.True(_options!.Headers.CacheControl?.NoStore);
    [Fact] public void should_not_forward_other_methods() => Assert.False(_writesForwarded);
    [Fact] public void should_match_case_insensitively() => Assert.Equal(HttpStatusCode.OK, _upperCase!.StatusCode);
    [Fact] public void should_match_with_a_trailing_separator() => Assert.Equal(HttpStatusCode.OK, _trailingSeparator!.StatusCode);
    [Fact] public void should_not_serve_anything_beneath_it_without_a_session() => Assert.False(_beneathForwarded);
    [Fact] public void should_not_answer_beneath_it_with_success() => Assert.NotEqual(HttpStatusCode.OK, _beneath!.StatusCode);
}
