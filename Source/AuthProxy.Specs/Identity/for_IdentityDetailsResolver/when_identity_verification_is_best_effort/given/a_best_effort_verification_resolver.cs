// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text.Json.Nodes;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_best_effort.given;

/// <summary>
/// Provides a resolver for the deployment every existing installation already is: one service with a
/// backend, asked for identity details, with no opinion stated about what its answer is worth.
/// </summary>
/// <remarks>
/// The mode is deliberately not written down. These specs exist to pin what an <em>unchanged</em>
/// configuration does, and a configuration that names the mode is a different deployment from the one at
/// risk of having its meaning changed underneath it.
/// </remarks>
public class a_best_effort_verification_resolver : Specification
{
    /// <summary>The tenant every request in these specs acts in.</summary>
    protected const string TenantId = "tenant-a";

    /// <summary>The detail a service supplies alongside whatever verdict it states.</summary>
    protected const string DetailName = "onboarding";

    /// <summary>The value of that detail.</summary>
    protected const string DetailValue = "pending";

    /// <summary>
    /// The envelope a service answers when it states the caller is authenticated but not authorized. This is
    /// the exact shape <c>IdentityProviderResult</c> serializes, so it is what a service reaching for the
    /// documented response type writes.
    /// </summary>
    protected const string NegativeBody = /*lang=json,strict*/
        "{\"isAuthenticated\":true,\"isAuthorized\":false,\"details\":{\"onboarding\":\"pending\"}}";

    /// <summary>The envelope a service answers when its two verdicts contradict each other.</summary>
    protected const string ConflictingBody = /*lang=json,strict*/
        "{\"isAuthenticated\":false,\"isAuthorized\":true,\"details\":{\"onboarding\":\"pending\"}}";

    protected ScriptedIdentityHandler _handler;
    protected C.AuthProxy _config;
    protected C.Service _service;
    protected IIdentityAuthorizationCache _authorizationCache;
    protected IdentityDetailsResolver _resolver;
    protected DefaultHttpContext _context;

    void Establish()
    {
        _handler = new ScriptedIdentityHandler();
        _service = new C.Service
        {
            Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" }
        };
        _config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service> { ["main"] = _service }
        };

        var configuration = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        configuration.CurrentValue.Returns(_ => _config);

        var clients = Substitute.For<IHttpClientFactory>();
        clients.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(_handler, disposeHandler: false));

        _authorizationCache = Substitute.For<IIdentityAuthorizationCache>();
        _resolver = new IdentityDetailsResolver(
            configuration,
            clients,
            [],
            new MemoryCache(new MemoryCacheOptions()),
            _authorizationCache,
            Substitute.For<ILogger<IdentityDetailsResolver>>());
        _context = new DefaultHttpContext();
    }

    /// <summary>
    /// Builds a response the scripted handler can answer with.
    /// </summary>
    /// <param name="statusCode">The status code to answer.</param>
    /// <param name="body">The body to answer.</param>
    /// <returns>The response.</returns>
    protected static HttpResponseMessage Response(HttpStatusCode statusCode, string body = "") =>
        new(statusCode) { Content = new StringContent(body) };

    /// <summary>
    /// Builds the principal these specs act as.
    /// </summary>
    /// <param name="userId">The user identifier, defaulted so most specs need not name one.</param>
    /// <returns>The principal.</returns>
    protected static ClientPrincipal Principal(string userId = "user-1") => new() { UserId = userId };

    /// <summary>
    /// Reads a merged detail back off a resolved result.
    /// </summary>
    /// <param name="details">The details the resolver produced.</param>
    /// <param name="name">The property to read.</param>
    /// <returns>The value, or an empty string when the property is not there.</returns>
    protected static string Detail(object? details, string name) =>
        details is JsonObject merged && merged[name] is JsonValue value ? value.GetValue<string>() : string.Empty;

    /// <summary>
    /// Answers the identity endpoint however a spec tells it to.
    /// </summary>
    protected sealed class ScriptedIdentityHandler : HttpMessageHandler
    {
        /// <summary>
        /// Gets or sets what to answer, given the request.
        /// </summary>
        public Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Respond { get; set; } =
            (_, _) => Task.FromResult(Response(HttpStatusCode.OK, "{}"));

        /// <inheritdoc/>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Respond(request, cancellationToken);
    }
}
