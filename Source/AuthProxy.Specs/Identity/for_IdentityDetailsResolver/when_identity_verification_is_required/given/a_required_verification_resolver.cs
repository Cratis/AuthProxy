// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required.given;

/// <summary>
/// Provides a resolver for a deployment whose one service answers <c>/.cratis/me</c> with an authorization
/// verdict, plus a scriptable identity endpoint to answer with.
/// </summary>
/// <remarks>
/// Everything is built here and left mutable so a spec states only the one thing it is about: the endpoint's
/// answer through <see cref="_handler"/>, and the deployment's settings through <see cref="_config"/>. The
/// options monitor hands out the same configuration instance every time it is read, so a spec changing a
/// setting in its own setup changes what the resolver reads.
/// <para>
/// The client factory returns a fresh client per call because the resolver disposes what it is handed, as a
/// consumer of a client factory should. A single shared instance would be disposed after the first service
/// and every later call would fail for a reason no spec here is about.
/// </para>
/// </remarks>
public class a_required_verification_resolver : Specification
{
    /// <summary>The tenant every request in these specs acts in.</summary>
    protected const string TenantId = "tenant-a";

    /// <summary>The body a service answers when it verifies the caller.</summary>
    protected const string PositiveBody = /*lang=json,strict*/
        "{\"isAuthenticated\":true,\"isAuthorized\":true,\"details\":{\"displayName\":\"John Doe\"}}";

    /// <summary>The body a service answers when it refuses the caller in a well-formed way.</summary>
    protected const string NegativeBody = /*lang=json,strict*/
        "{\"isAuthenticated\":true,\"isAuthorized\":false,\"details\":{}}";

    protected ScriptedIdentityHandler _handler;
    protected C.AuthProxy _config;
    protected C.Service _service;
    protected IIdentityAuthorizationCache _authorizationCache;
    protected IMemoryCache _memoryCache;
    protected IdentityDetailsResolver _resolver;
    protected DefaultHttpContext _context;

    void Establish()
    {
        _handler = new ScriptedIdentityHandler();
        _service = new C.Service
        {
            Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" },
            IdentityVerification = C.IdentityVerificationMode.Required
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
        _memoryCache = new MemoryCache(new MemoryCacheOptions());
        _resolver = new IdentityDetailsResolver(
            configuration,
            clients,
            [],
            _memoryCache,
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
    /// Answers the identity endpoint however a spec tells it to, and counts what it was asked.
    /// </summary>
    protected sealed class ScriptedIdentityHandler : HttpMessageHandler
    {
        int _calls;

        /// <summary>
        /// Gets the number of identity endpoint requests received.
        /// </summary>
        public int Calls => _calls;

        /// <summary>
        /// Gets or sets what to answer, given the request and the one-based number of the call.
        /// </summary>
        public Func<HttpRequestMessage, int, CancellationToken, Task<HttpResponseMessage>> Respond { get; set; } =
            (_, _, _) => Task.FromResult(Response(HttpStatusCode.OK, PositiveBody));

        /// <inheritdoc/>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Respond(request, Interlocked.Increment(ref _calls), cancellationToken);
    }
}
