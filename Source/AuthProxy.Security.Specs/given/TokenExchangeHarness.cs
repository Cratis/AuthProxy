// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Cratis.AuthProxy.BearerRoutes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Cratis.AuthProxy.Security.given;

/// <summary>A real bearer pipeline whose only exchange destination is an in-memory Identity endpoint.</summary>
public sealed class TokenExchangeHarness : AddressedBearerRouteHarness
{
    /// <summary>The configured external issuer, not accepted by the local JWT validator.</summary>
    public const string ExternalIssuer = "https://external.example";

    bool _exchangeEnabled = true;

    /// <summary>Removes exchange configuration on the next options-monitor reload.</summary>
    public void DisableExchange()
    {
        _exchangeEnabled = false;
        ((IConfigurationRoot)Services.GetRequiredService<IConfiguration>()).Reload();
    }

    /// <summary>Gets or sets the Identity response factory.</summary>
    public Func<string> Result { get; set; }

    /// <summary>Gets or sets the HTTP status returned by Identity.</summary>
    public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;

    /// <summary>Gets the count of exchange calls.</summary>
    public int Calls { get; private set; }

    /// <summary>Gets the last exchange form.</summary>
    public string Form { get; private set; } = string.Empty;

    /// <summary>Gets all proxy log messages, including exception text if present.</summary>
    public ConcurrentQueue<string> Logs { get; } = new();

    /// <summary>Initializes the harness with a signed tenant-bound Identity response.</summary>
    public TokenExchangeHarness() => Result = () => Exchanged();

    /// <summary>Creates a signed external presentation, whose tenant has no authority to select the exchange target.</summary>
    /// <returns>The subject token.</returns>
    public string Subject() => Issuer.Token(new StubIssuer.TokenRequest { Issuer = ExternalIssuer, Claims = new Dictionary<string, object> { ["tenant_id"] = "subject-tenant", ["sub"] = "external-subject" } });

    /// <summary>Creates a signed exchange result.</summary>
    /// <param name="audience">The resulting audience.</param>
    /// <param name="tenant">The resulting tenant.</param>
    /// <param name="idp">The resulting idp.</param>
    /// <param name="scope">The resulting scopes.</param>
    /// <returns>A signed JWT.</returns>
    public string Exchanged(string audience = "direct-mcp", string tenant = "tenant-a", string idp = ExternalIssuer, string scope = "direct-mcp:read") => Issuer.Token(new StubIssuer.TokenRequest
    {
        Audience = audience,
        Claims = new Dictionary<string, object> { ["tid"] = tenant, ["idp"] = idp, ["scope"] = scope, ["env"] = "staging", ["sub"] = "identity-subject" },
        Expires = DateTime.UtcNow.AddMinutes(5),
    });

    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        base.AddSettings(settings);
        const string route = $"{C.AuthProxy.SectionKey}:Services:app:BearerRoutes:0";
        settings[$"{route}:Audiences:0"] = "direct-mcp";
        settings[$"{route}:TenantClaimType"] = C.BearerRoute.DefaultTenantClaimType;
        settings[$"{route}:RequiredScopes:0"] = "direct-mcp:read";
        settings[$"{route}:ForwardAuthorizationHeader"] = "true";
        settings[$"{route}:TokenExchange:Endpoint"] = "https://identity.example/connect/token";
        settings[$"{route}:TokenExchange:ClientId"] = "synthetic-client";
        settings[$"{route}:TokenExchange:ClientSecret"] = string.Concat("synthetic-", "not-a-credential");
        settings[$"{route}:TokenExchange:Resource"] = "https://cratis.direct/mcp";
        settings[$"{route}:TokenExchange:Audience"] = "direct-mcp";
        settings[$"{route}:TokenExchange:Scopes:0"] = "direct-mcp:read";
        settings[$"{route}:TokenExchange:ResultIssuer"] = Issuer.Issuer;
        settings[$"{route}:TokenExchange:Issuers:0:Issuer"] = ExternalIssuer;
    }

    /// <inheritdoc/>
    protected override void ConfigureHost(IWebHostBuilder builder)
    {
        builder.ConfigureLogging(logging => logging.AddProvider(new LogProvider(Logs)));
        builder.ConfigureTestServices(services =>
        {
            services.PostConfigure<C.AuthProxy>(configuration =>
            {
                if (!_exchangeEnabled) configuration.Services["app"].BearerRoutes[0].TokenExchange = null;
            });
            services.AddHttpClient(BearerRouteDefaults.TokenExchangeHttpClientName)
                .ConfigurePrimaryHttpMessageHandler(() => new Handler(this));
        });
    }

    sealed class LogProvider(ConcurrentQueue<string> messages) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new CapturedLog(messages);
        public void Dispose() { }
    }

    sealed class CapturedLog(ConcurrentQueue<string> messages) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            messages.Enqueue(formatter(state, exception) + exception);
    }

    sealed class Handler(TokenExchangeHarness harness) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.Equal("https://identity.example/connect/token", request.RequestUri!.AbsoluteUri);
            harness.Calls++;
            harness.Form = await request.Content!.ReadAsStringAsync(cancellationToken);
            var body = harness.Status == HttpStatusCode.OK
                ? JsonSerializer.Serialize(new { access_token = harness.Result(), token_type = "Bearer", expires_in = 300, issued_token_type = "urn:ietf:params:oauth:token-type:access_token" })
                : "{\"error\":\"invalid_grant\"}";
            return new(harness.Status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        }
    }
}
