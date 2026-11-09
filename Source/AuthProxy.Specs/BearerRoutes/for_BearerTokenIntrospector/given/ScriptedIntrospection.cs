// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;
using Cratis.AuthProxy.BearerRoutes.Introspection;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerTokenIntrospector.given;

/// <summary>
/// An introspector over a scripted endpoint, recording what it was sent and what it logged.
/// </summary>
public sealed class ScriptedIntrospection : IHttpClientFactory
{
    public const string Token = "header.payload.signature";
    public const string Secret = "not-a-real-secret";
    public const string Subject = "account-1";
    public const string IssuerName = "https://auth.example.test/";

    readonly List<string> _logs = [];

    public ScriptedIntrospection(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond, TimeSpan? cacheDuration = null, TimeSpan? timeout = null)
    {
        Settings = new C.BearerIssuerIntrospection
        {
            Endpoint = "https://auth.example.test/connect/introspect",
            ClientId = "authproxy",
            ClientSecret = Secret,
            CacheDuration = cacheDuration ?? TimeSpan.FromSeconds(30),
            Timeout = timeout ?? TimeSpan.FromSeconds(2),
        };
        Issuer = new ResolvedBearerIssuer(IssuerName, "https://auth.example.test/.well-known/oauth-authorization-server", ["at+jwt"], true) { Introspection = Settings };
        Time = new ManualTimeProvider();
        Respond = respond;
        Introspector = new BearerTokenIntrospector(this, new IntrospectionCache(Time), Time, new RecordingLogger<BearerTokenIntrospector>(_logs));
    }

    public C.BearerIssuerIntrospection Settings { get; }

    public ResolvedBearerIssuer Issuer { get; }

    public ManualTimeProvider Time { get; }

    public BearerTokenIntrospector Introspector { get; }

    public Func<HttpRequestMessage, Task<HttpResponseMessage>> Respond { get; set; }

    public int Calls { get; private set; }

    public string? LastBody { get; private set; }

    public HttpRequestMessage? LastRequest { get; private set; }

    public string? LastAuthorization { get; private set; }

    public IReadOnlyList<string> Logs => _logs;

    public static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    public BearerTokenValidation Validated(long? expires = null)
    {
        var claims = new List<Claim>
        {
            new(BearerRouteClaims.Subject, Subject),
            new(BearerRouteClaims.Issuer, IssuerName),
            new(BearerRouteClaims.ClientId, "cratis-cli"),
            new("exp", (expires ?? Time.GetUtcNow().AddMinutes(15).ToUnixTimeSeconds()).ToString(System.Globalization.CultureInfo.InvariantCulture)),
        };
        return BearerTokenValidation.Success(new ClaimsPrincipal(new ClaimsIdentity(claims, "test")), "tenant", null) with { Issuer = Issuer };
    }

    public Task<IntrospectionVerdict> Introspect(string token = Token, long? expires = null, CancellationToken cancellationToken = default) =>
        Introspector.Introspect(token, Validated(expires), Issuer, cancellationToken);

    public HttpClient CreateClient(string name) => new(new Handler(this));

    sealed class Handler(ScriptedIntrospection owner) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            owner.Calls++;
            owner.LastRequest = request;
            owner.LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            owner.LastAuthorization = request.Headers.Authorization?.ToString();
            return await owner.Respond(request).WaitAsync(cancellationToken);
        }
    }

    sealed class RecordingLogger<T>(List<string> sink) : ILogger<T>
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            sink.Add(formatter(state, exception) + exception);
    }
}
