// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_CratisIdentityProfile.given;

/// <summary>
/// An AuthProxy with one Cratis Identity provider whose discovery document is served by a fake back channel, so the
/// profile runs against the standard OIDC contract without a running realm.
/// </summary>
public class a_cratis_identity_realm : Specification
{
    protected const string Scheme = "cratis-identity";
    protected const string Authority = "https://identity.cratis.example/realms/products";
    protected const string AuthorizationEndpoint = $"{Authority}/connect/authorize";
    protected const string EndSessionEndpoint = $"{Authority}/connect/endsession";
    protected const string ClientSecret = "configured-client-secret-value";

    protected ServiceProvider _services;
    protected RecordingLoggerProvider _logs;

    protected virtual string DiscoveredIssuer => Authority;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Cratis Identity",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Type"] = nameof(C.OidcProviderType.CratisIdentity),
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = Authority,
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "studio-web",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientSecret"] = ClientSecret,
        });

        _logs = new RecordingLoggerProvider();
        builder.Logging.ClearProviders();
        builder.Logging.SetMinimumLevel(LogLevel.Trace);
        builder.Logging.AddProvider(_logs);

        builder.Services.AddOptions<C.Authentication>().BindConfiguration(C.Authentication.SectionKey);
        builder.AddIngressAuthentication();
        builder.Services.Configure<OpenIdConnectOptions>(Scheme, options => options.BackchannelHttpHandler = new DiscoveryHandler(DiscoveredIssuer));

        _services = builder.Services.BuildServiceProvider();
    }

    void Destroy() => _services.Dispose();

    protected DefaultHttpContext NewContext() => new()
    {
        RequestServices = _services,
        Request = { Scheme = "https", Host = new HostString("studio.cratis.example"), Path = "/" },
        Response = { Body = new MemoryStream() },
    };

    sealed class DiscoveryHandler(string issuer) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri?.AbsoluteUri != $"{Authority}/.well-known/openid-configuration")
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }

            var document = JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["issuer"] = issuer,
                ["authorization_endpoint"] = AuthorizationEndpoint,
                ["token_endpoint"] = $"{Authority}/connect/token",
                ["end_session_endpoint"] = EndSessionEndpoint,
                ["response_types_supported"] = new[] { "code" },
                ["code_challenge_methods_supported"] = new[] { "S256" },
            });

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(document, Encoding.UTF8, "application/json"),
            });
        }
    }
}
