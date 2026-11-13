// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;
using System.Text;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.for_StudioMcpProof.given;

/// <summary>
/// The MCP proxy configured from the environment the deployment emits, in front of a recording origin.
/// </summary>
public class StudioMcpProxy : WebApplicationFactory<Program>
{
    public const string McpDomain = "mcp.cratis.studio";
    public const string ResourceMetadataUrl = $"https://{McpDomain}/.well-known/oauth-protected-resource/mcp";
    public const string Audience = "studio-mcp";
    public const string Scope = "studio:mcp:read";
    public const string EmittedIssuer = "https://issuer.local.test/";
    public const string VerificationUrl = "http://core/api/internal/mcp/client-credentials/verify";
    public const string OrganizationTenant = "33333333-3333-3333-3333-333333333333";

    // Copied verbatim from the emitted environment list. Placeholders are substituted in Settings().
    static readonly string[] _emittedServiceEnvironment =
    [
        "Cratis__AuthProxy__Services__mcp__Backend__BaseUrl=<McpDeployment.BackendUrl>",
        "Cratis__AuthProxy__Services__mcp__Frontend__BaseUrl=<McpDeployment.BackendUrl>",
        "Cratis__AuthProxy__Services__mcp__IdentityVerification=Required",
        "Cratis__AuthProxy__Services__mcp__ResolveIdentityDetails=false",
        "Cratis__AuthProxy__Services__mcp__ClientCredentials__RoutePrefix=/mcp",
        $"Cratis__AuthProxy__Services__mcp__ClientCredentials__VerificationPath={VerificationUrl}",
        "Cratis__AuthProxy__Services__mcp__AnonymousPaths__0=/.well-known/oauth-protected-resource",
    ];

    static readonly string[] _emittedBearerRouteEnvironment =
    [
        "Cratis__AuthProxy__Services__mcp__BearerRoutes__0__PathPrefix=/mcp",
        $"Cratis__AuthProxy__Services__mcp__BearerRoutes__0__Issuers__0__Issuer={EmittedIssuer}",
        "Cratis__AuthProxy__Services__mcp__BearerRoutes__0__Audiences__0=studio-mcp",
        "Cratis__AuthProxy__Services__mcp__BearerRoutes__0__RequiredScopes__0=studio:mcp:read",
        "Cratis__AuthProxy__Services__mcp__BearerRoutes__0__ResourceMetadataUrl=https://<mcpDomain>/.well-known/oauth-protected-resource/mcp",
        "Cratis__AuthProxy__Services__mcp__BearerRoutes__0__TenantClaimType=tid",
        "Cratis__AuthProxy__Services__mcp__BearerRoutes__0__IdentityProvider=cratis-id",
        "Cratis__AuthProxy__Services__mcp__BearerRoutes__0__AcceptWithoutIdentityVerification=true",
    ];

    // Deployment-wide, non-secret values the same deployment emits for every proxy it builds.
    static readonly string[] _emittedDeploymentEnvironment =
    [
        "Cratis__AuthProxy__Session__SlidingExpiration=true",
        "Cratis__AuthProxy__Logout__AdditionalCookies__0__Name=_oauth2_proxy_admin",
        "Cratis__AuthProxy__Logout__AdditionalCookies__0__Domain=.cratis.studio",
        "Cratis__AuthProxy__SearchIndexing__Exclude=true",
    ];

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
    readonly string _keysPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
    readonly bool _withBearerRoute;

    public StudioMcpProxy() : this(true)
    {
    }

    protected StudioMcpProxy(bool withBearerRoute)
    {
        _withBearerRoute = withBearerRoute;
        Directory.CreateDirectory(_pagesPath);
        Directory.CreateDirectory(_keysPath);
        File.WriteAllText(Path.Combine(_pagesPath, "select-provider.html"), "<html><body>Select Provider</body></html>");
        File.WriteAllText(Path.Combine(_pagesPath, "forbidden.html"), "<html><body>Forbidden</body></html>");

        Origin = RecordingBackend.Start().GetAwaiter().GetResult();
        Issuer = StubIssuer.Start().GetAwaiter().GetResult();
    }

    public RecordingBackend Origin { get; }

    public StubIssuer Issuer { get; }

    public CoreVerifier Verifier { get; } = new();

    public IReadOnlyDictionary<string, string?> AppliedSettings { get; private set; } = new Dictionary<string, string?>();

    public static HttpRequestMessage McpCall(string? token)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(/*lang=json,strict*/ """{"jsonrpc":"2.0","id":1,"method":"tools/list"}""", Encoding.UTF8, "application/json"),
        };
        if (token is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return request;
    }

    public HttpClient CreateMachineClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    public async Task<(HttpStatusCode Status, string? AccessToken)> Mint(HttpClient client)
    {
        using var response = await client.PostAsync(WellKnownPaths.Token, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "studio-mcp-client",
            ["client_secret"] = "local-proof-value",
        }));
        if (!response.IsSuccessStatusCode)
        {
            return (response.StatusCode, null);
        }

        using var body = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return (response.StatusCode, body.RootElement.GetProperty("access_token").GetString());
    }

    public string ExternalToken(IDictionary<string, object>? claims = null, string? issuer = null)
    {
        var merged = new Dictionary<string, object> { ["scope"] = Scope };
        foreach (var (key, value) in claims ?? new Dictionary<string, object>())
        {
            merged[key] = value;
        }

        return Issuer.Token(merged, Audience, issuer: issuer);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing)
        {
            return;
        }

        Origin.DisposeAsync().AsTask().GetAwaiter().GetResult();
        Issuer.DisposeAsync().AsTask().GetAwaiter().GetResult();
        foreach (var path in new[] { _pagesPath, _keysPath })
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        var settings = Settings();
        AppliedSettings = settings;
        builder
            .UseEnvironment("Production")
            .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(settings));

        builder.ConfigureTestServices(services => services
            .AddHttpClient(nameof(ClientCredentialsVerifier))
            .ConfigurePrimaryHttpMessageHandler(() => Verifier));
    }

    Dictionary<string, string?> Settings()
    {
        var lines = _emittedServiceEnvironment
            .Concat(_withBearerRoute ? _emittedBearerRouteEnvironment : [])
            .Concat(_emittedDeploymentEnvironment);

        var settings = new Dictionary<string, string?>();
        foreach (var line in lines)
        {
            var separator = line.IndexOf('=', StringComparison.Ordinal);
            var key = line[..separator].Replace("__", ":", StringComparison.Ordinal);
            var value = line[(separator + 1)..]
                .Replace("<McpDeployment.BackendUrl>", Origin.BaseUrl, StringComparison.Ordinal)
                .Replace("<mcpDomain>", McpDomain, StringComparison.Ordinal);

            // The one substitution of a real value: the issuer must be the loopback stub that signs the tokens.
            if (value == EmittedIssuer)
            {
                value = Issuer.Issuer;
            }

            settings[key] = value;
        }

        // Mounted in the cluster; local directories here.
        settings[$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath;
        settings[$"{C.AuthProxy.SectionKey}:DataProtectionKeysPath"] = _keysPath;

        return settings;
    }

    /// <summary>
    /// Stands in for Core's client-credentials verification endpoint at its in-cluster address.
    /// </summary>
    public sealed class CoreVerifier : HttpMessageHandler
    {
        int _calls;

        public int Calls => Volatile.Read(ref _calls);

        public Uri? LastUri { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            LastUri = request.RequestUri;
            var response = request.RequestUri?.AbsoluteUri == VerificationUrl
                ? new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent($$"""{"tenant":"{{OrganizationTenant}}"}""", Encoding.UTF8, "application/json"),
                }
                : new HttpResponseMessage(HttpStatusCode.NotFound);
            return Task.FromResult(response);
        }
    }
}

public class StudioMcpProxyWithoutIssuer : StudioMcpProxy
{
    public StudioMcpProxyWithoutIssuer() : base(false)
    {
    }
}

[CollectionDefinition(Name, DisableParallelization = true)]
public class StudioMcpProofCollection : ICollectionFixture<StudioMcpProxy>, ICollectionFixture<StudioMcpProxyWithoutIssuer>
{
    public const string Name = "StudioMcpProof";
}
