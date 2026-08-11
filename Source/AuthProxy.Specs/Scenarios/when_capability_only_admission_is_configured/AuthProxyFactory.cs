// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using Cratis.AuthProxy.Admission;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Scenarios.when_capability_only_admission_is_configured;

/// <summary>
/// A proxy that answers nothing until a capability admits — configured the way a closed deployment is, and
/// otherwise like every other deployment these scenarios describe: a real backend route, page assets,
/// bundled web assets, providers, and a tenant that always resolves.
/// <para>
/// Everything that could make a refusal distinguishable is deliberately present. A deployment with no
/// providers, no pages and no backend would refuse everything trivially and prove nothing.
/// </para>
/// </summary>
public class AuthProxyFactory : WebApplicationFactory<Program>
{
    public const string TenantId = "cccccccc-cccc-cccc-cccc-cccccccccccc";
    public const string BackendBaseUrl = "http://backend.test/";
    public const string AdmissionPath = "/.cratis/admission";
    public const string AssetPath = "/assets/app.js";
    public const string AssetContent = "console.log('bundled web asset');";
    public const string PageAssetPath = "/_pages/select-provider.html";
    public const string ConfiguredProviderScheme = "provider-one";

    /// <summary>The prefix of every capability the verifier will admit — once each.</summary>
    public const string AdmittedPrefix = "admit-";

    /// <summary>The capability the verifier cannot be reached about.</summary>
    public const string UnreachableCapability = "unreachable-capability";

    readonly ConcurrentDictionary<string, byte> _spent = new(StringComparer.Ordinal);
    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
    readonly string _webRootPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    public AuthProxyFactory()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, "select-provider.html"), "<html><body>Select Provider</body></html>");

        Directory.CreateDirectory(Path.Combine(_webRootPath, "assets"));
        File.WriteAllText(Path.Combine(_webRootPath, "assets", "app.js"), AssetContent);
        File.WriteAllText(Path.Combine(_webRootPath, "index.html"), "<html><body>Login</body></html>");
    }

    /// <summary>
    /// Creates a client that surfaces every answer as a response rather than following or storing anything.
    /// </summary>
    /// <returns>A configured <see cref="HttpClient"/>.</returns>
    public HttpClient CreateProbingClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    /// <summary>
    /// Mints a capability this deployment's verifier will admit exactly once.
    /// </summary>
    /// <returns>The capability.</returns>
    public static string MintCapability() => $"{AdmittedPrefix}{Guid.NewGuid():N}";

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (!disposing)
        {
            return;
        }

        foreach (var directory in new[] { _pagesPath, _webRootPath }.Where(Directory.Exists))
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder
            .UseEnvironment("Production")
            .UseWebRoot(_webRootPath)
            .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = BackendBaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:app:Frontend:BaseUrl"] = BackendBaseUrl,
                [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,

                [$"{C.Admission.SectionKey}:Mode"] = nameof(C.AdmissionMode.CapabilityOnly),
                [$"{C.Admission.SectionKey}:Capability:VerifierUrl"] = "https://verifier.test/admit",
                [$"{C.Admission.SectionKey}:Capability:MaximumLength"] = "256",
                [$"{C.Admission.SectionKey}:EntryLifetime"] = "00:10:00",

                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,

                [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Provider One",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.example.test/one",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-one",
                [$"{C.Authentication.SectionKey}:OidcProviders:1:Name"] = "Provider Two",
                [$"{C.Authentication.SectionKey}:OidcProviders:1:Authority"] = "https://login.example.test/two",
                [$"{C.Authentication.SectionKey}:OidcProviders:1:ClientId"] = "client-two",
            }))
            .ConfigureTestServices(services => services.AddSingleton<IHttpClientFactory>(new VerifierHttpClientFactory(Answer)));
    }

    async Task<HttpResponseMessage> Answer(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var presentation = await request.Content!.ReadFromJsonAsync<CapabilityVerificationRequest>(cancellationToken);

        if (string.Equals(presentation!.Capability, UnreachableCapability, StringComparison.Ordinal))
        {
            throw new HttpRequestException("connection refused");
        }

        // Single use, so presenting the same capability twice is refused by the authority that owns it —
        // exactly where that rule belongs, and never in AuthProxy.
        var admits = presentation.Capability.StartsWith(AdmittedPrefix, StringComparison.Ordinal)
            && _spent.TryAdd(presentation.Capability, 0);

        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new CapabilityVerificationResponse(
                admits,
                presentation.Transaction,
                presentation.Challenge,
                new Dictionary<string, string>(StringComparer.Ordinal))),
        };
    }

    sealed class VerifierHttpClientFactory(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(new DispatchingHandler(handler)) { Timeout = TimeSpan.FromSeconds(10) };

        sealed class DispatchingHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
                handler(request, cancellationToken);
        }
    }
}
