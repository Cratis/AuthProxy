// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.Admission;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A running AuthProxy that answers nothing until a capability admits, in front of a real recording origin.
/// </summary>
/// <remarks>
/// A third harness rather than a setting on the shared one, for the same reason the claim-gated one is its
/// own: the shared harness is the deployment every other security spec reasons about, and closing it would
/// change the premise of all of them.
/// <para>
/// It is deliberately end to end and deliberately configured with everything a caller could learn something
/// from — a declared anonymous path, configured providers, real page assets and a real origin. The question
/// these specs ask is not what the client sees, which is easy to get right, but whether anything at all
/// reached the application: a refusal that still caused a request, a <c>/.cratis/me</c> call or a log entry
/// inside the backend is a refusal that told an unadmitted caller the backend is there.
/// </para>
/// </remarks>
public class CapabilityOnlyHarness : WebApplicationFactory<Program>
{
    /// <summary>The tenant every request resolves to.</summary>
    public const string TenantId = "33333333-3333-3333-3333-333333333333";

    /// <summary>The one path this deployment declares anonymous — and which admission closes anyway.</summary>
    public const string AnonymousPath = "/public";

    /// <summary>A path that is not anonymous.</summary>
    public const string ProtectedPath = "/private";

    /// <summary>Where a capability is presented.</summary>
    public const string AdmissionPath = "/.cratis/admission";

    /// <summary>The prefix of every capability this deployment's verifier admits.</summary>
    public const string AdmittedPrefix = "admit-";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    /// <summary>
    /// Initializes a new instance of the <see cref="CapabilityOnlyHarness"/> class.
    /// </summary>
    public CapabilityOnlyHarness()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, WellKnownPageNames.SelectProvider), "<html><body>Select Provider</body></html>");

        Origin = RecordingBackend.Start().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Gets the origin AuthProxy forwards to, and the record of what reached it.
    /// </summary>
    public RecordingBackend Origin { get; }

    /// <summary>
    /// Mints a capability this deployment's verifier admits.
    /// </summary>
    /// <returns>The capability.</returns>
    public static string MintCapability() => $"{AdmittedPrefix}{Guid.NewGuid():N}";

    /// <summary>
    /// Creates a client that surfaces redirects as responses and carries only the cookies a spec puts on a
    /// request.
    /// </summary>
    /// <returns>A configured <see cref="HttpClient"/>.</returns>
    public HttpClient CreateSecurityClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    /// <summary>
    /// Presents a capability and returns the entry transaction it was admitted with.
    /// </summary>
    /// <param name="client">The client to present with.</param>
    /// <returns>The raw entry-transaction cookie value.</returns>
    public static async Task<string> Admit(HttpClient client)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, AdmissionPath)
        {
            Content = new StringContent(MintCapability(), Encoding.UTF8, "text/plain"),
        };
        using var response = await client.SendAsync(request);

        var setCookie = response.Headers.GetValues("Set-Cookie").First();
        var value = setCookie[(setCookie.IndexOf('=', StringComparison.Ordinal) + 1)..];

        return value[..value.IndexOf(';', StringComparison.Ordinal)];
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (!disposing)
        {
            return;
        }

        Origin.DisposeAsync().AsTask().GetAwaiter().GetResult();

        if (Directory.Exists(_pagesPath))
        {
            Directory.Delete(_pagesPath, recursive: true);
        }
    }

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder
            .UseEnvironment("Production")
            .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = Origin.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:app:Frontend:BaseUrl"] = Origin.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:app:AnonymousPaths:0"] = AnonymousPath,

                [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,

                [$"{C.Admission.SectionKey}:Mode"] = nameof(C.AdmissionMode.CapabilityOnly),
                [$"{C.Admission.SectionKey}:Capability:VerifierUrl"] = "https://verifier.test/admit",
                [$"{C.Admission.SectionKey}:EntryLifetime"] = "00:10:00",

                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,

                [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Provider One",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.example.test/one",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-one",
            }))
            .ConfigureTestServices(services =>
            {
                // Substituted at the seam rather than at the transport, so the proxy's own outbound calls —
                // notably the identity call to the origin — keep going where a deployment's would.
                services.AddSingleton<ICapabilityVerifier, PrefixCapabilityVerifier>();

                services
                    .AddAuthentication(HeaderAuthenticationHandler.Scheme)
                    .AddScheme<AuthenticationSchemeOptions, HeaderAuthenticationHandler>(
                        HeaderAuthenticationHandler.Scheme,
                        _ => { });
            });
    }

    /// <summary>
    /// A verifier standing in for the deployment's own: it admits anything carrying the agreed prefix.
    /// </summary>
    sealed class PrefixCapabilityVerifier : ICapabilityVerifier
    {
        public Task<CapabilityVerification> Verify(CapabilityPresentation presentation, CancellationToken cancellationToken) =>
            Task.FromResult(presentation.Capability.StartsWith(AdmittedPrefix, StringComparison.Ordinal)
                ? CapabilityVerification.Admitted
                : CapabilityVerification.Denied);
    }
}
