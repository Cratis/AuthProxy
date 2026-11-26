// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Cratis.AuthProxy.Code;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Scenarios.when_signing_in_with_a_code;

public class AuthProxyFactory : WebApplicationFactory<Program>
{
    public const string TenantId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    public const string KnownDomain = "@known.test";
    public const string Subject = "user-42";
    public const string Issuer = "https://example.test/.cratis/code";

    readonly string _statePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    public RecordingCodeDelivery Delivery { get; } = new(KnownDomain, Subject);

    public static string NewKnownAddress() => $"{Guid.NewGuid():N}{KnownDomain}";

    public static string NewUnknownAddress() => $"{Guid.NewGuid():N}@unknown.test";

    protected virtual IEnumerable<KeyValuePair<string, string?>> ExtraSettings => [];

    public HttpClient CreateTestClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });

    public static string Field(string html, string name)
    {
        var match = FieldPattern(name).Match(html);
        return match.Success ? System.Net.WebUtility.HtmlDecode(match.Groups[1].Value) : string.Empty;
    }

    static Regex FieldPattern(string name) => new($"""name="{name}" value="([^"]*)" """, RegexOptions.None, TimeSpan.FromSeconds(2));

    /// <summary>Starts a sign-in and returns the protected state the pages carry.</summary>
    /// <param name="client">The browser.</param>
    /// <returns>The state.</returns>
    public static async Task<string> Start(HttpClient client)
    {
        using var challenge = await client.GetAsync("/.cratis/login/code?returnUrl=/");
        using var page = await client.GetAsync(challenge.Headers.Location);
        return Field(await page.Content.ReadAsStringAsync(), "state");
    }

    /// <summary>Asks for a code for an address, as the address page does.</summary>
    /// <param name="client">The browser.</param>
    /// <param name="state">The protected state.</param>
    /// <param name="address">The address typed.</param>
    /// <returns>The page that answered.</returns>
    public static async Task<string> Request(HttpClient client, string state, string address)
    {
        using var response = await client.PostAsync(
            "/signin-code",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["state"] = state, ["step"] = "request", ["email"] = address }));
        return await response.Content.ReadAsStringAsync();
    }

    /// <summary>Presents a code, as the code page does.</summary>
    /// <param name="client">The browser.</param>
    /// <param name="state">The protected state.</param>
    /// <param name="challenge">The challenge the code page named.</param>
    /// <param name="code">The code typed.</param>
    /// <returns>The response.</returns>
    public static Task<HttpResponseMessage> Verify(HttpClient client, string state, string challenge, string code) =>
        client.PostAsync(
            "/signin-code",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["state"] = state, ["step"] = "verify", ["challenge"] = challenge, ["code"] = code }));

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && Directory.Exists(_statePath))
        {
            Directory.Delete(_statePath, recursive: true);
        }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        using var rsa = RSA.Create(2048);
        var pem = rsa.ExportPkcs8PrivateKeyPem();

        builder.UseEnvironment("Production");
        foreach (var (key, value) in new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Services:test:Backend:BaseUrl"] = "http://backend.test/",
                [$"{C.AuthProxy.SectionKey}:Services:test:Frontend:BaseUrl"] = "http://frontend.test/",
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,

                [$"{C.Authentication.SectionKey}:CodeStatePath"] = _statePath,
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Code",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Type"] = nameof(C.OidcProviderType.Code),
                [$"{C.Authentication.SectionKey}:OidcProviders:0:RequireVerifiedEmail"] = "true",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Code:RequestUrl"] = "https://example.test/_code/request",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Code:Issuer"] = Issuer,
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Code:Attestation:Issuer"] = "authproxy",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Code:Attestation:Audience"] = "app",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Code:Attestation:ActiveKeyId"] = "k1",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Code:Attestation:SigningKeys:0:KeyId"] = "k1",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Code:Attestation:SigningKeys:0:PrivateKeyPem"] = pem,
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Code:MaxAttempts"] = "3",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Code:Throttle:PerAddress"] = "2",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Session:Lifetime"] = "08:00:00",
            }.Concat(ExtraSettings))
        {
            builder.UseSetting(key, value);
        }

        builder.ConfigureTestServices(services => services.AddSingleton<ICodeDelivery>(Delivery));
    }
}
