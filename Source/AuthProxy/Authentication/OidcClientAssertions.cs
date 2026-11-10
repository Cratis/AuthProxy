// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Represents an implementation of <see cref="IOidcClientAssertions"/> built on the Microsoft.Identity.Web credential
/// loaders.
/// </summary>
/// <remarks>
/// A certificate is loaded once per provider and kept until it expires; each request gets a freshly signed,
/// short-lived assertion. Federated sources (workload identity token file, managed identity) are kept as the loader's
/// assertion provider, which caches the platform token and fetches a new one before it expires.
/// </remarks>
/// <param name="loader">The <see cref="ICredentialsLoader"/> that loads certificates and federated assertion providers.</param>
/// <param name="timeProvider">The <see cref="TimeProvider"/> stamping the assertions.</param>
/// <param name="logger">The <see cref="ILogger"/> for diagnostics.</param>
public sealed class OidcClientAssertions(
    ICredentialsLoader loader,
    TimeProvider timeProvider,
    ILogger<OidcClientAssertions> logger) : IOidcClientAssertions
{
    readonly ConcurrentDictionary<string, CredentialState> _credentials = new(StringComparer.Ordinal);

    /// <inheritdoc/>
    public async Task<string> Create(string scheme, C.OidcProvider provider, string audience, CancellationToken cancellationToken)
    {
        if (provider.ClientCredential is not { UsesClientAssertion: true } credential)
        {
            throw new OidcClientCredentialUnavailable($"The OIDC provider '{provider.Name}' is not configured with a client-assertion credential.");
        }

        var state = _credentials.GetOrAdd(
            scheme,
            static (_, configured) => new CredentialState(OidcClientCredentialDescription.From(configured.ClientCredential!, configured.Authority)),
            provider);
        await state.Semaphore.WaitAsync(cancellationToken);
        try
        {
            var description = state.Description;
            var now = timeProvider.GetUtcNow();
            ThrottleCertificateReload(state, provider, credential, now);

            await Load(description, provider);
            now = timeProvider.GetUtcNow();
            var certificate = description.Certificate;
            certificate = await ReloadExpiredCertificate(state, provider, certificate, now);

            if (certificate is not null)
            {
                return SignCertificate(certificate, provider, audience, now);
            }

            if (description.CachedValue is ClientAssertionProviderBase assertionProvider)
            {
                try
                {
                    return await assertionProvider.GetSignedAssertionAsync(new AssertionRequestOptions
                    {
                        ClientID = provider.ClientId,
                        Authority = provider.Authority,
                        TokenEndpoint = audience,
                        CancellationToken = cancellationToken
                    });
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    logger.ClientCredentialUnavailable(provider.Name, credential.Source.ToString(), exception);
                    throw new OidcClientCredentialUnavailable(
                        $"The {credential.Source} client credential of OIDC provider '{provider.Name}' produced no client assertion.",
                        exception);
                }
            }

            throw new OidcClientCredentialUnavailable(
                $"The {credential.Source} client credential of OIDC provider '{provider.Name}' could not be loaded.");
        }
        finally
        {
            state.Semaphore.Release();
        }
    }

    static string SignCertificate(X509Certificate2 certificate, C.OidcProvider provider, string audience, DateTimeOffset now)
    {
        if (certificate.NotAfter.ToUniversalTime() <= now.UtcDateTime)
        {
            throw new OidcClientCredentialUnavailable($"The client certificate of OIDC provider '{provider.Name}' has expired.");
        }

        return CertificateClientAssertion.Create(certificate, provider.ClientId, audience, now);
    }

    static void ThrottleCertificateReload(CredentialState state, C.OidcProvider provider, C.OidcClientCredential credential, DateTimeOffset now)
    {
        if (state.Description.Certificate is not null || state.NextCertificateReload == default)
        {
            return;
        }

        // An expiry-triggered reload can return no certificate or fail. Throttle those retries too.
        if (now < state.NextCertificateReload)
        {
            throw new OidcClientCredentialUnavailable(
                $"The {credential.Source} client credential of OIDC provider '{provider.Name}' could not be loaded.");
        }

        state.NextCertificateReload = now.AddMinutes(1);
    }

    async Task<X509Certificate2?> ReloadExpiredCertificate(CredentialState state, C.OidcProvider provider, X509Certificate2? certificate, DateTimeOffset now)
    {
        if (certificate is null || certificate.NotAfter.ToUniversalTime() > now.UtcDateTime)
        {
            return certificate;
        }

        if (now < state.NextCertificateReload)
        {
            return certificate;
        }

        // Serialize reload and signing so resetting/disposal cannot invalidate another request's key.
        // An unchanged expired file or thumbprint must not cause a load and warning on every sign-in.
        state.NextCertificateReload = now.AddMinutes(1);
        logger.ClientCertificateExpired(provider.Name);
        var description = state.Description;
        loader.ResetCredentials([description]);
        try
        {
            await Load(description, provider);
        }
        finally
        {
            if (!ReferenceEquals(certificate, description.Certificate))
            {
                certificate.Dispose();
            }
        }

        return description.Certificate;
    }

    async Task Load(CredentialDescription description, C.OidcProvider provider)
    {
        try
        {
            await loader.LoadCredentialsIfNeededAsync(description, new CredentialSourceLoaderParameters(provider.ClientId, provider.Authority));
        }
        catch (Exception exception)
        {
            logger.ClientCredentialUnavailable(provider.Name, provider.ClientCredential!.Source.ToString(), exception);
            throw new OidcClientCredentialUnavailable(
                $"The {provider.ClientCredential.Source} client credential of OIDC provider '{provider.Name}' could not be loaded.",
                exception);
        }
    }

    sealed class CredentialState(CredentialDescription description)
    {
        internal CredentialDescription Description { get; } = description;

        internal SemaphoreSlim Semaphore { get; } = new(1, 1);

        internal DateTimeOffset NextCertificateReload { get; set; }
    }
}
