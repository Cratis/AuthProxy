// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
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
    readonly ConcurrentDictionary<string, CredentialDescription> _descriptions = new(StringComparer.Ordinal);

    /// <inheritdoc/>
    public async Task<string> Create(string scheme, C.OidcProvider provider, string audience, CancellationToken cancellationToken)
    {
        if (provider.ClientCredential is not { UsesClientAssertion: true } credential)
        {
            throw new OidcClientCredentialUnavailable($"The OIDC provider '{provider.Name}' is not configured with a client-assertion credential.");
        }

        var description = _descriptions.GetOrAdd(scheme, static (_, configured) => OidcClientCredentialDescription.From(configured), credential);
        await Load(description, provider);

        var now = timeProvider.GetUtcNow();
        if (description.Certificate is not null && description.Certificate.NotAfter.ToUniversalTime() <= now.UtcDateTime)
        {
            // A rotated certificate replaces the expired one in its file, store or vault; load it again rather than
            // signing with a certificate the provider will refuse.
            logger.ClientCertificateExpired(provider.Name);
            loader.ResetCredentials([description]);
            await Load(description, provider);
        }

        if (description.Certificate is { } certificate)
        {
            return CertificateClientAssertion.Create(certificate, provider.ClientId, audience, now);
        }

        if (description.CachedValue is ClientAssertionProviderBase assertionProvider)
        {
            try
            {
                return await assertionProvider.GetSignedAssertionAsync(new AssertionRequestOptions
                {
                    ClientID = provider.ClientId,
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
}
