// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;
using System.Security.Cryptography;
using Cratis.AuthProxy.Attestations;
using Cratis.AuthProxy.SignIns;
using Microsoft.IdentityModel.Tokens;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Code;

/// <summary>
/// Posts code requests to the application, signed with the provider's attestation key so the application can tell it is
/// AuthProxy asking.
/// </summary>
/// <param name="httpClientFactory">Creates the HTTP client.</param>
/// <param name="timeProvider">The clock.</param>
/// <param name="logger">The logger.</param>
public sealed class CodeDelivery(
    IHttpClientFactory httpClientFactory,
    TimeProvider timeProvider,
    ILogger<CodeDelivery> logger) : ICodeDelivery
{
    /// <inheritdoc/>
    public async Task<string?> Deliver(C.CodeSignIn settings, CodeRequest request)
    {
        var attestation = settings.Attestation;
        if (attestation is null || !Uri.TryCreate(settings.RequestUrl, UriKind.Absolute, out var target))
        {
            logger.CodeRequestNotConfigured();
            return null;
        }

        var key = attestation.SigningKeys.FirstOrDefault(_ => string.Equals(_.KeyId, attestation.ActiveKeyId, StringComparison.Ordinal));
        if (key is null)
        {
            logger.CodeRequestCouldNotBeSigned();
            return null;
        }

        using var content = JsonContent.Create(request, options: JsonSerializerOptions.Web);
        var body = await content.ReadAsByteArrayAsync();
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [SignInAttestationClaims.Purpose] = SignInAttestationClaims.CodeRequestPurpose,
            [SignInAttestationClaims.HttpMethod] = HttpMethod.Post.Method,
            [SignInAttestationClaims.HttpUri] = target.GetLeftPart(UriPartial.Path),
            [SignInAttestationClaims.BodyHash] = Base64UrlEncoder.Encode(SHA256.HashData(body)),
        };

        if (!AttestationSigner.TryIssue(
                new AttestationSigningContract(attestation.Issuer, attestation.Audience, key.KeyId, key.PrivateKeyPem, attestation.Lifetime),
                timeProvider.GetUtcNow(),
                claims,
                out var envelope))
        {
            logger.CodeRequestCouldNotBeSigned();
            return null;
        }

        using var message = new HttpRequestMessage(HttpMethod.Post, target) { Content = content };
        message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", envelope);

        try
        {
            using var client = httpClientFactory.CreateClient();
            using var response = await client.SendAsync(message);
            if (!response.IsSuccessStatusCode)
            {
                logger.CodeRequestRefused((int)response.StatusCode);
                return null;
            }

            var answer = await response.Content.ReadFromJsonAsync<CodeDeliveryAnswer>(JsonSerializerOptions.Web);
            return string.IsNullOrWhiteSpace(answer?.Subject) ? null : answer.Subject;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            logger.CodeRequestFailed(ex);
            return null;
        }
    }

    sealed record CodeDeliveryAnswer(string? Subject);
}
