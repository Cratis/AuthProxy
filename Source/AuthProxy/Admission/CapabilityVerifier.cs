// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Asks the deployment's own verifier whether a presented capability admits the caller.
/// </summary>
/// <param name="httpClientFactory">The factory for the client the verifier is called with.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="logger">The logger.</param>
/// <remarks>
/// Every outcome that is not an explicit, matching yes is a refusal — a refusing verifier, an error status,
/// an unparsable body, a reply about another presentation, a connection that never opened, and a call that
/// ran out of time. Failing open here would mean an outage of the verifier is an outage of the gate, which
/// is the one failure mode that turns this mode into nothing.
/// </remarks>
public class CapabilityVerifier(
    IHttpClientFactory httpClientFactory,
    IOptionsMonitor<C.AuthProxy> config,
    ILogger<CapabilityVerifier> logger) : ICapabilityVerifier
{
    /// <summary>
    /// The name of the configured <see cref="HttpClient"/> the verifier is called with.
    /// </summary>
    public const string HttpClientName = "Cratis.AuthProxy.CapabilityVerifier";

    static readonly JsonSerializerOptions _serializerOptions = new(JsonSerializerDefaults.Web);

    /// <inheritdoc/>
    public async Task<CapabilityVerification> Verify(CapabilityPresentation presentation, CancellationToken cancellationToken)
    {
        var capability = config.CurrentValue.Admission.Capability;
        if (capability is null || string.IsNullOrWhiteSpace(capability.VerifierUrl))
        {
            logger.CapabilityVerifierNotConfigured();
            return CapabilityVerification.Denied;
        }

        try
        {
            using var client = httpClientFactory.CreateClient(HttpClientName);
            using var content = JsonContent.Create(
                new CapabilityVerificationRequest(presentation.Capability, presentation.Transaction, presentation.Challenge),
                options: _serializerOptions);
            using var response = await client.PostAsync(new Uri(capability.VerifierUrl), content, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                logger.CapabilityRefused();
                return CapabilityVerification.Denied;
            }

            var answer = await response.Content.ReadFromJsonAsync<CapabilityVerificationResponse>(_serializerOptions, cancellationToken);

            return Interpret(answer, presentation);
        }
        catch (Exception)
        {
            // Fail closed, and deliberately for every exception rather than a classified few: an outcome
            // this cannot name is exactly the outcome it must not treat as a yes.
            logger.CapabilityVerifierUnavailable();
            return CapabilityVerification.Denied;
        }
    }

    /// <summary>
    /// Compares two opaque values without letting the comparison's duration describe them.
    /// </summary>
    /// <param name="expected">The value AuthProxy authored.</param>
    /// <param name="actual">The value that came back.</param>
    /// <returns><see langword="true"/> when they are the same; otherwise <see langword="false"/>.</returns>
    static bool FixedTimeEquals(string expected, string? actual)
    {
        if (actual is null)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected),
            Encoding.UTF8.GetBytes(actual));
    }

    /// <summary>
    /// Turns a verifier's reply into a verification, refusing anything that does not name this presentation.
    /// </summary>
    /// <param name="answer">The verifier's reply.</param>
    /// <param name="presentation">The presentation it was asked about.</param>
    /// <returns>The <see cref="CapabilityVerification"/>.</returns>
    CapabilityVerification Interpret(CapabilityVerificationResponse? answer, CapabilityPresentation presentation)
    {
        if (answer?.Admitted != true)
        {
            logger.CapabilityRefused();
            return CapabilityVerification.Denied;
        }

        if (!FixedTimeEquals(presentation.Transaction, answer.Transaction)
            || !FixedTimeEquals(presentation.Challenge, answer.Challenge))
        {
            logger.CapabilityVerifierAnsweredAnotherPresentation();
            return CapabilityVerification.Denied;
        }

        return CapabilityVerification.Admitted;
    }
}
