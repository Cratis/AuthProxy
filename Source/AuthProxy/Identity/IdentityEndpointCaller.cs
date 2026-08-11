// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text.Json.Nodes;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Calls one service's <c>/.cratis/me</c> endpoint and reports what it established.
/// </summary>
/// <param name="httpClientFactory">The HTTP client factory.</param>
/// <param name="logger">
/// The logger to write to. This is the resolver's own logger rather than one of this type's category, so
/// everything an operator needs to explain a single identity resolution stays on one category.
/// </param>
/// <remarks>
/// Separated from <see cref="IdentityDetailsResolver"/> because the two answer different questions. This
/// one turns an HTTP exchange into a fact — reached or not, refused or not, verdict or not — and holds no
/// opinion about what should happen next. The resolver decides what the fact is worth, which is where the
/// per-service mode belongs.
/// </remarks>
public class IdentityEndpointCaller(IHttpClientFactory httpClientFactory, ILogger logger)
{
    /// <summary>
    /// Calls a service's identity endpoint and reports the outcome.
    /// </summary>
    /// <param name="serviceName">The configured name of the service being called.</param>
    /// <param name="baseUrl">The service's backend base URL.</param>
    /// <param name="principal">The enriched principal to present to the service.</param>
    /// <param name="tenantId">The tenant the caller is acting in.</param>
    /// <param name="logIdentifier">The non-identifying label used when logging about this caller.</param>
    /// <param name="timeout">How long to wait for an answer. Non-positive leaves the wait unbounded.</param>
    /// <param name="cancellationToken">The caller's own request lifetime.</param>
    /// <returns>What the service established, and the details it supplied.</returns>
    /// <remarks>
    /// Nothing here throws. Every way the call can fail is a fact about the service, and a fact is what the
    /// resolver needs in order to apply the configured mode to it — an exception escaping would force the
    /// decision to be made in an exception handler, which is exactly how the failure direction was lost.
    /// </remarks>
    public async Task<IdentityVerificationOutcome> Call(
        string serviceName,
        string baseUrl,
        ClientPrincipal principal,
        string tenantId,
        string logIdentifier,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var url = baseUrl.TrimEnd('/') + WellKnownPaths.IdentityDetails;
        logger.CallingIdentityEndpoint(url, serviceName);

        using var client = httpClientFactory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.SetMicrosoftIdentityHeaders(principal);
        request.Headers.Add(Headers.TenantId, HeaderValue.ToTransportValue(tenantId));

        using var timeoutSource = timeout > TimeSpan.Zero
            ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken)
            : null;
        timeoutSource?.CancelAfter(timeout);
        var token = timeoutSource?.Token ?? cancellationToken;

        try
        {
            using var httpResponse = await client.SendAsync(request, token);

            if (httpResponse.StatusCode == HttpStatusCode.Forbidden)
            {
                logger.IdentityEndpointForbidden(serviceName, logIdentifier);
                return IdentityVerificationOutcome.Denied(IdentityVerificationReason.Forbidden);
            }

            if (!httpResponse.IsSuccessStatusCode)
            {
                logger.IdentityEndpointUnsuccessful(serviceName, (int)httpResponse.StatusCode);
                return IdentityVerificationOutcome.Indeterminate(IdentityVerificationReason.UnsuccessfulStatusCode);
            }

            var body = await httpResponse.Content.ReadAsStringAsync(token);

            return string.IsNullOrWhiteSpace(body)
                ? IdentityVerificationOutcome.Indeterminate(IdentityVerificationReason.EmptyResponse)
                : ReadOutcome(body, serviceName);
        }
        catch (OperationCanceledException ex) when (cancellationToken.IsCancellationRequested)
        {
            logger.ErrorCallingIdentityEndpoint(ex, serviceName);
            return IdentityVerificationOutcome.Indeterminate(IdentityVerificationReason.Canceled);
        }
        catch (OperationCanceledException ex)
        {
            logger.ErrorCallingIdentityEndpoint(ex, serviceName);
            return IdentityVerificationOutcome.Indeterminate(IdentityVerificationReason.TimedOut);
        }
        catch (Exception ex)
        {
            logger.ErrorCallingIdentityEndpoint(ex, serviceName);
            return IdentityVerificationOutcome.Indeterminate(IdentityVerificationReason.TransportFailure);
        }
    }

    /// <summary>
    /// Reads one boolean verdict property, ignoring the casing a service happens to serialize with.
    /// </summary>
    /// <param name="parsed">The parsed response body.</param>
    /// <param name="name">The property name to read.</param>
    /// <returns>The verdict, or <see langword="null"/> when the body states none.</returns>
    /// <remarks>
    /// Only a JSON boolean counts. A string, a number or a missing property all mean the service stated no
    /// verdict — inferring one from a quoted affirmative would be guessing at an authorization decision.
    /// </remarks>
    static bool? ReadVerdict(JsonObject parsed, string name) =>
        parsed.FirstOrDefault(property => string.Equals(property.Key, name, StringComparison.OrdinalIgnoreCase)).Value
            is JsonValue value && value.TryGetValue<bool>(out var verdict)
            ? verdict
            : null;

    /// <summary>
    /// Reads a successful response body into an outcome.
    /// </summary>
    /// <param name="body">The response body.</param>
    /// <param name="serviceName">The configured name of the service being called.</param>
    /// <returns>What the body established, and the details it carried.</returns>
    IdentityVerificationOutcome ReadOutcome(string body, string serviceName)
    {
        JsonObject parsed;
        try
        {
            parsed = JsonNode.Parse(body)?.AsObject() ?? new JsonObject();
        }
        catch (Exception ex)
        {
            logger.CouldNotParseIdentityResponse(ex, serviceName);
            return IdentityVerificationOutcome.Indeterminate(IdentityVerificationReason.UnreadableResponse);
        }

        // Preserved exactly as released: a service may answer the full identity envelope, or the bare
        // details object. Anything that is not an envelope is details, and details alone say nothing about
        // whether the caller may be here.
        var details = parsed["details"]?.AsObject() ?? parsed;
        var authorized = ReadVerdict(parsed, "isAuthorized");
        var authenticated = ReadVerdict(parsed, "isAuthenticated");

        return (authorized, authenticated) switch
        {
            (false, _) => IdentityVerificationOutcome.Denied(IdentityVerificationReason.NotAuthorized, details),
            (true, false) => IdentityVerificationOutcome.Indeterminate(IdentityVerificationReason.ConflictingVerdict, details),
            (true, _) => IdentityVerificationOutcome.Positive(details),
            _ => IdentityVerificationOutcome.Indeterminate(IdentityVerificationReason.NoVerdict, details)
        };
    }
}
