// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Net.Http.Json;
using Cratis.AuthProxy.Admission.given;
using Cratis.AuthProxy.given;

namespace Cratis.AuthProxy.Admission.for_CapabilityVerifier.given;

/// <summary>
/// The verifier over a stub transport, so a spec decides exactly what came back — or that nothing did.
/// </summary>
public class a_capability_verifier : Specification
{
    protected const string Capability = "a-presented-capability";

    protected CapabilityPresentation _presentation;
    protected C.AuthProxy _config;
    protected StubHttpClientFactory _httpClientFactory;
    protected RecordingLogger<CapabilityVerifier> _logger;
    protected CapabilityVerifier _verifier;
    protected CapabilityVerification _verification;

    void Establish()
    {
        _presentation = new CapabilityPresentation(Capability, "3f9c0a1b7e2d4c6f", "8b1d5e7a0c3f2941");
        _config = new C.AuthProxy
        {
            Admission = new C.Admission
            {
                Mode = C.AdmissionMode.CapabilityOnly,
                Capability = new C.AdmissionCapability { VerifierUrl = "https://verifier.test/admit" },
            },
        };
    }

    /// <summary>
    /// Builds the verifier over a transport answering with the given delegate.
    /// </summary>
    /// <param name="handler">What the verifier answers.</param>
    /// <param name="timeout">How long the client waits.</param>
    protected void VerifierAnswering(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler,
        TimeSpan? timeout = null)
    {
        _httpClientFactory = new StubHttpClientFactory(handler, timeout);
        _logger = new RecordingLogger<CapabilityVerifier>();

        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(_config);

        _verifier = new CapabilityVerifier(_httpClientFactory, config, _logger);
    }

    /// <summary>
    /// Builds an answer body.
    /// </summary>
    /// <param name="admitted">Whether the capability admits.</param>
    /// <param name="transaction">The transaction the answer names.</param>
    /// <param name="challenge">The challenge the answer names.</param>
    /// <returns>A successful HTTP answer carrying it.</returns>
    protected static HttpResponseMessage Answer(
        bool admitted,
        string? transaction,
        string? challenge) =>
        new(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new CapabilityVerificationResponse(admitted, transaction, challenge)),
        };
}
