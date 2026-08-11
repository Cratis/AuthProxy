// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Admission.for_AdmissionServiceCollectionExtensions;

/// <summary>
/// The client the verifier is called with is the one the registration configures, asserted from the real
/// registration rather than from the constant it is configured with.
/// </summary>
/// <remarks>
/// <c>CreateClient</c> answers for a name nothing ever registered — with <see cref="HttpClient"/>'s own
/// hundred-second default. So deleting the registration outright leaves every existing spec green and every
/// caller who has been admitted to nothing able to hold a request open for a hundred seconds against a
/// verifier that stopped answering. The timeout is the thing that stops that, and this is what says it is
/// still there.
/// <para>
/// Resolved through <c>AddIngressConfiguration</c> rather than through <c>AddAdmission</c> alone, because
/// that is what the process does and it is what makes the hazard reproducible: the ingress registration adds
/// an unnamed <c>HttpClient</c> too, so a provider missing the named registration still hands back a client
/// — the silently wrong one — instead of failing to resolve anything.
/// </para>
/// </remarks>
public class when_adding_admission : Specification
{
    ServiceProvider _serviceProvider;
    HttpClient _client;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.AddIngressConfiguration();

        _serviceProvider = builder.Services.BuildServiceProvider();
    }

    void Because() => _client = _serviceProvider
        .GetRequiredService<IHttpClientFactory>()
        .CreateClient(CapabilityVerifier.HttpClientName);

    void Destroy()
    {
        _client?.Dispose();
        _serviceProvider.Dispose();
    }

    [Fact]
    void should_bound_how_long_a_verifier_is_waited_for() =>
        _client.Timeout.ShouldEqual(AdmissionServiceCollectionExtensions.VerifierTimeout);
}
