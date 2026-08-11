// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Extension methods for registering the admission services on <see cref="WebApplicationBuilder"/>.
/// </summary>
public static class AdmissionServiceCollectionExtensions
{
    /// <summary>
    /// The time a call to the capability verifier is given before it is treated as unanswered.
    /// </summary>
    /// <remarks>
    /// Short on purpose. The call is on the request path of a caller who has been admitted to nothing, so a
    /// verifier that has stopped answering must not become a way to hold connections open.
    /// </remarks>
    public static readonly TimeSpan VerifierTimeout = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Registers the admission policy, the capability seam and the validation that refuses a door closed
    /// without a key.
    /// </summary>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> for chaining.</returns>
    /// <remarks>
    /// Registration alone changes nothing about a request. A deployment that never sets the section leaves
    /// <see cref="IAdmissionPolicy.IsConfigured"/> answering <see langword="false"/>, and nothing here is
    /// consulted again.
    /// </remarks>
    public static WebApplicationBuilder AddAdmission(this WebApplicationBuilder builder)
    {
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<IEntryTransactionProtector, EntryTransactionProtector>();
        builder.Services.AddSingleton<IAdmissionPolicy, AdmissionPolicy>();
        builder.Services.AddSingleton<ICapabilityVerifier, CapabilityVerifier>();
        builder.Services.AddSingleton<ICapabilityAdmission, CapabilityAdmission>();
        builder.Services.AddSingleton<IValidateOptions<C.AuthProxy>, AdmissionConfigurationValidator>();
        builder.Services.AddHttpClient(CapabilityVerifier.HttpClientName, client => client.Timeout = VerifierTimeout);

        return builder;
    }
}
