// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Cratis.AuthProxy.Security.given;

/// <summary>Refuses signing to exercise back-channel fail-closed behavior independently of canonicalization.</summary>
public class RefusedBackChannelSigningHarness : ForwardedIdentityHarness
{
    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        base.AddSettings(settings);
        settings[$"{C.AuthProxy.SectionKey}:Services:app:IdentityVerification"] = nameof(C.IdentityVerificationMode.BestEffort);
    }

    /// <inheritdoc/>
    protected override void ConfigureHost(IWebHostBuilder builder)
    {
        base.ConfigureHost(builder);
        builder.ConfigureTestServices(services => services.Replace(ServiceDescriptor.Singleton<IForwardedIdentitySigner>(new RefusingSigner())));
    }

    sealed class RefusingSigner : IForwardedIdentitySigner
    {
        public ForwardedIdentitySigningOutcome Sign(HttpRequestMessage request, ForwardedIdentitySigningTarget target) => ForwardedIdentitySigningOutcome.Refused;
    }
}
