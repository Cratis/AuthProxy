// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Configuration.for_Service;

/// <summary>
/// The Aspire package is a standalone NuGet package that cannot reference the proxy it configures, so it
/// carries its own copy of this enumeration and hands the choice over as a string in an environment
/// variable — exactly as it already does for the provider type. That string is the only thing joining the
/// two definitions, and a rename on either side would fail in the worst possible direction: binding falls
/// back to the default, which is the permissive mode, and nothing anywhere would say so.
/// <para>
/// Both ends are therefore pinned by name. The Aspire specs assert the exact strings the builder writes;
/// this asserts the exact strings the proxy reads. A rename on either side now breaks a spec rather than a
/// deployment.
/// </para>
/// </summary>
public class when_binding_identity_verification : Specification
{
    C.AuthProxy _config;

    void Because() => _config = new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Services:required:Backend:BaseUrl"] = "https://required.example.com",
            ["Services:required:IdentityVerification"] = "Required",
            ["Services:required:IdentityVerificationTimeout"] = "00:00:03",
            ["Services:relaxed:Backend:BaseUrl"] = "https://relaxed.example.com",
            ["Services:relaxed:IdentityVerification"] = "BestEffort",
            ["Services:unstated:Backend:BaseUrl"] = "https://unstated.example.com"
        })
        .Build()
        .Get<C.AuthProxy>()!;

    [Fact] void should_bind_the_required_mode() => _config.Services["required"].IdentityVerification.ShouldEqual(IdentityVerificationMode.Required);
    [Fact] void should_bind_the_best_effort_mode() => _config.Services["relaxed"].IdentityVerification.ShouldEqual(IdentityVerificationMode.BestEffort);
    [Fact] void should_leave_an_unstated_mode_permissive() => _config.Services["unstated"].IdentityVerification.ShouldEqual(IdentityVerificationMode.BestEffort);
    [Fact] void should_bind_the_verification_timeout() => _config.Services["required"].IdentityVerificationTimeout.ShouldEqual(TimeSpan.FromSeconds(3));
    [Fact] void should_leave_an_unstated_timeout_at_ten_seconds() => _config.Services["unstated"].IdentityVerificationTimeout.ShouldEqual(TimeSpan.FromSeconds(10));
    [Fact] void should_treat_the_deployment_as_requiring_verification() => _config.RequiresIdentityVerification.ShouldBeTrue();
}
