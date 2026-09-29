// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A deployment that requires identity verification of every forwarded request does not start with a bearer route
/// that would forward requests without it, unless the route says so. The mistake is named at startup rather than
/// found in production.
/// </summary>
public class when_a_bearer_route_does_not_accept_callers_without_required_identity_verification : IDisposable
{
    readonly VerificationRequiringHarness _harness = new();
    readonly Exception? _startup;

    public when_a_bearer_route_does_not_accept_callers_without_required_identity_verification() =>
        _startup = Record.Exception(() => _harness.CreateClient().Dispose());

    [Fact] public void should_refuse_to_start() => Assert.IsType<OptionsValidationException>(_startup);
    [Fact] public void should_name_the_setting_that_accepts_it() => Assert.Contains(nameof(C.BearerRoute.AcceptWithoutIdentityVerification), _startup!.Message, StringComparison.Ordinal);

    public void Dispose()
    {
        _harness.Dispose();
        GC.SuppressFinalize(this);
    }

    sealed class VerificationRequiringHarness : BearerRouteHarness
    {
        protected override void AddSettings(IDictionary<string, string?> settings) =>
            settings[$"{C.AuthProxy.SectionKey}:Services:app:IdentityVerification"] = nameof(C.IdentityVerificationMode.Required);
    }
}
