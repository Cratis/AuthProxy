// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

/// <summary>
/// Declaring what a service's identity answer is worth is its own builder rather than another optional
/// argument on <c>WithBackend</c>.
/// <para>
/// An optional argument is baked into the call site when the app host is compiled, so adding one to a
/// shipped method changes its signature and every app host already built against the package fails to bind
/// until it is rebuilt. A new method costs nothing to an existing app host and is the only additive way to
/// extend a published surface.
/// </para>
/// </summary>
public class when_declaring_identity_verification : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish()
    {
        _resource.WithIdentityVerification("main", IdentityVerificationMode.Required);
        _resource.WithIdentityVerification("other", IdentityVerificationMode.BestEffort, TimeSpan.FromSeconds(3));
    }

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_declare_the_required_mode() => _environment["Cratis__AuthProxy__Services__main__IdentityVerification"].ShouldEqual("Required");
    [Fact] void should_declare_the_best_effort_mode() => _environment["Cratis__AuthProxy__Services__other__IdentityVerification"].ShouldEqual("BestEffort");
    [Fact] void should_leave_the_timeout_to_the_proxy_when_none_is_given() => _environment.ContainsKey("Cratis__AuthProxy__Services__main__IdentityVerificationTimeout").ShouldBeFalse();
    [Fact] void should_declare_a_given_timeout() => _environment["Cratis__AuthProxy__Services__other__IdentityVerificationTimeout"].ShouldEqual("00:00:03");
    [Fact] void should_leave_identity_resolution_itself_alone() => _environment.Keys.Any(_ => _.Contains("ResolveIdentityDetails", StringComparison.Ordinal)).ShouldBeFalse();
}
