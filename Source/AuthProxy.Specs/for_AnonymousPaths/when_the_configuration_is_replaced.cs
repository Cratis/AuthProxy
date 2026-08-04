// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_AnonymousPaths;

/// <summary>
/// The resolved prefixes are cached per configuration instance so that a request does not re-parse every
/// declared entry three times over. This pins the property that makes that safe: a replaced configuration is
/// a different instance, so it resolves again.
/// <para>
/// Withdrawing an anonymous path is the direction that matters. A cache that kept serving the old answer
/// would leave a path anonymous after it had been removed — authentication silently not applied to a surface
/// an operator believes they just closed. Asserted in both directions, and with the same declared set on two
/// separate instances, so the cache cannot be satisfied by never caching at all.
/// </para>
/// </summary>
public class when_the_configuration_is_replaced : Specification
{
    C.AuthProxy _withPortalAnonymous;
    C.AuthProxy _withPortalWithdrawn;
    C.AuthProxy _withPortalAnonymousAgain;

    static C.AuthProxy ConfigurationDeclaring(params string[] anonymousPaths) =>
        new()
        {
            Services = new Dictionary<string, C.Service>
            {
                ["test"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://backend.test/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "http://frontend.test/" },
                    AnonymousPaths = [.. anonymousPaths],
                },
            },
        };

    void Establish()
    {
        _withPortalAnonymous = ConfigurationDeclaring("/portal");
        _withPortalWithdrawn = ConfigurationDeclaring("/status");
        _withPortalAnonymousAgain = ConfigurationDeclaring("/portal");
    }

    [Fact] void should_match_the_declared_prefix() =>
        AnonymousPaths.Matches("/portal", _withPortalAnonymous).ShouldBeTrue();

    [Fact] void should_stop_matching_once_the_prefix_is_withdrawn() =>
        AnonymousPaths.Matches("/portal", _withPortalWithdrawn).ShouldBeFalse();

    [Fact] void should_match_the_prefix_the_replacement_declares() =>
        AnonymousPaths.Matches("/status", _withPortalWithdrawn).ShouldBeTrue();

    [Fact] void should_not_carry_the_withdrawn_prefix_into_a_later_configuration() =>
        AnonymousPaths.Matches("/status", _withPortalAnonymousAgain).ShouldBeFalse();

    [Fact] void should_resolve_a_separate_instance_declaring_the_same_prefix() =>
        AnonymousPaths.Matches("/portal", _withPortalAnonymousAgain).ShouldBeTrue();
}
