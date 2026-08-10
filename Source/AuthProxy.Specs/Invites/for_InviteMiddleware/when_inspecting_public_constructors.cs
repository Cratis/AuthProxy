// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

/// <summary>
/// Specifies the released and resolver-aware public constructor contracts for <see cref="InviteMiddleware"/>.
/// </summary>
public class when_inspecting_public_constructors : Specification
{
    bool _hasReleasedConstructor;
    bool _hasResolverAwareConstructor;
    bool _hasAttestationAwareConstructor;

    void Because()
    {
        var constructors = typeof(InviteMiddleware).GetConstructors();
        _hasReleasedConstructor = constructors.Any(_ => HasParameters(_, ReleasedParameterTypes));
        _hasResolverAwareConstructor = constructors.Any(_ => HasParameters(_, ResolverAwareParameterTypes));
        _hasAttestationAwareConstructor = constructors.Any(_ => HasParameters(_, AttestationAwareParameterTypes));
    }

    [Fact] void should_keep_the_released_eight_argument_constructor() => _hasReleasedConstructor.ShouldBeTrue();
    [Fact] void should_expose_the_resolver_aware_constructor() => _hasResolverAwareConstructor.ShouldBeTrue();
    [Fact] void should_expose_the_attestation_aware_constructor() => _hasAttestationAwareConstructor.ShouldBeTrue();

    static Type[] ReleasedParameterTypes =>
    [
        typeof(RequestDelegate),
        typeof(IInviteTokenValidator),
        typeof(IOptionsMonitor<C.AuthProxy>),
        typeof(IOptionsMonitor<C.Authentication>),
        typeof(ITenantResolver),
        typeof(IHttpClientFactory),
        typeof(IErrorPageProvider),
        typeof(ILogger<InviteMiddleware>)
    ];

    static Type[] ResolverAwareParameterTypes =>
    [
        .. ReleasedParameterTypes,
        typeof(ICanonicalIdentityResolver)
    ];

    static Type[] AttestationAwareParameterTypes =>
    [
        .. ResolverAwareParameterTypes,
        typeof(IInvitationAttestationIssuer),
        typeof(IInvitationEntryStateProtector)
    ];

    static bool HasParameters(System.Reflection.ConstructorInfo constructor, Type[] expected) =>
        constructor.GetParameters().Select(_ => _.ParameterType).SequenceEqual(expected);
}
