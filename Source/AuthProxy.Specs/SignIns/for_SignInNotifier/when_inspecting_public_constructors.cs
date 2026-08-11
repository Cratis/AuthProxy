// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier;

/// <summary>
/// Specifies the released and resolver-aware public constructor contracts for <see cref="SignInNotifier"/>.
/// </summary>
public class when_inspecting_public_constructors : Specification
{
    bool _hasReleasedConstructor;
    bool _hasResolverAwareConstructor;
    bool _hasSignerAwareConstructor;

    void Because()
    {
        var constructors = typeof(SignInNotifier).GetConstructors();
        _hasReleasedConstructor = constructors.Any(_ => HasParameters(_, ReleasedParameterTypes));
        _hasResolverAwareConstructor = constructors.Any(_ => HasParameters(_, ResolverAwareParameterTypes));
        _hasSignerAwareConstructor = constructors.Any(_ => HasParameters(_, SignerAwareParameterTypes));
    }

    [Fact] void should_keep_the_released_four_argument_constructor() => _hasReleasedConstructor.ShouldBeTrue();
    [Fact] void should_expose_the_resolver_aware_constructor() => _hasResolverAwareConstructor.ShouldBeTrue();
    [Fact] void should_expose_the_signer_aware_constructor() => _hasSignerAwareConstructor.ShouldBeTrue();

    static Type[] ReleasedParameterTypes =>
    [
        typeof(IOptionsMonitor<C.AuthProxy>),
        typeof(IClientLocationResolver),
        typeof(IHttpClientFactory),
        typeof(ILogger<SignInNotifier>)
    ];

    static Type[] ResolverAwareParameterTypes =>
    [
        .. ReleasedParameterTypes,
        typeof(ICanonicalIdentityResolver)
    ];

    static Type[] SignerAwareParameterTypes =>
    [
        .. ResolverAwareParameterTypes,
        typeof(ISignInNotificationSigner)
    ];

    static bool HasParameters(System.Reflection.ConstructorInfo constructor, Type[] expected) =>
        constructor.GetParameters().Select(_ => _.ParameterType).SequenceEqual(expected);
}
