// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.given;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.when_issuing_an_envelope;

/// <summary>
/// The route binding, mutated on its own. Signing two different routes with everything else held constant is
/// the only thing that separates a real route binding from two constants that happen to read correctly for
/// the single route the notifier actually uses.
/// </summary>
public class and_the_route_differs : a_sign_in_notification_signer
{
    static readonly Uri _otherTarget = new("https://elsewhere.example.com/hook");

    JsonWebToken _first;
    JsonWebToken _second;

    void Because()
    {
        _signer.TryIssue(HttpMethod.Post, Target, Body, out var first);
        _signer.TryIssue(HttpMethod.Put, _otherTarget, Body, out var second);
        _first = Read(first);
        _second = Read(second);
    }

    [Fact] void should_bind_the_first_method() => Claim(_first, SignInAttestationClaims.HttpMethod).ShouldEqual("POST");
    [Fact] void should_bind_the_second_method() => Claim(_second, SignInAttestationClaims.HttpMethod).ShouldEqual("PUT");
    [Fact] void should_bind_the_first_target() => Claim(_first, SignInAttestationClaims.HttpUri).ShouldEqual("https://studio.example.com/api/internal/sign-ins");
    [Fact] void should_bind_the_second_target() => Claim(_second, SignInAttestationClaims.HttpUri).ShouldEqual("https://elsewhere.example.com/hook");
    [Fact] void should_not_leave_the_body_binding_free_to_move() => Claim(_first, SignInAttestationClaims.BodyHash).ShouldEqual(Claim(_second, SignInAttestationClaims.BodyHash));
}
