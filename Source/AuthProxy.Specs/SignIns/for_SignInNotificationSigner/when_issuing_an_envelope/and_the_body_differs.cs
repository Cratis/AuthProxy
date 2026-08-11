// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.given;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.when_issuing_an_envelope;

/// <summary>
/// The body binding, mutated on its own — the route is held identical so only the bytes move. A forged body
/// differing by a single character produces a different digest, which is what makes the subject of a
/// notification unforgeable rather than merely transported.
/// </summary>
public class and_the_body_differs : a_sign_in_notification_signer
{
    static readonly byte[] _forgedBody = Encoding.UTF8.GetBytes("{\"subject\":\"subject-124\"}");

    JsonWebToken _honest;
    JsonWebToken _forged;

    void Because()
    {
        _signer.TryIssue(HttpMethod.Post, Target, Body, out var honest);
        _signer.TryIssue(HttpMethod.Post, Target, _forgedBody, out var forged);
        _honest = Read(honest);
        _forged = Read(forged);
    }

    [Fact] void should_digest_the_honest_bytes() => Claim(_honest, SignInAttestationClaims.BodyHash).ShouldEqual(Digest(Body));
    [Fact] void should_digest_the_forged_bytes() => Claim(_forged, SignInAttestationClaims.BodyHash).ShouldEqual(Digest(_forgedBody));
    [Fact] void should_not_reuse_one_digest_for_two_bodies() => (Claim(_honest, SignInAttestationClaims.BodyHash) == Claim(_forged, SignInAttestationClaims.BodyHash)).ShouldBeFalse();
    [Fact] void should_not_let_the_route_binding_move_with_it() => Claim(_honest, SignInAttestationClaims.HttpUri).ShouldEqual(Claim(_forged, SignInAttestationClaims.HttpUri));
}
