// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier;

/// <summary>
/// The compatibility contract. The signer is wired exactly as the host wires it, but no
/// <c>SignIn:Attestation</c> section exists — so the request that leaves must be indistinguishable from the
/// one the released four-argument notifier sends: the same body bytes, and no <c>Authorization</c> header.
/// </summary>
public class when_signing_is_not_configured : a_signed_sign_in_notifier
{
    protected override C.SignInAttestation? CreateAttestation() => null;

    SignInNotificationResult _result;
    byte[] _bytes;
    byte[] _releasedBytes;

    async Task Because()
    {
        _result = await _notifier.Notify(_httpContext, _principal);
        _bytes = _handler.LastRequestBytes.ToArray();
        _releasedBytes = (await NotifyThroughTheReleasedNotifier()).LastRequestBytes.ToArray();
    }

    [Fact] void should_notify() => _result.ShouldEqual(SignInNotificationResult.Notified);
    [Fact] void should_not_authenticate_the_request() => _handler.LastRequestAuthorization.ShouldBeNull();
    [Fact] void should_send_the_released_json() => Encoding.UTF8.GetString(_bytes).ShouldEqual(Encoding.UTF8.GetString(_releasedBytes));
    [Fact] void should_send_the_released_number_of_bytes() => _bytes.Length.ShouldEqual(_releasedBytes.Length);
    [Fact] void should_not_be_comparing_two_empty_bodies() => _releasedBytes.ShouldNotBeEmpty();
}
