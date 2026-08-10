// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management.for_DataProtectionReadiness;

/// <summary>
/// A key ring that initializes against a writable keys directory makes the instance ready.
/// </summary>
public class when_the_key_ring_initializes : given.a_readiness_check
{
    bool _ready;
    bool _readyAgain;

    async Task Because()
    {
        _ready = await _readiness.IsReady(CancellationToken.None);
        _readyAgain = await _readiness.IsReady(CancellationToken.None);
    }

    [Fact] void should_be_ready() => _ready.ShouldBeTrue();

    /// <summary>
    /// Asked twice on purpose. The answer has to be recomputed rather than remembered, because a key ring
    /// that becomes unusable — a volume unmounted, a permission revoked — must be able to change it. A
    /// cached first answer would keep an instance in rotation for as long as the cache lived.
    /// </summary>
    [Fact] void should_still_be_ready_when_asked_again() => _readyAgain.ShouldBeTrue();
}
