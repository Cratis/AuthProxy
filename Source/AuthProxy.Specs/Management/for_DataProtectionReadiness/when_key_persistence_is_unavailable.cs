// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection.Repositories;

namespace Cratis.AuthProxy.Management.for_DataProtectionReadiness;

/// <summary>
/// An instance whose key ring will not initialize is not ready, and says so.
/// <para>
/// This is the failure the whole endpoint exists for. The key ring encrypts the authentication cookie and
/// every AuthProxy-issued token, so an instance that cannot build one cannot serve a single authenticated
/// request — and it accepts sockets perfectly well while failing to, which is precisely why the TCP probe a
/// deployment falls back to reports it healthy and keeps sending it traffic.
/// </para>
/// </summary>
public class when_key_persistence_is_unavailable : given.a_readiness_check
{
    bool _ready;

    protected override IXmlRepository? KeyStorage => new given.UnreachableKeyStorage();

    async Task Because() => _ready = await _readiness.IsReady(CancellationToken.None);

    [Fact] void should_not_be_ready() => _ready.ShouldBeFalse();
}
