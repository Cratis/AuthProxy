// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.AccessTokens.given;

/// <summary>
/// A real <see cref="UserTokenStore"/> on an in-memory cache and an ephemeral key ring.
/// </summary>
public class a_user_token_store : Specification
{
    protected RecordingDistributedCache _cache;
    protected ManualTime _time;
    protected UserTokenStore _store;
    protected C.AuthProxy _config;

    void Establish()
    {
        _time = new ManualTime(new DateTimeOffset(2026, 10, 1, 12, 0, 0, TimeSpan.Zero));
        _cache = new RecordingDistributedCache(_time);
        _config = new C.AuthProxy();
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(_ => _config);
        _store = new UserTokenStore(_cache, new EphemeralDataProtectionProvider(), config, _time);
    }
}
