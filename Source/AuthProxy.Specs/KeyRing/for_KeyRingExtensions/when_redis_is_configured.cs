// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection.StackExchangeRedis;

namespace Cratis.AuthProxy.KeyRing.for_KeyRingExtensions;

public class when_redis_is_configured : given.a_key_ring_configuration
{
    protected override IDictionary<string, string?> Settings => new Dictionary<string, string?>
    {
        [$"{Section}:DataProtection:Store"] = "Redis",
        [$"{Section}:DataProtection:Redis:ConnectionString"] = "127.0.0.1:1,abortConnect=false,connectTimeout=300",
    };

    void Because() => Build();

    [Fact] void should_persist_to_redis() => _options.XmlRepository.ShouldBeOfExactType<RedisXmlRepository>();
}
