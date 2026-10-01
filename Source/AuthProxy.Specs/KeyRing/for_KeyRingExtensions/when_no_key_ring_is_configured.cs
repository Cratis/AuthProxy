// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.KeyRing.for_KeyRingExtensions;

public class when_no_key_ring_is_configured : given.a_key_ring_configuration
{
    void Because() => Build();

    [Fact] void should_leave_the_framework_default_repository() => _options.XmlRepository.ShouldBeNull();
    [Fact] void should_not_protect_the_keys_at_rest() => _options.XmlEncryptor.ShouldBeNull();
}
