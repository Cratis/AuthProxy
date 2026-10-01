// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.KeyRing.for_KeyRingConfigurationValidator;

public class when_a_key_path_is_configured : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new KeyRingConfigurationValidator().Validate(null, new C.AuthProxy { DataProtectionKeysPath = "/mnt/keys" });

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
