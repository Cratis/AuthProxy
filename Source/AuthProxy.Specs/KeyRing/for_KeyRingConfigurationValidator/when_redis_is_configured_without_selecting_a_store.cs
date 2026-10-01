// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.KeyRing.for_KeyRingConfigurationValidator;

public class when_redis_is_configured_without_selecting_a_store : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new KeyRingConfigurationValidator().Validate(null, new C.AuthProxy
    {
        DataProtection = new()
        {
            Redis = new() { ConnectionString = "redis:6379" },
        },
    });

    [Fact] void should_refuse_the_configuration() => _result.Failed.ShouldBeTrue();
    [Fact] void should_fail_once_for_the_ignored_section() => _result.Failures.Count().ShouldEqual(1);
    [Fact] void should_name_the_ignored_redis_section() => _result.FailureMessage!.ShouldContain("DataProtection:Redis");
    [Fact] void should_name_the_default_store() => _result.FailureMessage!.ShouldContain("DataProtection:Store is 'FileSystem'");
}
