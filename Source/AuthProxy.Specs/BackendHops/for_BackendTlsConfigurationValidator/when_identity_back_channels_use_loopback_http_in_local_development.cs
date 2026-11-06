// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_identity_back_channels_use_loopback_http_in_local_development : identity_back_channels
{
    protected override C.DeploymentProfile Profile => C.DeploymentProfile.LocalDevelopment;

    void Because() => _result = new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, _configuration);

    [Fact] void should_allow_http_back_channels() => _result.Succeeded.ShouldBeTrue();
}
