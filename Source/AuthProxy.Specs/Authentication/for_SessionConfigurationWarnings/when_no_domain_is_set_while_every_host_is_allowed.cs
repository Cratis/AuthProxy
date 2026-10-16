// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionConfigurationWarnings;

public class when_no_domain_is_set_while_every_host_is_allowed : Specification
{
    string[] _warnings;

    void Because() => _warnings = [.. SessionConfigurationWarnings.Describe(new C.Session(), ["*"])];

    [Fact] void should_not_warn() => _warnings.ShouldBeEmpty();
}
