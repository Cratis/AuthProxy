// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_OidcProviderScheme;

public class when_getting_scheme_from_simple_name : Specification
{
    string _result;

    void Because() => _result = OidcProviderScheme.FromName("Microsoft");

    [Fact] void should_return_lowercase_name() => Assert.Equal("microsoft", _result);
}
