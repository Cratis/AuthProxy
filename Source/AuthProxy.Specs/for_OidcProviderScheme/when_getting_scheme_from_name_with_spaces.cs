// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_OidcProviderScheme;

public class when_getting_scheme_from_name_with_spaces : Specification
{
    string _result;

    void Because() => _result = OidcProviderScheme.FromName("My Provider");

    [Fact] void should_replace_spaces_with_dashes() => Assert.Equal("my-provider", _result);
}
