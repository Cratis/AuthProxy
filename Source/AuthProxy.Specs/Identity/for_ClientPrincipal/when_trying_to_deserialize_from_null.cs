// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_ClientPrincipal;

public class when_trying_to_deserialize_from_null : Specification
{
    bool _succeeded;
    ClientPrincipal? _result;

    void Because() => _succeeded = ClientPrincipal.TryFromBase64(null, out _result);

    [Fact] void should_not_succeed() => Assert.False(_succeeded);
    [Fact] void should_return_null_principal() => Assert.Null(_result);
}
