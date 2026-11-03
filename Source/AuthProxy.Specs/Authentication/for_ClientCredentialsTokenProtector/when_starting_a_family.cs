// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsTokenProtector;

public class when_starting_a_family : given.a_client_credentials_token_protector
{
    protected override TimeSpan FamilyLifetime => TimeSpan.FromDays(7);

    DateTimeOffset _deadline;

    void Because() => _deadline = Protector.StartFamily(Service);

    [Fact] void should_end_the_configured_lifetime_from_now() => _deadline.ShouldEqual(Time.GetUtcNow().AddDays(7));
}
