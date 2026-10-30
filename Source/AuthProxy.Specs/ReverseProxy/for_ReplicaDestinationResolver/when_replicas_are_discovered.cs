// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaDestinationResolver;

public class when_replicas_are_discovered : given.a_resolver
{
    void Establish() => Discovers("10.0.0.1", "10.0.0.2");

    async Task Because() => _result = await Resolve();

    [Fact] void should_publish_one_destination_per_replica() => _result.Destinations.Count.ShouldEqual(2);
    [Fact] void should_not_publish_the_seed() => _result.Destinations.ContainsKey(SeedId).ShouldBeFalse();
    [Fact] void should_id_each_replica_from_the_seed_and_a_hash() => _result.Destinations.Keys.All(id => id.StartsWith(SeedId + "#", StringComparison.Ordinal) && id.Length == SeedId.Length + 17 && id[(SeedId.Length + 1)..].All(character => char.IsAsciiHexDigitUpper(character))).ShouldBeTrue();
    [Fact] void should_not_put_an_address_in_an_id() => _result.Destinations.Keys.Any(id => id.Contains("10.0.0")).ShouldBeFalse();
    [Fact] void should_address_each_replica() => _result.Destinations.Values.Select(_ => _.Address).Order().ShouldEqual(["https://10.0.0.1:8443/", "https://10.0.0.2:8443/"]);
    [Fact] void should_send_the_service_authority_as_host() => _result.Destinations.Values.All(_ => _.Host == "core:8443").ShouldBeTrue();
    [Fact] void should_keep_the_metadata() => _result.Destinations.Values.All(_ => _.Metadata[MicroserviceReverseProxyConfigProvider.ServiceMetadataKey] == "core").ShouldBeTrue();
    [Fact] void should_offer_a_change_token_that_has_not_changed() => _result.ChangeToken.HasChanged.ShouldBeFalse();
}
