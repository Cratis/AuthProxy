// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider.when_sticky_routing_is_enabled;

public class and_the_backend_declares_it : given.a_provider_over_a_sticky_service
{
    ClusterConfig _backend;
    ClusterConfig _frontend;
    IProxyConfig _plain;

    void Because()
    {
        var config = _provider.GetConfig();
        _backend = BackendOf(config);
        _frontend = config.Clusters.Single(_ => _.ClusterId == "reporting-frontend-cluster");
        Provide(Configuration(sticky: false));
        _plain = _provider.GetConfig();
    }

    [Fact] void should_enable_session_affinity() => _backend.SessionAffinity.Enabled.ShouldEqual(true);
    [Fact] void should_use_the_data_protected_cookie_policy() => _backend.SessionAffinity.Policy.ShouldEqual("Cookie");
    [Fact] void should_redistribute_on_failure() => _backend.SessionAffinity.FailurePolicy.ShouldEqual("Redistribute");
    [Fact] void should_name_the_cookie_after_the_service() => _backend.SessionAffinity.AffinityKeyName.ShouldEqual(".cratis-affinity-reporting");
    [Fact] void should_set_a_host_only_path_wide_cookie() => (_backend.SessionAffinity.Cookie.Path == "/" && _backend.SessionAffinity.Cookie.Domain is null).ShouldBeTrue();
    [Fact] void should_set_a_session_cookie() => (_backend.SessionAffinity.Cookie.Expiration is null && _backend.SessionAffinity.Cookie.MaxAge is null).ShouldBeTrue();
    [Fact] void should_keep_the_cookie_from_scripts() => _backend.SessionAffinity.Cookie.HttpOnly.ShouldEqual(true);
    [Fact] void should_set_the_cookie_same_site_lax() => _backend.SessionAffinity.Cookie.SameSite.ShouldEqual(SameSiteMode.Lax);
    [Fact] void should_set_the_cookie_secure_when_the_request_is() => _backend.SessionAffinity.Cookie.SecurePolicy.ShouldEqual(CookieSecurePolicy.SameAsRequest);
    [Fact] void should_mark_the_cookie_essential() => _backend.SessionAffinity.Cookie.IsEssential.ShouldEqual(true);
    [Fact] void should_check_health_passively() => (_backend.HealthCheck.Passive.Enabled == true && _backend.HealthCheck.Passive.Policy == "TransportFailureRate").ShouldBeTrue();
    [Fact] void should_fall_back_to_all_destinations_when_none_is_healthy() => _backend.HealthCheck.AvailableDestinationsPolicy.ShouldEqual("HealthyOrPanic");
    [Fact] void should_publish_one_seed_destination() => _backend.Destinations.Single().Value.Address.ShouldEqual("http://reporting:8080/");
    [Fact] void should_mark_the_seed_with_the_replica_host() => _backend.Destinations.Single().Value.Metadata[MicroserviceReverseProxyConfigProvider.ReplicaHostMetadataKey].ShouldEqual("reporting-headless.svc");
    [Fact] void should_mark_the_seed_with_the_refresh_interval() => _backend.Destinations.Single().Value.Metadata[MicroserviceReverseProxyConfigProvider.ReplicaRefreshMetadataKey].ShouldEqual("00:00:15");
    [Fact] void should_mark_the_seed_with_the_service() => _backend.Destinations.Single().Value.Metadata[MicroserviceReverseProxyConfigProvider.ServiceMetadataKey].ShouldEqual("reporting");
    [Fact] void should_leave_the_frontend_without_affinity() => _frontend.SessionAffinity.ShouldBeNull();
    [Fact] void should_leave_the_frontend_without_health_checks() => _frontend.HealthCheck.ShouldBeNull();
    [Fact] void should_leave_the_other_service_as_it_would_be() => BackendOf(_plain, "portal").ShouldEqual(BackendOf(_provider.GetConfig(), "portal"));
}
