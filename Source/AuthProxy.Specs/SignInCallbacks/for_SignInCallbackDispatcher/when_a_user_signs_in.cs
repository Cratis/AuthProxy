// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackDispatcher;

public class when_a_user_signs_in : given.a_dispatcher
{
    void Because() => SignIn();

    [Fact] void should_queue_one_callback() => _queue.Requests.Count.ShouldEqual(1);
    [Fact] void should_report_a_sign_in() => _queue.Requests[0].Kind.ShouldEqual(SignInCallbackKind.SignedIn);
    [Fact] void should_name_the_service() => _queue.Requests[0].ServiceName.ShouldEqual(ServiceName);
    [Fact] void should_post_to_the_configured_path_on_the_backend() => _queue.Requests[0].Url.ShouldEqual("http://app.internal:8080/.cratis/showrunner/sign-in");
    [Fact] void should_describe_the_user() => _queue.Requests[0].Principal.UserId.ShouldEqual("user-1");
    [Fact] void should_carry_the_resolved_tenant() => _queue.Requests[0].Tenant.ShouldEqual(Tenant);
    [Fact] void should_stamp_the_time() => _queue.Requests[0].Occurred.ShouldEqual(_time.GetUtcNow());
    [Fact] void should_use_the_default_timeout() => _queue.Requests[0].Timeout.ShouldEqual(TimeSpan.FromSeconds(5));
}
