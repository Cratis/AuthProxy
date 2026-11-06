// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackDispatcher;

public class when_a_leading_slash_callback_uses_an_https_backend : given.a_dispatcher
{
    void Establish()
    {
        _service.Backend = new() { BaseUrl = "https://backend.example/base/" };
        _service.ForwardedIdentity = new();
    }

    void Because() => SignIn();

    [Fact] void should_queue_the_callback() => _queue.Requests.Count.ShouldEqual(1);
    [Fact] void should_keep_the_https_backend_and_path() => _queue.Requests.Single().Url.ShouldEqual("https://backend.example/base/.cratis/showrunner/sign-in");
}
