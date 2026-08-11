// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy.when_recognizing_a_presentation;

/// <summary>
/// Matching by prefix would make the path itself a place to put a capability, which is the one place it
/// must never be: a path is written into access logs, proxy cache keys and browser history. Anything below
/// the configured path is an ordinary unadmitted request.
/// </summary>
public class and_something_below_the_admission_path_is_requested : given.an_admission_policy
{
    bool _isPresentation;

    void Establish() => _context.Request.Path = "/.cratis/admission/a-capability-in-the-path";

    void Because() => _isPresentation = _policy.IsPresentation(_context, _config);

    [Fact] void should_not_recognize_a_presentation() => _isPresentation.ShouldBeFalse();
}
