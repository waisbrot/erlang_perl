-module(test_suite).

-include_lib("eunit/include/eunit.hrl").

all_test_() ->
    erlang_perl:start(),
    [{module, driver_tests},
     {module, eval_tests}].
