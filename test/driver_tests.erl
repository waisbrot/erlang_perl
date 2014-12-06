-module(driver_tests).

-include_lib("eunit/include/eunit.hrl").

load_test_() ->
  [{setup, fun test_util:port_setup/0,
    fun test_util:port_teardown/1,
    [fun() ->
         P = test_util:get_thing(),
         ?assert(is_port(P)),
         erlang:unlink(P) end]}].

destroy_test_() ->
  [{setup, fun test_util:port_setup/0,
    fun test_util:null_teardown/1,
    [fun() ->
         P = test_util:get_thing(),
         ?assertMatch(true, perl_driver:destroy(P)),
         ?assertError(badarg, perl:define(P, <<"sub { 100; }">>)),
         erlang:unlink(P) end]}].

spinup_test_() ->
  [fun() ->
       F = fun({ok, P}) -> perl_driver:restart(P) end,
       Ports = [perl_driver:new() || _X <- lists:seq(1, 16)],
       [F(P) || P <- Ports] end].
