-module(eval_tests).

-include_lib("eunit/include/eunit.hrl").

eval_test_() ->
    [{setup, fun test_util:port_setup/0,
      fun test_util:port_teardown/1,
      [
      fun() ->
              %% Regression test case for embedded error properties in function return values
              P = test_util:get_thing(),
              ?assertMatch({ok,123}, perl:eval(P, <<"123">>)),
              erlang:unlink(P) end,
       fun() ->
               P = test_util:get_thing(),
               ?assertMatch({ok,<<"abc">>}, perl:eval(P, <<"'abc'">>)),
               erlang:unlink(P) end,
       fun() ->
               P = test_util:get_thing(),
               ?assertMatch({error,<<"Can't modify constant item in scalar assignment at 'test_eval' line 1, at EOF\n">>}, perl:eval(P, <<"#line 1 'test_eval'\n0=1">>)),
               erlang:unlink(P) end
      ]      
     }].

function_test_() ->
    [{setup, fun test_util:port_setup/0,
      fun test_util:port_teardown/1,
      [
      fun() ->
              %% Regression test case for embedded error properties in function return values
              P = test_util:get_thing(),
              ?assertMatch({error,<<"syntax error at 'test_eval' line 1, near \"{ =\"\n">>}, perl:define(P, <<"#line 1 'test_eval'\nsub { = syntax error }">>)),
              erlang:unlink(P) end,
       fun() ->
               P = test_util:get_thing(),
               {ok, Sub} = perl:define(P, <<"sub { 101; }">>),
               ?assertMatch({ok, 101}, perl:call_sub(P, Sub, [1])),
               erlang:unlink(P) end,
       fun() ->
               P = test_util:get_thing(),
               {ok, Sub} = perl:define(P, <<"sub { return $_[0][0] + $_[0][1]; };">>),
               ?assertMatch({ok, 95}, perl:call_sub(P, Sub, [85, 10])),
               erlang:unlink(P) end,
       fun() ->
               P = test_util:get_thing(),
               {ok, Sub} = perl:define(P, <<"sub { return $_[0][0]{first}; };">>),
               Data = {struct, [{<<"first">>, <<"abc">>}]},
               ?assertMatch({ok, <<"abc">>}, perl:call_sub(P, Sub, [Data])),
               erlang:unlink(P) end,
       fun() ->
               P = test_util:get_thing(),
               {ok, Sub} = perl:define(P, <<"sub { return $_[0][0][1]{first}; }">>),
               ?assertMatch({ok, <<"abc">>}, perl:call_sub(P, Sub, [[1,{struct, [{<<"first">>, <<"abc">>}]}]])),
               erlang:unlink(P) end
      ]      
     }].
