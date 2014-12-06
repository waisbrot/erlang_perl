%% @author Kevin Smith <ksmith@basho.com>
%% @copyright 2009-2010 Basho Technologies
%%
%%    Licensed under the Apache License, Version 2.0 (the "License");
%%    you may not use this file except in compliance with the License.
%%    You may obtain a copy of the License at
%%
%%        http://www.apache.org/licenses/LICENSE-2.0
%%
%%    Unless required by applicable law or agreed to in writing, software
%%    distributed under the License is distributed on an "AS IS" BASIS,
%%    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%    See the License for the specific language governing permissions and
%%    limitations under the License.

%% @doc This module manages all of the low-level details surrounding the
%% linked-in driver. It is reponsible for loading and unloading the driver
%% as needed. This module is also reponsible for creating and destroying
%% instances of Javascript VMs.

-module(perl_driver).

-export([load_driver/0, new/0, restart/1, destroy/1]).
-export([define_perl/2, define_perl/3, eval_perl/2, eval_perl/3]).
-export([call_perl_sub/2, call_perl_sub/3]).

-define(SCRIPT_TIMEOUT, 5000).
-define(DRIVER_NAME, "erlang_perl_drv").

%% @spec load_driver() -> true | false
%% @doc Attempt to load the Javascript driver
load_driver() ->
    {ok, Drivers} = erl_ddll:loaded_drivers(),
    case lists:member(?DRIVER_NAME, Drivers) of
        false ->
            case erl_ddll:load(priv_dir(), ?DRIVER_NAME) of
                ok ->
                    true;
                {error, Error} ->
                    error_logger:error_msg("Error loading ~p: ~p~n", [?DRIVER_NAME, erl_ddll:format_error(Error)]),
                    false
            end;
        true ->
            true
    end.

%% @spec new() -> {ok, port()} | {error, atom()} | {error, any()}
%% @doc Create a new Javascript VM instance and preload Douglas Crockford's
%% json2 converter (http://www.json.org/js.html). Uses a default heap
%% size of 8MB and a default thread stack size of 8KB.
new() ->
    new(no_json).

%% @type init_fun() = function(port()).
%% @spec new(int(), int(), no_json | init_fun() | {ModName::atom(), FunName::atom()}) -> {ok, port()} | {error, atom()} | {error, any()}
%% @doc Create a new Javascript VM instance. The function arguments control how the VM instance is initialized.
%% User supplied initializers must return true or false.
new(no_json) ->
    Port = open_port({spawn, ?DRIVER_NAME}, [binary]),
    {ok, Port};
new(Initializer) when is_function(Initializer) ->
    {ok, Port} = new(),
    case Initializer(Port) of
        ok ->
            {ok, Port};
        {error, Error} ->
            perl_driver:destroy(Port),
            error_logger:error_report(Error),
            throw({error, init_failed})
    end;
new({InitMod, InitFun}) ->
    {ok, Port} = new(),
    case InitMod:InitFun(Port) of
        ok ->
            {ok, Port};
        {error, Error} ->
            perl_driver:destroy(Port),
            error_logger:error_report(Error),
            throw({error, init_failed})
    end.

%% @spec restart(port()) -> ok
%% @doc Destroys a Perl VM instance
restart(Ctx) ->
    call_driver(Ctx, "rp", [], 60000).

%% @spec destroy(port()) -> ok
%% @doc Destroys a Javascript VM instance
destroy(Ctx) ->
    port_close(Ctx).

%% @spec define_perl(port(), binary()) -> ok | {error, any()}
%% @doc Define a Javascript expression:
%% perl_driver:define(Port, &lt;&lt;"var x = 100;"&gt;&gt;).
define_perl(Ctx, Perl) ->
    define_perl(Ctx, Perl, ?SCRIPT_TIMEOUT).

%% @private
%%define_perl(Ctx, {file, FileName}, Timeout) ->
%%    {ok, File} = file:read_file(FileName),
%%    _ = file,
%%    define_perl(Ctx, File, Timeout);

%% @spec define_perl(port(), binary(), integer()) -> {ok, binary()} | {error, any()}
%% @doc Define anonymous Perl subroutine:
define_perl(Ctx, Perl, Timeout) when is_binary(Perl) ->
    case call_driver(Ctx, "ip", [Perl], Timeout) of
        {ok, Result} ->
            {ok, Result};
        {error, Error} ->
            {error, Error};
        ok ->
            ok
    end.

call_perl_sub(Ctx, SubName) ->
    call_perl_sub(Ctx, SubName, [], ?SCRIPT_TIMEOUT).

call_perl_sub(Ctx, SubName, Payload) ->
    call_perl_sub(Ctx, SubName, Payload, ?SCRIPT_TIMEOUT).

call_perl_sub(Ctx, SubName, Payload, Timeout) ->
    case call_driver(Ctx, "cp", [SubName, list_to_binary(perl_mochijson2:encode(Payload))], Timeout) of
        {error, ErrorJson} when is_binary(ErrorJson) ->
            erlang:display(ErrorJson),
            {struct, [{<<"error">>, {struct, Error}}]} = perl_mochijson2:decode(ErrorJson),
            {error, Error};
        {ok, Result} ->
            {ok, hd(perl_mochijson2:decode(Result))};
        {error, Error} ->
            {error, Error};
        ok ->
            ok
    end.

%% @private
eval_perl(Ctx, Code) when is_binary(Code) ->
    eval_perl(Ctx, Code, ?SCRIPT_TIMEOUT).

eval_perl(Ctx, Code, Timeout) when is_binary(Code) ->
    case call_driver(Ctx, "ep", [Code], Timeout) of
        {ok, Result} ->
            {ok, hd(perl_mochijson2:decode(Result))};
        {error, Error} ->
            {error, Error}
    end.

%% @private
priv_dir() ->
    %% Hacky workaround to handle running from a standard app directory
    %% and .ez package
    case code:priv_dir(erlang_perl) of
        {error, bad_name} ->
            filename:join([filename:dirname(code:which(?MODULE)), "..", "priv"]);
        Dir ->
            Dir
    end.

%% @private
call_driver(Ctx, Command, Args, Timeout) ->
    CallToken = make_call_token(),
    Marshalled = js_drv_comm:pack(Command, [CallToken] ++ Args),
    port_command(Ctx, Marshalled),
    Result = receive
                 {CallToken, ok} ->
                     ok;
                 {CallToken, ok, R} ->
                     {ok, R};
                 {CallToken, error, Error} ->
                     {error, Error}
             after Timeout ->
                     {error, timeout}
             end,
    Result.

%% @private
make_call_token() ->
    list_to_binary(integer_to_list(erlang:phash2(erlang:make_ref()))).

