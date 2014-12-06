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

%% @doc Convenience module for interacting with Javascript from Erlang.
%% The functions provided by this module marshal bindings and function
%% args into JSON before sending them to Javascript. While this does
%% incur a certain amount of overhead it has the benefit of (mostly)
%% preserving types as they roundtrip between Erlang and Javascript.
%% Of course, this also means all Erlang values MUST BE convertable
%% into JSON. In practice, this is less restricting than it sounds.
-module(perl).

-export([define/2, call_sub/2, call_sub/3, eval/2]).


%% @spec define(port(), binary()) -> ok | {error, any()}
%% @doc Define one or more Perl expressions.
define(Ctx, Perl) ->
    perl_driver:define_perl(Ctx, Perl).

call_sub(Ctx, SubName) ->
    call_sub(Ctx, SubName, []).

call_sub(Ctx, SubName, Bindings) ->
    perl_driver:call_perl_sub(Ctx, SubName, Bindings).

eval(Ctx, Perl) ->
    perl_driver:eval_perl(Ctx, Perl).
