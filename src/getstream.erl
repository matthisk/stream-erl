-module(getstream).

-behaviour(application).

%% Application callbacks
-export([start/0, start/2, stop/1]).

-export([
		basic_auth/2,
		feed_id/2,
		get_activities/2
		]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% ===================================================================
%% Types
%% ===================================================================

-type state() :: pending | success | error | failure.
-type credentials() ::
    {basic, Key :: string(), Secret :: string()}
    | {oauth, Token :: string()}.
-type signature() :: base64:asci_binary().
-type feed_id() :: {string(), string()}.
-type activity() :: map().
-type result() :: ok | {ok, term()} | {error, term()}.

-type method() :: get | post | put | delete.

%% ===================================================================
%% Application callbacks
%% ===================================================================

%% @hidden
-spec start() -> {ok, [atom()]}.
start() -> application:ensure_all_started(getstream).


-spec start(application:start_type(), term()) ->
	{ok, pid()} | {ok, pid(), term()} | {error, term()}.
start(_StartType, _StartArgs) ->
    getstream_sup:start_link().

-spec stop(term()) -> ok.
stop(_State) ->
    ok.

-spec basic_auth(string(), string()) -> credentials().
basic_auth(Key, Secret) ->
	{basic, Key, Secret}.

-spec feed_id(string(), string()) -> feed_id().
feed_id(Slug, Id) ->
	{Slug, Id}.


-spec get_activities(credentials(), feed_id()) ->
	jiffy:json_value().
get_activities(Credentials, FeedId) ->
	get_activities(Credentials, FeedId, #{}).

-spec get_activities(credentials(), feed_id(), map()) ->
	jiffy:json_value().
get_activities(Credentials, FeedId, Options) ->
	Uri = make_url(feed_detail, Credentials, FeedId),
	Signature = sign(Credentials, FeedId),
	{ok, Result} = run(Signature, Uri, Options),
	jiffy:decode(Result, [return_maps]).


-spec add_activities(credentials(), feed_id(), [activity()]) ->
	jiffy:json_value().
add_activities(Credentials, FeedId, Activities) ->
	post(Credentials, FeedId, Activities).

-spec add_activity(credentials(), feed_id(), activity()) ->
	jiffy:json_value().
add_activity(Credentials, FeedId, Activity) ->
	add_activities(Credentials, FeedId, [Activity]).


-spec follow(credentials(), feed_id(), feed_id(), map()) ->
	jiffy:json_value().
follow(Credentials, FeedId, TargetId, #{}) ->
	follow(Credentials, FeedId, TargetId, #{ activity_copy_limit => 20 });
follow(Credentials, FeedId, TargetId, #{ activity_copy_limit := ActivityCopyLimit }) ->
	BodyMap = #{ target => TargetId, activity_copy_limit => ActivityCopyLimit },
	Body = jiffy:encode(BodyMap),
	post(Credentials, FeedId, Body).


-spec post(credentials(), feed_id(), term()) ->
	jiffy:json_value().
post(Credentials, FeedId, Body) ->
	Uri = make_url(feed_detail, Credentials, FeedId),
	Signature = sign(Credentials, FeedId),
	RawBody = jiffy:encode(Body),
	erlang:display(RawBody),
	{ok, Result} = run(Signature, Uri, post, RawBody, #{}),
	jiffy:decode(Result, [return_maps]).


-spec run(signature(), string(), map()) ->
	string() | {error, term()}.
run(Signature, Uri, Options) ->
	run(Signature, Uri, get, [], Options).

-spec run(signature(), iodata(), method(), iodata(), map()) ->
	{ok, string()} | {error, term()}.
run(Signature, Uri, Method, Body, Options) ->
	UriQs = append_qs(Uri, Options),
	Headers = [
		{<<"X-Stream-Client">>, <<"stream-erl-0.0.0">>},
		{<<"stream-auth-type">>, <<"simple">>},
		{<<"authorization">>, Signature}
	],
	perform_request(UriQs, Method, Headers, Body, Options).
 

-spec append_qs(iodata(), map()) ->
	iodata().
append_qs(Uri, Options) ->
	[_|QS] = fold(fun(K, V, AccIn) -> "&" ++ K ++ "=" ++ V ++ AccIn end, "", Options),
	Uri ++ "?" ++ QS.	

-spec perform_request(iodata(), shotgun:http_verb(), shotgun:http_headers(), shotgun:body(), map()) ->
	shotgun:result().
perform_request(Uri, Method, Headers, Body, Options) ->
	{ok, Pid} = shotgun:open("api.getstream.io", 443, https),
	try shotgun:request(Pid, Method, Uri, Headers, Body, #{}) of
		{ok, #{status_code := 200, body := RespBody}} ->
			{ok, RespBody};
		{ok, #{status_code := 201, body := RespBody}} ->
			{ok, RespBody};
		{ok, #{status_code := 204, body := RespBody}} ->
			{ok, RespBody};
		{ok, #{status_code := 302, headers := RespHeaders}} ->
			RedirectUrl = proplists:get_value(<<"location">>, RespHeaders),
			run(RedirectUrl, Headers, Method, Body, Options);
		{ok, #{status_code := Status, headers := RespHeaders, body := RespBody}} ->
			{error, {Status, RespHeaders, RespBody}}
	after
		shotgun:close(Pid)
	end.

-spec sign(credentials(), feed_id()) -> signature().
sign({basic, Key, Secret}, {Slug, Id}) ->
	Digest = crypto:hash(sha, list_to_binary(Secret)),
	Data = io_lib:format("~s~s", [Slug, Id]),
	Mac = crypto:hmac(sha, Digest, list_to_binary(Data)),
	Token = base64:encode_to_string(Mac),
	UrlSafeToken = replace(Token, ["/","\\+", "^=+", "=+$"], ["_", "-", "", ""], [{return, list}, global]),
	list_to_binary(io_lib:format("~s ~s", [Data, UrlSafeToken])).

replace(Data, [], [Rep|Reps], Options) ->
	{error, "Supply the same amount of replacements as regular expressions"};
replace(Data, [Reg|Regs], [], Options) ->
	{error, "Supply the same amount of regular expressions as replacements"};
replace(Data, [Reg], [Rep], Options) ->
	re:replace(Data, Reg, Rep, Options);
replace(Data, [Reg|Regs], [Rep|Reps], Options) ->
	Next = re:replace(Data, Reg, Rep, Options),
	replace(Next, Regs, Reps, Options).

authorization({basic, Key, Secret}, Headers)
	-> Headers.

make_url(feed_detail, Credentials, {Slug, Id}) ->
	Url = "/feed/~s/~s/",
	Part = io_lib:format(Url, [Slug, Id]),
	make_url(base, Credentials, Part);

make_url(base, {basic, Key, _}, Part) ->
	Url = "/api/v1.0~s?api_key=~s",
	io_lib:format(Url, [Part, Key]).

-ifdef(TEST).

simple_test() ->
	{ok, _} = getstream:start(),
    ?assertNot(undefined == whereis(getstream_sup)).

replace_test() ->
	Match1 = replace("abc", ["a", "c"], ["b", "b"], [{return, list}, global]),
	replace("abc", ["d"], ["e"], [{return, list}, global]),
	?assertEqual("bbb", Match1).

sign_test() ->
	Creds = basic_auth("key", "gthc2t9gh7pzq52f6cky8w4r4up9dr6rju9w3fjgmkv6cdvvav2ufe5fv7e2r9qy"),
	FeedId = feed_id("flat", "1"),
	Signature = sign(Creds, FeedId),
	?assertEqual("flat1 iFX1l5f_lIUWgZFBnv5UisTTW18", binary_to_list(Signature)).

make_url_test() ->
	Uri = make_url(feed_detail, basic_auth("key", "secret"), feed_id("user", "1")),
	?assertEqual("/api/v1.0/feed/user/1/?api_key=key", Uri).

append_qs_test() ->
	Uri = "http://test.nl",
	QS = #{ "app" => "test", "key" => "something" },
	FullUri = append_qs(Uri, Qs),
	?assertEqual("http://test.nl?app=test&key=something", FullUri).

get_activities_test() ->
	Creds = basic_auth("abj7hpkjf6bm", "5y3wwjdg6kx8j7qjx7quwc7vnvb6gaucyvz7nweqam9tkzghtkqhvp7hb3tgfyh4"),
	FeedId = feed_id("user", "2LyE8334rPECksD9v"),
	Result = get_activities(Creds, FeedId),
	#{<<"results">> := RealResult} = Result,
	?assertEqual("", RealResult).

add_activity_test() ->
	Creds = basic_auth("abj7hpkjf6bm", "5y3wwjdg6kx8j7qjx7quwc7vnvb6gaucyvz7nweqam9tkzghtkqhvp7hb3tgfyh4"),
	FeedId = feed_id("user", "2LyE8334rPECksD9v"),
	Activity = #{
		<<"actor">> => <<"ik">>,
		<<"verb">> => <<"do">>,
		<<"object">> => <<"0">>
	},
	add_activity(Creds, FeedId, Activity).

-endif.