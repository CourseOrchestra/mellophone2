-- FUNCTION: public.postprocess(character varying, character varying, boolean, character varying, character varying, boolean, integer, bigint)

-- DROP FUNCTION IF EXISTS public.postprocess(character varying, character varying, boolean, character varying, character varying, boolean, integer, bigint);

CREATE OR REPLACE FUNCTION public.postprocess(
	OUT ret integer,
	sesid character varying,
	userlogin character varying,
	userauth boolean,
	userattributes character varying,
	userip character varying,
	userlocked boolean,
	userloginattempts integer,
	usertimetounlock bigint,
	OUT message character varying)
    RETURNS record
    LANGUAGE 'plpgsql'
    COST 100
    VOLATILE PARALLEL UNSAFE
AS $BODY$
BEGIN

 ret := 0;

 message := 'Пользователь не прошел проверку в функции постобработки со следующими параметрами: '
            || '  sesid = '             || coalesce(sesid, 'null')
            || ', userlogin = '         || coalesce(userlogin, 'null')
            || ', userauth = '          || userauth
			|| ', userattributes = '    || coalesce(userattributes, 'null')
            || ', userip = '            || coalesce(userip, 'null')
			|| ', userlocked = '        || userlocked
            || ', userloginattempts = ' || userloginattempts
            || ', usertimetounlock = '  || usertimetounlock;


END;
$BODY$;

ALTER FUNCTION public.postprocess(character varying, character varying, boolean, character varying, character varying, boolean, integer, bigint)
    OWNER TO postgres;
