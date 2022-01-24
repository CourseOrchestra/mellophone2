CREATE OR ALTER PROCEDURE
POST_PROCESS
(
	SESID VARCHAR(256),
	USERLOGIN VARCHAR(256),
	USERAUTH BOOLEAN,
	USERATTRIBUTES VARCHAR(1024),
	USERIP VARCHAR(16),
	USERLOCKED BOOLEAN,
	USERLOGINATTEMPTS INTEGER,
	USERTIMETOUNLOCK INTEGER
)

RETURNS
(
	CODE INTEGER,
	MESSAGE VARCHAR(512)
)

AS
BEGIN

MESSAGE = 'Polzovatel ne proshel proverku v funkcii postobrabotki so sleduyushchimi parametrami: '
    || 'sesid = ' || coalesce(SESID, '')
    || ', userlogin = ' || coalesce(USERLOGIN, '')
    || ', userauth = ' || coalesce(USERAUTH, '')
	  || ', userattributes = ' || coalesce(USERATTRIBUTES, '')
    || ', userip = ' || coalesce(USERIP, '')
    || ', userlocked = ' || coalesce(USERLOCKED, '')
    || ', userloginattempts = ' || coalesce(USERLOGINATTEMPTS, '')
    || ', usertimetounlock = ' || coalesce(USERTIMETOUNLOCK, '')
    ;

CODE = 0;

SUSPEND;

END;
