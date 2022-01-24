USE [showcase]
GO


CREATE PROCEDURE [dbo].[postProcess]

	@sesid varchar(256),
	
	@userlogin varchar(256),
	@userauth bit,
    @userattributes varchar(1024),
	@userip varchar(16),    
  
    @userlocked bit,
	@userloginattempts int,
	@usertimetounlock int,

	@message varchar(512) output
	
AS
BEGIN

set @message = 'Пользователь не прошел проверку в функции постобработки со следующими параметрами: '
             + '  sesid = ' + ISNULL(@sesid, '')
             + ', userlogin = ' + ISNULL(@userlogin, '')
             + ', userauth = ' + CAST(@userauth AS CHAR(1))
			 + ', userattributes = ' + ISNULL(@userattributes, '')
             + ', userip = ' + ISNULL(@userip, '')
             + ', userlocked = ' + CAST(@userlocked AS CHAR(1))
             + ', userloginattempts = ' + CAST(@userloginattempts AS CHAR(16))
             + ', usertimetounlock = ' + CAST(@usertimetounlock AS CHAR(16))

RETURN 1;

END


GO






