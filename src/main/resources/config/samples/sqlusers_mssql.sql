USE [showcase]
GO

IF  EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[Пользователи]') AND type in (N'U'))
DROP TABLE [dbo].[Пользователи]
GO

USE [showcase]
GO

SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

SET ANSI_PADDING ON
GO

CREATE TABLE [dbo].[Пользователи](
	[Поле1] [nchar](10) NULL,
	[Поле2] [nchar](10) NULL,
	[Логин] [varchar](50) NOT NULL,
	[Пароль] [varchar](50) NULL,
	[Поле objectSid] [varchar](50) NULL,
	[Поле name] [varchar](50) NULL,
	[Поле email] [varchar](50) NULL,
	[Поле phone] [varchar](50) NULL,
	[Поле organization] [varchar](50) NULL,
	[Поле fax] [varchar](50) NULL,
 CONSTRAINT [PK_Пользователи] PRIMARY KEY CLUSTERED 
(
	[Логин] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]

GO

SET ANSI_PADDING OFF
GO


-----------------------------------------------------------------------


INSERT INTO [showcase].[dbo].[Пользователи]
           (
            [Логин]
           ,[Пароль]
           ,[Поле objectSid]
           ,[Поле name]
           ,[Поле email]
           ,[Поле phone]
           ,[Поле organization]
           ,[Поле fax]                      
           )
     VALUES
           (
            'Иванов1'
           ,'пасс1'
           ,'8dbf2a31-cfe6-4188-a2f0-0125481355cd'
           ,'Алексей В. Васильев'
           ,'12@yandex.ru'
           ,'123-56-78'
           ,'org1'
           ,'fax1'                      
           )
GO


INSERT INTO [showcase].[dbo].[Пользователи]
           (
            [Логин]
           ,[Пароль]
           ,[Поле objectSid]
           ,[Поле name]
           ,[Поле email]
           ,[Поле phone]
           ,[Поле organization]
           ,[Поле fax]                      
           )
     VALUES
           (
            'Петров1'
           ,'c8233fc18a5fd0f87284d9fa971049891315ed84'
           ,'f2f0dbe5-da83-4367-9827-01e7c179ea3a'
           ,'Борис В. Смирнов'
           ,'34@yandex.ru'
           ,'784-23-f5'
           ,'org2'
           ,'fax2'                      
           )
GO



INSERT INTO [showcase].[dbo].[Пользователи]
           (
            [Логин]
           ,[Пароль]
           ,[Поле objectSid]
           ,[Поле name]
           ,[Поле email]
           ,[Поле phone]
           ,[Поле organization]
           ,[Поле fax]                      
           )
     VALUES
           (
            'Сидоров1'
           ,'пасс3'
           ,'5e599041-6a69-466e-b22c-f3003be536d9'
           ,'Евгений Балмасов'
           ,'56@yandex.ru'
           ,'апе-43-67'
           ,'org3'
           ,'fax3'                      
           )
GO


INSERT INTO [showcase].[dbo].[Пользователи]
           (
            [Логин]
           ,[Пароль]
           ,[Поле objectSid]
           ,[Поле name]
           ,[Поле email]
           ,[Поле phone]
           ,[Поле organization]
           ,[Поле fax]                      
           )
     VALUES
           (
            'user111'
           ,'pwd111'
           ,'8dbf2a31-cfe6-4188-a2f0-0125481355ce'
           ,'Алексей В. Васильев'
           ,'12@yandex.ru'
           ,'123-56-78'
           ,'org4'
           ,'fax4'                      
           )
GO


