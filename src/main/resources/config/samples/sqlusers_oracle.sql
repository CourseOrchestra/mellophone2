
--  drop table "ПОЛЬЗОВАТЕЛИ";


  CREATE TABLE "ПОЛЬЗОВАТЕЛИ" 
   (	"Поле1" NCHAR(10), 
	"Поле2" NCHAR(10), 
	"Логин" VARCHAR2(50 BYTE) NOT NULL ENABLE, 
	"Пароль" VARCHAR2(50 BYTE), 
	"Поле objectSid" VARCHAR2(50 BYTE), 
	"Поле name" VARCHAR2(50 BYTE), 
	"Поле email" VARCHAR2(50 BYTE), 
	"Поле phone" VARCHAR2(50 BYTE), 
	"Поле organization" VARCHAR2(50 BYTE), 
	"Поле fax" VARCHAR2(50 BYTE), 
	 CONSTRAINT "ПОЛЬЗОВАТЕЛИ_PK" PRIMARY KEY ("Логин")
  USING INDEX PCTFREE 10 INITRANS 2 MAXTRANS 255 COMPUTE STATISTICS 
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT FLASH_CACHE DEFAULT CELL_FLASH_CACHE DEFAULT)
  TABLESPACE "USERS"  ENABLE
   ) SEGMENT CREATION IMMEDIATE 
  PCTFREE 10 PCTUSED 40 INITRANS 1 MAXTRANS 255 NOCOMPRESS LOGGING
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT FLASH_CACHE DEFAULT CELL_FLASH_CACHE DEFAULT)
  TABLESPACE "USERS" ;



Insert into "ПОЛЬЗОВАТЕЛИ" ("Поле1","Поле2","Логин","Пароль","Поле objectSid","Поле name","Поле email","Поле phone","Поле organization","Поле fax") values (null,null,'user333','pwd111','8dbf2a31-cfe6-4188-a2f0-0125481355ce','Алексей В. Васильев','12@yandex.ru','123-56-78','org4','fax4');
Insert into "ПОЛЬЗОВАТЕЛИ" ("Поле1","Поле2","Логин","Пароль","Поле objectSid","Поле name","Поле email","Поле phone","Поле organization","Поле fax") values (null,null,'Иванов3','пасс1','8dbf2a31-cfe6-4188-a2f0-0125481355cd','Алексей В. Васильев','12@yandex.ru','123-56-78','org1','fax1');
Insert into "ПОЛЬЗОВАТЕЛИ" ("Поле1","Поле2","Логин","Пароль","Поле objectSid","Поле name","Поле email","Поле phone","Поле organization","Поле fax") values (null,null,'Петров3','c8233fc18a5fd0f87284d9fa971049891315ed84','f2f0dbe5-da83-4367-9827-01e7c179ea3a','Борис В. Смирнов','34@yandex.ru','784-23-f5','org2','fax2');
Insert into "ПОЛЬЗОВАТЕЛИ" ("Поле1","Поле2","Логин","Пароль","Поле objectSid","Поле name","Поле email","Поле phone","Поле organization","Поле fax") values (null,null,'Сидоров3','пасс3','5e599041-6a69-466e-b22c-f3003be536d9','Евгений Балмасов','56@yandex.ru','апе-43-67','org3','fax3');


COMMIT;


