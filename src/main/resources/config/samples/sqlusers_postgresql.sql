
drop table IF EXISTS  "Пользователи";

CREATE TABLE public."Пользователи" (
  "Поле1" CHAR(10),
  "Поле2" CHAR(10),
  "Логин" VARCHAR(50) NOT NULL,
  "Пароль" VARCHAR(50),
  "Поле objectSid" VARCHAR(50),
  "Поле name" VARCHAR(50),
  "Поле email" VARCHAR(50),
  "Поле phone" VARCHAR(50),
  "Поле organization" VARCHAR(50),
  "Поле fax" VARCHAR(50),
  CONSTRAINT "Пользователи_pkey" PRIMARY KEY("Логин")
) WITHOUT OIDS;

Insert into "Пользователи" ("Поле1","Поле2","Логин","Пароль","Поле objectSid","Поле name","Поле email","Поле phone","Поле organization","Поле fax") values (null,null,'user222','pwd111','8dbf2a31-cfe6-4188-a2f0-0125481355ce','Алексей В. Васильев','12@yandex.ru','123-56-78','org4','fax4');
Insert into "Пользователи" ("Поле1","Поле2","Логин","Пароль","Поле objectSid","Поле name","Поле email","Поле phone","Поле organization","Поле fax") values (null,null,'Иванов2','пасс1','8dbf2a31-cfe6-4188-a2f0-0125481355cd','Алексей В. Васильев','12@yandex.ru','123-56-78','org1','fax1');
Insert into "Пользователи" ("Поле1","Поле2","Логин","Пароль","Поле objectSid","Поле name","Поле email","Поле phone","Поле organization","Поле fax") values (null,null,'Петров2','c8233fc18a5fd0f87284d9fa971049891315ed84','f2f0dbe5-da83-4367-9827-01e7c179ea3a','Борис В. Смирнов','34@yandex.ru','784-23-f5','org2','fax2');
Insert into "Пользователи" ("Поле1","Поле2","Логин","Пароль","Поле objectSid","Поле name","Поле email","Поле phone","Поле organization","Поле fax") values (null,null,'Сидоров2','пасс3','5e599041-6a69-466e-b22c-f3003be536d9','Евгений Балмасов','56@yandex.ru','апе-43-67','org3','fax3');

