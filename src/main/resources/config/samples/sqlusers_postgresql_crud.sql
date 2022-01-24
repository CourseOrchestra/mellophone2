


-- Table: public.User

-- DROP TABLE IF EXISTS public."User";

CREATE TABLE IF NOT EXISTS public."User"
(
    sid character varying(100) COLLATE pg_catalog."default" NOT NULL,
    login character varying(100) COLLATE pg_catalog."default",
    pwd character varying(100) COLLATE pg_catalog."default",
    CONSTRAINT "User_pkey" PRIMARY KEY (sid)
    )

    TABLESPACE pg_default;

ALTER TABLE IF EXISTS public."User"
    OWNER to postgres;
-- Index: User_login

-- DROP INDEX IF EXISTS public."User_login";

CREATE UNIQUE INDEX IF NOT EXISTS "User_login"
    ON public."User" USING btree
    (login COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;


-----------------------------------------------------------------------------------------------------


-- Table: public.UserAttr

-- DROP TABLE IF EXISTS public."UserAttr";

CREATE TABLE IF NOT EXISTS public."UserAttr"
(
    sid character varying(100) COLLATE pg_catalog."default" NOT NULL,
    fieldid character varying(100) COLLATE pg_catalog."default" NOT NULL,
    fieldvalue character varying(100) COLLATE pg_catalog."default",
    CONSTRAINT "UserAttr_pkey" PRIMARY KEY (sid, fieldid)
    )

    TABLESPACE pg_default;

ALTER TABLE IF EXISTS public."UserAttr"
    OWNER to postgres;
-- Index: UserAttr_sid

-- DROP INDEX IF EXISTS public."UserAttr_sid";

CREATE INDEX IF NOT EXISTS "UserAttr_sid"
    ON public."UserAttr" USING btree
    (sid COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;


