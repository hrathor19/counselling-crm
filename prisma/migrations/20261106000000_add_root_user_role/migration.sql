-- Adds ROOT_USER to the Role enum.
--
-- Safe inside a normal transaction on Postgres 12+ (servers here are 17 local
-- / 18.6 old prod) as long as the new value is not USED in the same
-- transaction — this migration only adds it, nothing in this file reads or
-- writes a row carrying it, so it does not need the standalone/autocommit
-- treatment ALTER TYPE otherwise requires.
ALTER TYPE "Role" ADD VALUE IF NOT EXISTS 'ROOT_USER';
