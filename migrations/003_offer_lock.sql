-- PostgreSQL row locking requires UPDATE privilege even for FOR SHARE.
-- Keep the application read-only by exposing only a fixed, parameterized locker.
CREATE FUNCTION north.lock_offer(offer_id text) RETURNS SETOF north.offers
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, north AS $$
 SELECT * FROM north.offers WHERE id = offer_id FOR SHARE
$$;
REVOKE ALL ON FUNCTION north.lock_offer(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION north.lock_offer(text) TO north_app;
