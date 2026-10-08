CREATE TABLE north.offers (
 id north.identifier PRIMARY KEY,
 merchant_id north.identifier NOT NULL,
 product text NOT NULL,
 category text NOT NULL,
 condition text NOT NULL CHECK (condition IN ('new','used')),
 currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
 revision bigint NOT NULL CHECK (revision > 0),
 quantity bigint NOT NULL CHECK (quantity > 0),
 unit_amount bigint NOT NULL CHECK (unit_amount > 0),
 fees bigint NOT NULL CHECK (fees >= 0),
 shipping bigint NOT NULL CHECK (shipping >= 0),
 amount bigint NOT NULL CHECK (amount > 0),
 verified boolean NOT NULL,
 risk smallint NOT NULL CHECK (risk BETWEEN 0 AND 100),
 active boolean NOT NULL,
 CHECK (amount::numeric=unit_amount::numeric*quantity+fees+shipping)
);
GRANT SELECT ON north.offers TO north_app;
