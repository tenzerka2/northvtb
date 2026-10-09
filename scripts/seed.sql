\set ON_ERROR_STOP on
INSERT INTO north.offers VALUES
 ('demo-1-expensive','verified-premium','PS5-Pro','gaming','new','RUB',1,1,9690000,0,0,9690000,true,0,true),
 ('demo-2-unverified','unknown-shop','PS5-Pro','gaming','new','RUB',1,1,8100000,0,0,8100000,false,80,true),
 ('demo-3-valid','verified-shop','PS5-Pro','gaming','new','RUB',1,1,8299000,0,0,8299000,true,0,true)
ON CONFLICT(id) DO NOTHING;

INSERT INTO north.offers VALUES
 ('monitor-dns','dns','Dell UltraSharp U2723QE','electronics','new','RUB',1,1,8299000,0,0,8299000,true,0,true),
 ('monitor-technopark','technopark','Dell UltraSharp U2723QE','electronics','new','RUB',1,1,7950000,0,0,7950000,true,0,true),
 ('monitor-citilink','citilink','Dell UltraSharp U2723QE','electronics','new','RUB',1,1,8990000,0,0,8990000,true,0,true)
ON CONFLICT(id) DO NOTHING;
