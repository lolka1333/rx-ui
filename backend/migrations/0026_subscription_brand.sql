-- Operator-configurable service name shown in the subscription landing
-- page header. Empty string ≡ no override → the landing page falls back
-- to a neutral default. Validation on the API side enforces a max
-- length and strips control chars so the response header stays safe.
ALTER TABLE panel_settings ADD COLUMN sub_brand_name TEXT NOT NULL DEFAULT '';
