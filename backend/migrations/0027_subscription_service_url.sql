-- Operator-configurable URL of the main service website (telegram bot,
-- landing, support page) — surfaced as a "Перейти на сервис" button in
-- the subscription landing header. Empty ≡ button hidden.
ALTER TABLE panel_settings ADD COLUMN sub_service_url TEXT NOT NULL DEFAULT '';
