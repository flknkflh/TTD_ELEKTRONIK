-- The letter number and subject a signer typed for one signature. They are
-- drawn on the QR caption and shown on the verification pages.
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS letter_no      TEXT NOT NULL DEFAULT '';
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS letter_subject TEXT NOT NULL DEFAULT '';
