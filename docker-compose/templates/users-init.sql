CREATE TABLE IF NOT EXISTS users (
  id                 SERIAL PRIMARY KEY,
  first_name         TEXT NOT NULL,
  last_name          TEXT,
  ssn                TEXT,
  phone              TEXT,
  email              TEXT UNIQUE NOT NULL,
  credit_card_number TEXT,
  ip_address         TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_uidx ON users (lower(email));
CREATE INDEX IF NOT EXISTS users_first_name_lower_idx  ON users (lower(first_name));

INSERT INTO users (first_name, last_name, ssn, phone, email, credit_card_number, ip_address) VALUES ('Amelia', 'Wilson', '591-00-9242', '+1-812-669-2470', 'amelia.wilson475@example.com', '0388-6685-4496-5569', '19.229.74.152') ON CONFLICT (email) DO NOTHING;
INSERT INTO users (first_name, last_name, ssn, phone, email, credit_card_number, ip_address) VALUES ('Henry', 'Davis', '231-05-3839', '+1-088-393-8653', 'henry.davis409@example.com', '1980-9699-1980-8063', '75.157.149.113') ON CONFLICT (email) DO NOTHING;
INSERT INTO users (first_name, last_name, ssn, phone, email, credit_card_number, ip_address) VALUES ('Noah', 'Thompson', '714-83-8341', '+1-461-252-3994', 'noah.thompson206@example.com', '2391-5556-0490-6326', '34.226.225.173') ON CONFLICT (email) DO NOTHING;
INSERT INTO users (first_name, last_name, ssn, phone, email, credit_card_number, ip_address) VALUES ('Mia', 'Williams', '369-20-3281', '+1-210-559-3064', 'mia.williams670@example.com', '1848-7392-1645-6205', '75.44.47.208') ON CONFLICT (email) DO NOTHING;
INSERT INTO users (first_name, last_name, ssn, phone, email, credit_card_number, ip_address) VALUES ('Charlotte', 'Anderson', '640-76-1524', '+1-074-756-9987', 'charlotte.anderson799@example.com', '2909-6058-3186-0764', '7.113.231.144') ON CONFLICT (email) DO NOTHING;
INSERT INTO users (first_name, last_name, ssn, phone, email, credit_card_number, ip_address) VALUES ('Noah', 'Miller', '694-46-9494', '+1-770-013-9159', 'noah.miller24@example.com', '8372-4679-0078-0733', '78.215.154.246') ON CONFLICT (email) DO NOTHING;

CREATE DATABASE litellm;