ALTER TABLE users ALTER COLUMN hashed_password DROP NOT NULL;
ALTER TABLE users ALTER COLUMN salt DROP NOT NULL;
