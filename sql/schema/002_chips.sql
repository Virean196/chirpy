-- +goose up
CREATE TABLE chirps(
    ID UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    body TEXT NOT NULL,
    user_id UUID NOT NULL,
    CONSTRAINT fk_users_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);


-- +goose down
DROP TABLE chirps;