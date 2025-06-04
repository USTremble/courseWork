CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT CHECK (role IN ('player', 'moderator', 'admin')) DEFAULT 'player',
    is_blocked BOOLEAN DEFAULT FALSE
);

CREATE TABLE teams (
    team_id SERIAL PRIMARY KEY,
    team_name TEXT NOT NULL UNIQUE,
    invite_code TEXT UNIQUE
);

CREATE TABLE events (
    event_id SERIAL PRIMARY KEY,
    code TEXT UNIQUE,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    type TEXT CHECK (type IN ('quiz', 'ctf')) NOT NULL,
    answer TEXT,
    file_path TEXT,
    status TEXT CHECK (status IN ('waiting', 'running', 'finished')) DEFAULT 'waiting',
    created_by INTEGER,
    FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL
);

CREATE TABLE event_teams (
    event_id INTEGER NOT NULL,
    team_id INTEGER NOT NULL,
    points INTEGER DEFAULT 0,
    status TEXT CHECK (status IN ('waiting', 'running', 'finished')) DEFAULT 'waiting',
    PRIMARY KEY (event_id, team_id),
    FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE,
    FOREIGN KEY (team_id) REFERENCES teams(team_id) ON DELETE CASCADE
);

CREATE TABLE team_members (
    user_id INTEGER NOT NULL,
    team_id INTEGER NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    PRIMARY KEY (user_id, team_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (team_id) REFERENCES teams(team_id) ON DELETE CASCADE
);

CREATE TABLE event_submits (
    submit_id SERIAL PRIMARY KEY,
    event_id INTEGER NOT NULL,
    team_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    answer TEXT NOT NULL,
    ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE,
    FOREIGN KEY (team_id) REFERENCES teams(team_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);


CREATE UNIQUE INDEX IF NOT EXISTS teams_name_unique ON teams (team_name);
CREATE UNIQUE INDEX IF NOT EXISTS teams_code_unique ON teams (invite_code);
CREATE UNIQUE INDEX IF NOT EXISTS events_name_unique ON events (name);
CREATE UNIQUE INDEX IF NOT EXISTS events_code_unique ON events (code);

