PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS samples (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,   -- master column (1,2,3...)
    cwe           TEXT,                                 -- e.g., "CWE-79"
    producer      TEXT,                                 -- e.g., "openai", "groq", "human"
    codetask      TEXT,                                 -- task/prompt name or scenario
    webproduct    TEXT,                                 -- e.g., "flask", "fastapi", "django"
    webstyle      TEXT,                                 -- e.g., "mvc", "minimal", "rest"
    secure        INTEGER NOT NULL DEFAULT 0,            -- 0/1

    code          TEXT,                                 -- source code (main)
    dockerfile    TEXT,
    sql_script    TEXT,
    requirements  TEXT,

    port          INTEGER,                              -- app port, e.g. 5000

    docker        TEXT,                                 -- docker run/build logs or status
    bandit        TEXT,                                 -- bandit output
    owasp_zap     TEXT,                                 -- OWASP ZAP alerts json/text
    nikto         TEXT,                                 -- nikto output
    burpsuite     TEXT,                                 -- burp output (json/text)
    semgrep       TEXT,                                 -- semgrep output
    sonarqube     TEXT,                                 -- sonar output

    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT
);

-- Faydalı indexler (hız için)
CREATE INDEX IF NOT EXISTS idx_samples_cwe    ON samples(cwe);
CREATE INDEX IF NOT EXISTS idx_samples_secure ON samples(secure);
CREATE INDEX IF NOT EXISTS idx_samples_prod   ON samples(producer);
